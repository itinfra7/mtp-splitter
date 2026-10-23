//! 인증된 터널 하나에서 TCP·UDP·DNS 스트림을 다중화한다.
//! 바이트 윈도와 메시지 수·메모리 한도를 함께 적용하며, 실패 시 직접 경로로 전환하지 않는다.

use crate::{
    config::ServerConfig,
    gateway_wire::{self, WireDialect},
    nat_engine::{TunnelState, TunnelStatus},
    paths::AppPaths,
    protocol::{
        ErrorCode, ErrorMessage, Frame, FrameType, MAX_DATAGRAM, MAX_TCP_DATA, Settings, Target,
        TargetAddress,
    },
    transport::{self, SecurityConfig},
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    time::Instant,
};

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_streams: usize,
    pub queued_frames_per_stream: usize,
    pub receive_memory_bytes: usize,
    pub open_timeout: Duration,
    pub write_timeout: Duration,
    pub ping_interval: Duration,
    pub pong_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_streams: 1024,
            queued_frames_per_stream: 32,
            receive_memory_bytes: 16 * 1024 * 1024,
            open_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(15),
            pong_timeout: Duration::from_secs(10),
        }
    }
}
impl Limits {
    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=16384).contains(&self.max_streams)
                && (1..=1024).contains(&self.queued_frames_per_stream),
            "다중화 스트림·큐 한도가 잘못됐습니다"
        );
        ensure!(
            (131072..=256 * 1024 * 1024).contains(&self.receive_memory_bytes),
            "수신 메모리 한도가 잘못됐습니다"
        );
        for timeout in [
            self.open_timeout,
            self.write_timeout,
            self.ping_interval,
            self.pong_timeout,
        ] {
            ensure!(
                !timeout.is_zero() && timeout <= Duration::from_secs(300),
                "다중화 제한 시간이 잘못됐습니다"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    Tcp,
    Udp,
    Dns,
}
impl StreamKind {
    fn capability(self) -> u32 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
            Self::Dns => 4,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Opening,
    Open,
    Complete,
}

struct Received {
    frame: Frame,
    _memory: OwnedSemaphorePermit,
}
#[derive(Default)]
struct InboxState {
    queue: VecDeque<Received>,
    error: Option<String>,
    eof: bool,
}
struct Inbox {
    state: Mutex<InboxState>,
    wake: Notify,
    capacity: usize,
}
impl Inbox {
    fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(InboxState::default()),
            wake: Notify::new(),
            capacity,
        }
    }
    fn push(&self, received: Received) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("스트림 수신 잠금 손상"))?;
        ensure!(
            state.error.is_none() && !state.eof && state.queue.len() < self.capacity,
            "스트림 수신 큐 한도 초과"
        );
        state.queue.push_back(received);
        drop(state);
        self.wake.notify_waiters();
        Ok(())
    }
    fn finish(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .eof = true;
        self.wake.notify_waiters();
    }
    fn fail(&self, reason: &str) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.error = Some(reason.to_owned());
        state.queue.clear();
        drop(state);
        self.wake.notify_waiters();
    }
    async fn next(&self) -> Result<Option<Frame>> {
        loop {
            let wake = self.wake.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("스트림 수신 잠금 손상"))?;
                if let Some(reason) = &state.error {
                    bail!("{reason}");
                }
                if let Some(received) = state.queue.pop_front() {
                    return Ok(Some(received.frame));
                }
                if state.eof {
                    return Ok(None);
                }
            }
            wake.await;
        }
    }
}

struct Record {
    kind: StreamKind,
    phase: Phase,
    inbox: Arc<Inbox>,
    send_credit: u32,
    receive_credit: u32,
    tx_fin: bool,
    tx_fin_sent: bool,
    rx_fin: bool,
    target: Option<Target>,
    dns_id: Option<[u8; 2]>,
    selected_peer: Option<Target>,
}
struct Book {
    streams: HashMap<u32, Record>,
    next_id: u32,
    send_credit: u32,
    receive_credit: u32,
    goaway: bool,
}
struct Outgoing {
    frames: Vec<Frame>,
    flushed: Option<oneshot::Sender<std::result::Result<(), String>>>,
}
struct Shared {
    dialect: WireDialect,
    tcp_limit: usize,
    udp_limit: usize,
    book: Mutex<Book>,
    peer: Settings,
    local: Settings,
    limits: Limits,
    data: mpsc::Sender<Outgoing>,
    control: mpsc::Sender<Outgoing>,
    budget: Arc<Semaphore>,
    credit_changed: Notify,
    closed: AtomicBool,
    reason: Mutex<String>,
    stopping: watch::Sender<bool>,
    ping: Mutex<Option<(u64, Instant)>>,
    status: Arc<TunnelStatus>,
}

impl Shared {
    fn close(&self, reason: &str) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.status.set(TunnelState::Down);
        *self.reason.lock().unwrap_or_else(|e| e.into_inner()) = reason.to_owned();
        let mut book = self.book.lock().unwrap_or_else(|e| e.into_inner());
        for (_, record) in book.streams.drain() {
            record.inbox.fail(reason);
        }
        drop(book);
        self.credit_changed.notify_waiters();
        self.stopping.send_replace(true);
    }
    fn reason(&self) -> String {
        self.reason
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    fn control(&self, frames: Vec<Frame>) -> Result<()> {
        if frames.is_empty() {
            return Ok(());
        }
        ensure!(!self.closed.load(Ordering::Acquire), "{}", self.reason());
        if self
            .control
            .try_send(Outgoing {
                frames,
                flushed: None,
            })
            .is_err()
        {
            self.close("게이트웨이 제어 큐가 포화됐습니다");
            bail!("게이트웨이 제어 큐가 포화됐습니다");
        }
        Ok(())
    }
    fn window(id: u32, amount: u32) -> Frame {
        Frame {
            kind: FrameType::WindowUpdate,
            stream_id: id,
            payload: amount.to_be_bytes().to_vec(),
        }
    }
    fn retire(&self, id: u32, code: ErrorCode, reason: &str, send_reset: bool) {
        let mut book = self.book.lock().unwrap_or_else(|e| e.into_inner());
        let Some(record) = book.streams.remove(&id) else {
            return;
        };
        let unacknowledged = self
            .local
            .stream_credit
            .saturating_sub(record.receive_credit);
        book.receive_credit = book
            .receive_credit
            .saturating_add(unacknowledged)
            .min(self.local.connection_credit);
        let graceful = (record.kind == StreamKind::Tcp && record.rx_fin && record.tx_fin_sent)
            || record.phase == Phase::Complete;
        record.inbox.fail(reason);
        drop(book);
        let mut frames = Vec::new();
        if unacknowledged != 0 {
            frames.push(Self::window(0, unacknowledged));
        }
        if send_reset
            && !graceful
            && !(record.kind == StreamKind::Dns && self.dialect == WireDialect::GatewayV1)
            && let Ok(payload) = ErrorMessage::new(code, reason).encode()
        {
            frames.push(Frame {
                kind: FrameType::StreamReset,
                stream_id: id,
                payload,
            });
        }
        let _ = self.control(frames);
        self.credit_changed.notify_waiters();
    }
    fn acknowledge(&self, id: u32, amount: usize) -> Result<()> {
        if amount == 0 {
            return Ok(());
        }
        let amount = u32::try_from(amount)?;
        let mut book = self
            .book
            .lock()
            .map_err(|_| anyhow::anyhow!("다중화 상태 잠금 손상"))?;
        let Some(record) = book.streams.get_mut(&id) else {
            return Ok(());
        };
        record.receive_credit = record
            .receive_credit
            .checked_add(amount)
            .filter(|value| *value <= self.local.stream_credit)
            .context("스트림 수신 윈도 초과")?;
        book.receive_credit = book
            .receive_credit
            .checked_add(amount)
            .filter(|value| *value <= self.local.connection_credit)
            .context("연결 수신 윈도 초과")?;
        drop(book);
        self.control(vec![Self::window(id, amount), Self::window(0, amount)])
    }
    async fn reserve(
        self: &Arc<Self>,
        id: u32,
        amount: usize,
        kind: StreamKind,
    ) -> Result<SendCredit> {
        let amount = u32::try_from(self.dialect.credit(amount))?;
        loop {
            let changed = self.credit_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            ensure!(!self.closed.load(Ordering::Acquire), "{}", self.reason());
            {
                let mut book = self
                    .book
                    .lock()
                    .map_err(|_| anyhow::anyhow!("다중화 상태 잠금 손상"))?;
                let Book {
                    streams,
                    send_credit,
                    ..
                } = &mut *book;
                let record = streams.get_mut(&id).context("스트림이 종료됐습니다")?;
                ensure!(
                    record.kind == kind && record.phase == Phase::Open && !record.tx_fin,
                    "송신할 수 없는 스트림 상태입니다"
                );
                if amount <= record.send_credit && amount <= *send_credit {
                    record.send_credit -= amount;
                    *send_credit -= amount;
                    return Ok(SendCredit {
                        shared: Arc::clone(self),
                        id,
                        amount,
                        committed: false,
                    });
                }
            }
            changed.await;
        }
    }
    fn refund_send(&self, id: u32, amount: u32) {
        if self.closed.load(Ordering::Acquire) || amount == 0 {
            return;
        }
        let result = (|| -> Result<()> {
            let mut book = self
                .book
                .lock()
                .map_err(|_| anyhow::anyhow!("송신 크레딧 복구 잠금 손상"))?;
            book.send_credit = book
                .send_credit
                .checked_add(amount)
                .filter(|value| {
                    *value
                        <= if self.dialect == WireDialect::GatewayV1 {
                            self.peer.connection_credit
                        } else {
                            0x7fff_ffff
                        }
                })
                .context("송신 크레딧 복구 오버플로")?;
            if let Some(record) = book.streams.get_mut(&id) {
                record.send_credit = record
                    .send_credit
                    .checked_add(amount)
                    .filter(|value| {
                        *value
                            <= if self.dialect == WireDialect::GatewayV1 {
                                self.peer.stream_credit
                            } else {
                                0x7fff_ffff
                            }
                    })
                    .context("스트림 크레딧 복구 오버플로")?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.close(&format!("{error:#}"));
        }
        self.credit_changed.notify_waiters();
    }
    async fn send(&self, outgoing: Outgoing) -> Result<()> {
        let mut stopping = self.stopping.subscribe();
        ensure!(!*stopping.borrow(), "{}", self.reason());
        tokio::select! {
            result = self.data.send(outgoing) => result.context("게이트웨이 송신 작업이 종료됐습니다"),
            _ = stopping.changed() => bail!("{}", self.reason()),
        }
    }
    fn route(&self, frame: Frame) -> Result<()> {
        match frame.kind {
            FrameType::Ping => {
                return self.control(vec![Frame {
                    kind: FrameType::Pong,
                    ..frame
                }]);
            }
            FrameType::Pong => {
                let mut ping = self
                    .ping
                    .lock()
                    .map_err(|_| anyhow::anyhow!("heartbeat 잠금 손상"))?;
                ensure!(
                    ping.as_ref()
                        .is_some_and(|(nonce, _)| nonce.to_be_bytes().as_slice() == frame.payload),
                    "요청하지 않은 PONG입니다"
                );
                *ping = None;
                return Ok(());
            }
            FrameType::GoAway => {
                let error = ErrorMessage::decode(&frame.payload)?;
                if error.code != ErrorCode::Cancelled {
                    bail!("서버가 연결 종료를 요청했습니다: {}", error.message);
                }
                self.book
                    .lock()
                    .map_err(|_| anyhow::anyhow!("다중화 상태 잠금 손상"))?
                    .goaway = true;
                return Ok(());
            }
            FrameType::Hello
            | FrameType::Welcome
            | FrameType::OpenTcp
            | FrameType::OpenUdp
            | FrameType::DnsQuery => bail!("서버가 허용되지 않은 방향의 프레임을 보냈습니다"),
            _ => (),
        }
        let mut book = self
            .book
            .lock()
            .map_err(|_| anyhow::anyhow!("다중화 상태 잠금 손상"))?;
        if frame.kind == FrameType::WindowUpdate && frame.stream_id == 0 {
            let amount = u32::from_be_bytes(frame.payload[..4].try_into()?);
            book.send_credit = book
                .send_credit
                .checked_add(amount)
                .filter(|value| {
                    *value
                        <= if self.dialect == WireDialect::GatewayV1 {
                            self.peer.connection_credit
                        } else {
                            0x7fff_ffff
                        }
                })
                .context("연결 송신 윈도 오버플로")?;
            drop(book);
            self.credit_changed.notify_waiters();
            return Ok(());
        }
        if !book.streams.contains_key(&frame.stream_id) {
            ensure!(
                frame.stream_id < book.next_id,
                "열지 않은 스트림의 프레임입니다"
            );
            let amount = if matches!(frame.kind, FrameType::TcpData | FrameType::UdpDatagram) {
                self.dialect.credit(frame.payload.len()) as u32
            } else {
                0
            };
            ensure!(
                amount <= book.receive_credit,
                "종료된 스트림의 연결 윈도 위반"
            );
            drop(book);
            if amount != 0 {
                self.control(vec![Self::window(0, amount)])?;
            }
            return Ok(());
        }
        let Book {
            streams,
            receive_credit,
            ..
        } = &mut *book;
        let record = streams
            .get_mut(&frame.stream_id)
            .expect("존재 확인한 스트림");
        match frame.kind {
            FrameType::WindowUpdate => {
                ensure!(
                    record.phase == Phase::Open && record.kind != StreamKind::Dns,
                    "잘못된 스트림 윈도 갱신입니다"
                );
                let amount = u32::from_be_bytes(frame.payload[..4].try_into()?);
                record.send_credit = record
                    .send_credit
                    .checked_add(amount)
                    .filter(|value| {
                        *value
                            <= if self.dialect == WireDialect::GatewayV1 {
                                self.peer.stream_credit
                            } else {
                                0x7fff_ffff
                            }
                    })
                    .context("스트림 송신 윈도 오버플로")?;
                drop(book);
                self.credit_changed.notify_waiters();
                return Ok(());
            }
            FrameType::OpenOk => {
                ensure!(
                    record.phase == Phase::Opening && record.kind != StreamKind::Dns,
                    "중복되거나 잘못된 OPEN_OK입니다"
                );
                let (_, offset) = Target::decode(&frame.payload)?;
                let (peer, _) = Target::decode(&frame.payload[offset..])?;
                let target = record.target.as_ref().context("목적지가 없습니다")?;
                ensure!(target.port == peer.port, "OPEN_OK의 목적지 포트가 다릅니다");
                if let TargetAddress::Ip(expected) = target.address {
                    ensure!(
                        peer.address == TargetAddress::Ip(expected),
                        "OPEN_OK의 목적지 IP가 다릅니다"
                    );
                }
                record.selected_peer = Some(peer);
                record.phase = Phase::Open;
            }
            FrameType::OpenError | FrameType::StreamReset => {
                if frame.kind == FrameType::OpenError {
                    ensure!(
                        record.phase == Phase::Opening,
                        "열린 스트림에 OPEN_ERROR가 왔습니다"
                    );
                }
                let error = ErrorMessage::decode(&frame.payload)?;
                let id = frame.stream_id;
                drop(book);
                self.retire(
                    id,
                    error.code,
                    &format!("서버 오류 {}: {}", error.code as u16, error.message),
                    false,
                );
                return Ok(());
            }
            FrameType::TcpData | FrameType::UdpDatagram => {
                let kind = if frame.kind == FrameType::TcpData {
                    StreamKind::Tcp
                } else {
                    StreamKind::Udp
                };
                ensure!(
                    record.phase == Phase::Open && record.kind == kind && !record.rx_fin,
                    "수신 데이터의 스트림 상태가 잘못됐습니다"
                );
                if kind == StreamKind::Udp && self.dialect == WireDialect::GatewayV1 {
                    let (source, _) = Target::decode(&frame.payload)?;
                    ensure!(
                        record.selected_peer.as_ref() == Some(&source),
                        "UDP 응답의 출발지가 OPEN_OK와 다릅니다"
                    );
                }
                let amount = self.dialect.credit(frame.payload.len()) as u32;
                ensure!(
                    amount <= record.receive_credit && amount <= *receive_credit,
                    "서버가 수신 윈도를 초과했습니다"
                );
                record.receive_credit -= amount;
                *receive_credit -= amount;
            }
            FrameType::TcpFin => {
                ensure!(
                    record.phase == Phase::Open && record.kind == StreamKind::Tcp && !record.rx_fin,
                    "잘못되거나 중복된 FIN입니다"
                );
                record.rx_fin = true;
                record.inbox.finish();
                return Ok(());
            }
            FrameType::DnsResponse => {
                ensure!(
                    record.kind == StreamKind::Dns
                        && record.phase == Phase::Open
                        && record
                            .dns_id
                            .as_ref()
                            .is_some_and(|id| id.as_slice() == &frame.payload[..2])
                        && frame.payload[2] & 0x80 != 0,
                    "DNS 응답의 상태·ID·QR이 잘못됐습니다"
                );
                record.phase = Phase::Complete;
            }
            _ => bail!("처리할 수 없는 게이트웨이 프레임입니다"),
        }
        let id = frame.stream_id;
        let inbox = Arc::clone(&record.inbox);
        let memory = Arc::clone(&self.budget)
            .try_acquire_many_owned(u32::try_from(frame.payload.len() + 128)?);
        let result = memory.map_err(anyhow::Error::from).and_then(|memory| {
            inbox.push(Received {
                frame,
                _memory: memory,
            })
        });
        drop(book);
        if result.is_err() {
            self.retire(
                id,
                ErrorCode::Capacity,
                "스트림 수신 큐 또는 메모리 한도 초과",
                true,
            );
        }
        Ok(())
    }
}

struct Owner {
    shared: Arc<Shared>,
}
struct SendCredit {
    shared: Arc<Shared>,
    id: u32,
    amount: u32,
    committed: bool,
}
impl SendCredit {
    fn commit(mut self) {
        self.committed = true;
    }
}
impl Drop for SendCredit {
    fn drop(&mut self) {
        if !self.committed {
            self.shared.refund_send(self.id, self.amount);
        }
    }
}
struct PendingFin {
    shared: Arc<Shared>,
    id: u32,
    sent: bool,
}
struct PendingTcpSend {
    shared: Arc<Shared>,
    id: u32,
    completed: bool,
}
impl Drop for PendingTcpSend {
    fn drop(&mut self) {
        if !self.completed {
            self.shared.retire(
                self.id,
                ErrorCode::Cancelled,
                "TCP 송신이 중단됐습니다",
                true,
            );
        }
    }
}
impl Drop for PendingFin {
    fn drop(&mut self) {
        if !self.sent {
            self.shared.retire(
                self.id,
                ErrorCode::Cancelled,
                "FIN 전송이 중단됐습니다",
                true,
            );
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.shared.close("게이트웨이 클라이언트가 종료됐습니다");
    }
}
#[derive(Clone)]
pub struct GatewayClient {
    owner: Arc<Owner>,
}

pub struct GatewayStream {
    id: u32,
    kind: StreamKind,
    client: GatewayClient,
    inbox: Arc<Inbox>,
    writing: tokio::sync::Mutex<()>,
    reading: tokio::sync::Mutex<()>,
    endpoints: Option<(Target, Target)>,
}
impl Drop for GatewayStream {
    fn drop(&mut self) {
        self.client.owner.shared.retire(
            self.id,
            ErrorCode::Cancelled,
            "로컬 스트림이 종료됐습니다",
            true,
        );
    }
}

impl GatewayClient {
    pub async fn connect(
        server: &ServerConfig,
        security: &SecurityConfig,
        paths: &AppPaths,
        status: Arc<TunnelStatus>,
        limits: Limits,
    ) -> Result<Self> {
        let (io, peer) = transport::connect_detailed(server, security, paths).await?;
        Self::attach_with_dialect(
            io,
            peer.settings,
            security.dialect().local_settings(),
            status,
            limits,
            security.dialect(),
            (peer.tcp_limit, peer.udp_limit),
        )
    }
    /// TLS 인증과 HELLO/WELCOME을 이미 완료한 바이트 스트림에 작업을 연결한다.
    pub fn attach_authenticated<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        io: S,
        peer: Settings,
        local: Settings,
        status: Arc<TunnelStatus>,
        limits: Limits,
    ) -> Result<Self> {
        Self::attach_with_dialect(
            io,
            peer,
            local,
            status,
            limits,
            WireDialect::Legacy,
            (usize::MAX, usize::MAX),
        )
    }
    /// 인증과 협상을 완료한 전송 규격을 명시하여 독립 상호운용 시험에도 사용한다.
    pub fn attach_with_dialect<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        io: S,
        peer: Settings,
        local: Settings,
        status: Arc<TunnelStatus>,
        limits: Limits,
        dialect: WireDialect,
        stream_limits: (usize, usize),
    ) -> Result<Self> {
        limits.validate()?;
        peer.encode()?;
        local.encode()?;
        let (data, data_receiver) = mpsc::channel(64);
        let (control, control_receiver) = mpsc::channel(128);
        let (stopping, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            dialect,
            tcp_limit: stream_limits.0,
            udp_limit: stream_limits.1,
            book: Mutex::new(Book {
                streams: HashMap::new(),
                next_id: 1,
                send_credit: peer.connection_credit,
                receive_credit: local.connection_credit,
                goaway: false,
            }),
            peer,
            local,
            budget: Arc::new(Semaphore::new(limits.receive_memory_bytes)),
            limits,
            data,
            control,
            credit_changed: Notify::new(),
            closed: AtomicBool::new(false),
            reason: Mutex::new(String::new()),
            stopping,
            ping: Mutex::new(None),
            status,
        });
        let client = Self {
            owner: Arc::new(Owner {
                shared: Arc::clone(&shared),
            }),
        };
        shared.status.set(TunnelState::Connected);
        let (reader, writer) = tokio::io::split(io);
        tokio::spawn(reader_task(reader, Arc::clone(&shared)));
        tokio::spawn(writer_task(
            writer,
            Arc::clone(&shared),
            data_receiver,
            control_receiver,
        ));
        Ok(client)
    }
    fn allocate(
        &self,
        kind: StreamKind,
        target: Option<Target>,
        dns_id: Option<[u8; 2]>,
    ) -> Result<GatewayStream> {
        let shared = &self.owner.shared;
        ensure!(
            !shared.closed.load(Ordering::Acquire),
            "{}",
            shared.reason()
        );
        ensure!(
            shared.peer.capabilities & kind.capability() != 0,
            "서버가 요청한 기능을 지원하지 않습니다"
        );
        let mut book = shared
            .book
            .lock()
            .map_err(|_| anyhow::anyhow!("다중화 상태 잠금 손상"))?;
        ensure!(
            !shared.closed.load(Ordering::Acquire),
            "{}",
            shared.reason()
        );
        ensure!(
            !book.goaway && book.streams.len() < shared.limits.max_streams,
            "새 스트림을 열 수 없거나 스트림 한도에 도달했습니다"
        );
        let limit = match kind {
            StreamKind::Tcp => shared.tcp_limit,
            StreamKind::Udp => shared.udp_limit,
            StreamKind::Dns => shared.limits.max_streams,
        };
        ensure!(
            book.streams
                .values()
                .filter(|record| record.kind == kind)
                .count()
                < limit,
            "서버가 허용한 종류별 스트림 한도에 도달했습니다"
        );
        let id = book.next_id;
        book.next_id = id.checked_add(2).context("스트림 ID가 소진됐습니다")?;
        let inbox = Arc::new(Inbox::new(shared.limits.queued_frames_per_stream));
        book.streams.insert(
            id,
            Record {
                kind,
                phase: if kind == StreamKind::Dns {
                    Phase::Open
                } else {
                    Phase::Opening
                },
                inbox: Arc::clone(&inbox),
                send_credit: shared.peer.stream_credit,
                receive_credit: shared.local.stream_credit,
                tx_fin: false,
                tx_fin_sent: false,
                rx_fin: false,
                target,
                dns_id,
                selected_peer: None,
            },
        );
        Ok(GatewayStream {
            id,
            kind,
            client: self.clone(),
            inbox,
            writing: tokio::sync::Mutex::new(()),
            reading: tokio::sync::Mutex::new(()),
            endpoints: None,
        })
    }
    async fn open(&self, kind: StreamKind, target: Target) -> Result<Arc<GatewayStream>> {
        let payload = target.encode()?;
        let mut stream = self.allocate(kind, Some(target), None)?;
        let kind = if kind == StreamKind::Tcp {
            FrameType::OpenTcp
        } else {
            FrameType::OpenUdp
        };
        let operation = async {
            self.owner
                .shared
                .send(Outgoing {
                    frames: vec![Frame {
                        kind,
                        stream_id: stream.id,
                        payload,
                    }],
                    flushed: None,
                })
                .await?;
            let response = stream
                .inbox
                .next()
                .await?
                .context("OPEN 응답 전에 스트림이 종료됐습니다")?;
            ensure!(
                response.kind == FrameType::OpenOk,
                "OPEN_OK 응답이 필요합니다"
            );
            let (local, size) = Target::decode(&response.payload)?;
            let (peer, _) = Target::decode(&response.payload[size..])?;
            Ok::<_, anyhow::Error>((local, peer))
        };
        stream.endpoints = Some(
            tokio::time::timeout(self.owner.shared.limits.open_timeout, operation)
                .await
                .context("게이트웨이 OPEN 제한 시간 초과")??,
        );
        Ok(Arc::new(stream))
    }
    pub async fn open_tcp(&self, target: Target) -> Result<Arc<GatewayStream>> {
        self.open(StreamKind::Tcp, target).await
    }
    pub async fn open_udp(&self, target: Target) -> Result<Arc<GatewayStream>> {
        self.open(StreamKind::Udp, target).await
    }
    pub async fn query_dns(&self, query: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            (12..=65535).contains(&query.len()) && query[2] & 0x80 == 0,
            "DNS 요청 길이 또는 QR이 잘못됐습니다"
        );
        let stream = self.allocate(StreamKind::Dns, None, Some([query[0], query[1]]))?;
        let operation = async {
            self.owner
                .shared
                .send(Outgoing {
                    frames: vec![Frame {
                        kind: FrameType::DnsQuery,
                        stream_id: stream.id,
                        payload: query.to_vec(),
                    }],
                    flushed: None,
                })
                .await?;
            let response = stream
                .inbox
                .next()
                .await?
                .context("DNS 응답 전에 스트림이 종료됐습니다")?;
            ensure!(
                response.kind == FrameType::DnsResponse,
                "DNS_RESPONSE가 필요합니다"
            );
            if self.owner.shared.dialect == WireDialect::GatewayV1 {
                validate_dns_response(query, &response.payload)?;
            }
            Ok::<_, anyhow::Error>(response.payload)
        };
        tokio::time::timeout(self.owner.shared.limits.open_timeout, operation)
            .await
            .context("원격 DNS 제한 시간 초과")?
    }
    pub fn active_streams(&self) -> usize {
        self.owner
            .shared
            .book
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .streams
            .len()
    }
    pub fn is_connected(&self) -> bool {
        !self.owner.shared.closed.load(Ordering::Acquire)
    }
    pub fn close(&self, reason: &str) {
        self.owner.shared.close(reason);
    }
    pub async fn closed(&self) -> String {
        let mut stopping = self.owner.shared.stopping.subscribe();
        if !*stopping.borrow() {
            let _ = stopping.changed().await;
        }
        self.owner.shared.reason()
    }
}

impl GatewayStream {
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn kind(&self) -> StreamKind {
        self.kind
    }
    pub fn endpoints(&self) -> Option<&(Target, Target)> {
        self.endpoints.as_ref()
    }
    pub async fn send_tcp(&self, bytes: &[u8]) -> Result<()> {
        ensure!(self.kind == StreamKind::Tcp, "TCP 스트림이 아닙니다");
        let _writing = self.writing.lock().await;
        let mut pending = PendingTcpSend {
            shared: Arc::clone(&self.client.owner.shared),
            id: self.id,
            completed: false,
        };
        let chunk_size = MAX_TCP_DATA
            .min(self.client.owner.shared.peer.stream_credit as usize)
            .min(self.client.owner.shared.peer.connection_credit as usize);
        for chunk in bytes.chunks(chunk_size) {
            let credit = self
                .client
                .owner
                .shared
                .reserve(self.id, chunk.len(), self.kind)
                .await?;
            self.client
                .owner
                .shared
                .send(Outgoing {
                    frames: vec![Frame {
                        kind: FrameType::TcpData,
                        stream_id: self.id,
                        payload: chunk.to_vec(),
                    }],
                    flushed: None,
                })
                .await?;
            credit.commit();
        }
        pending.completed = true;
        Ok(())
    }
    pub async fn send_datagram(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.kind == StreamKind::Udp && bytes.len() <= MAX_DATAGRAM,
            "UDP 스트림 또는 데이터그램 길이가 잘못됐습니다"
        );
        let _writing = self.writing.lock().await;
        let credit = self
            .client
            .owner
            .shared
            .reserve(self.id, bytes.len(), self.kind)
            .await?;
        self.client
            .owner
            .shared
            .send(Outgoing {
                frames: vec![Frame {
                    kind: FrameType::UdpDatagram,
                    stream_id: self.id,
                    payload: bytes.to_vec(),
                }],
                flushed: None,
            })
            .await?;
        credit.commit();
        Ok(())
    }
    pub async fn receive(&self) -> Result<Option<Vec<u8>>> {
        let _reading = self.reading.lock().await;
        let Some(frame) = self.inbox.next().await? else {
            return Ok(None);
        };
        let expected = if self.kind == StreamKind::Tcp {
            FrameType::TcpData
        } else {
            FrameType::UdpDatagram
        };
        ensure!(
            frame.kind == expected,
            "수신 프레임 종류가 스트림과 다릅니다"
        );
        self.client.owner.shared.acknowledge(
            self.id,
            self.client.owner.shared.dialect.credit(frame.payload.len()),
        )?;
        let mut payload = frame.payload;
        if self.kind == StreamKind::Udp
            && self.client.owner.shared.dialect == WireDialect::GatewayV1
        {
            let (_, offset) = Target::decode(&payload)?;
            payload.drain(..offset);
        }
        Ok(Some(payload))
    }
    pub async fn finish(&self) -> Result<()> {
        ensure!(
            self.kind == StreamKind::Tcp,
            "UDP에는 TCP FIN을 보낼 수 없습니다"
        );
        let _writing = self.writing.lock().await;
        let shared = &self.client.owner.shared;
        {
            let mut book = shared
                .book
                .lock()
                .map_err(|_| anyhow::anyhow!("다중화 상태 잠금 손상"))?;
            let record = book
                .streams
                .get_mut(&self.id)
                .context("스트림이 종료됐습니다")?;
            ensure!(
                record.phase == Phase::Open && !record.tx_fin,
                "이미 FIN을 보냈거나 열리지 않은 스트림입니다"
            );
            record.tx_fin = true;
        }
        let (sender, receiver) = oneshot::channel();
        let mut pending = PendingFin {
            shared: Arc::clone(shared),
            id: self.id,
            sent: false,
        };
        shared
            .send(Outgoing {
                frames: vec![Frame {
                    kind: FrameType::TcpFin,
                    stream_id: self.id,
                    payload: Vec::new(),
                }],
                flushed: Some(sender),
            })
            .await?;
        tokio::time::timeout(shared.limits.write_timeout, receiver)
            .await
            .context("FIN 전송 제한 시간 초과")??
            .map_err(anyhow::Error::msg)?;
        let mut book = shared
            .book
            .lock()
            .map_err(|_| anyhow::anyhow!("다중화 상태 잠금 손상"))?;
        book.streams
            .get_mut(&self.id)
            .context("FIN 중 스트림이 종료됐습니다")?
            .tx_fin_sent = true;
        pending.sent = true;
        Ok(())
    }
}

struct TaskGuard(Arc<Shared>);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.close("게이트웨이 전송 작업이 종료됐습니다");
    }
}

async fn reader_task<R: AsyncRead + Unpin>(mut reader: R, shared: Arc<Shared>) {
    let _guard = TaskGuard(Arc::clone(&shared));
    let mut stopping = shared.stopping.subscribe();
    let mut timer = tokio::time::interval(Duration::from_millis(100));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_ping = Instant::now();
    'connection: loop {
        if *stopping.borrow() {
            break;
        }
        // heartbeat 분기에서 read_exact 미래를 취소하지 않아 부분 프레임을 잃지 않는다.
        let incoming = gateway_wire::read_server(&mut reader, shared.dialect);
        tokio::pin!(incoming);
        let frame = loop {
            tokio::select! {
                _ = stopping.changed() => break 'connection,
                result = &mut incoming => match result { Ok(frame) => break frame, Err(error) => { shared.close(&format!("게이트웨이 수신 실패: {error:#}")); break 'connection; } },
                _ = timer.tick() => {
                    let mut ping = shared.ping.lock().unwrap_or_else(|e| e.into_inner());
                    if ping.as_ref().is_some_and(|(_, started)| started.elapsed() >= shared.limits.pong_timeout) {
                        drop(ping); shared.close("게이트웨이 PONG 제한 시간 초과"); break 'connection;
                    }
                    if ping.is_none() && last_ping.elapsed() >= shared.limits.ping_interval {
                        let nonce = rand::random::<u64>(); *ping = Some((nonce, Instant::now())); last_ping = Instant::now(); drop(ping);
                        if shared.control(vec![Frame { kind: FrameType::Ping, stream_id: 0, payload: nonce.to_be_bytes().to_vec() }]).is_err() { break 'connection; }
                    }
                }
            }
        };
        if let Err(error) = shared.route(frame) {
            shared.close(&format!("게이트웨이 프로토콜 위반: {error:#}"));
            break;
        }
    }
}

async fn writer_task<W: AsyncWrite + Unpin>(
    mut writer: W,
    shared: Arc<Shared>,
    mut data: mpsc::Receiver<Outgoing>,
    mut control: mpsc::Receiver<Outgoing>,
) {
    let _guard = TaskGuard(Arc::clone(&shared));
    let mut stopping = shared.stopping.subscribe();
    loop {
        if *stopping.borrow() {
            break;
        }
        let outgoing = tokio::select! { _ = stopping.changed() => break, message = control.recv() => message, message = data.recv() => message };
        let Some(outgoing) = outgoing else {
            break;
        };
        let writing = async {
            for frame in &outgoing.frames {
                let skip = matches!(
                    frame.kind,
                    FrameType::OpenTcp
                        | FrameType::OpenUdp
                        | FrameType::TcpData
                        | FrameType::UdpDatagram
                        | FrameType::TcpFin
                        | FrameType::DnsQuery
                ) && !shared
                    .book
                    .lock()
                    .map_err(|_| anyhow::anyhow!("다중화 상태 잠금 손상"))?
                    .streams
                    .contains_key(&frame.stream_id);
                if !skip {
                    gateway_wire::write_client(&mut writer, shared.dialect, frame).await?;
                } else if matches!(frame.kind, FrameType::TcpData | FrameType::UdpDatagram) {
                    shared.refund_send(
                        frame.stream_id,
                        shared.dialect.credit(frame.payload.len()) as u32,
                    );
                }
            }
            writer.flush().await?;
            Ok::<_, anyhow::Error>(())
        };
        let result = tokio::select! {
            _ = stopping.changed() => Err(anyhow::anyhow!("게이트웨이 전송이 취소됐습니다")),
            result = tokio::time::timeout(shared.limits.write_timeout, writing) => result.context("게이트웨이 쓰기 제한 시간 초과").and_then(|result| result),
        };
        if let Some(sender) = outgoing.flushed {
            let _ = sender.send(
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|error| format!("{error:#}")),
            );
        }
        if let Err(error) = result {
            shared.close(&format!("게이트웨이 송신 실패: {error:#}"));
            break;
        }
    }
}

/// 응답의 레코드 경계를 검사하고 원래 질문과 ID·종류·클래스를 대조한다.
fn validate_dns_response(query: &[u8], response: &[u8]) -> Result<()> {
    let expected = crate::fake_dns::parse_question(query)?;
    ensure!(
        response.len() >= 12
            && response.len() <= 65535
            && response[..2] == query[..2]
            && response[2] & 0xf8 == 0x80
            && response[4..6] == [0, 1],
        "DNS 응답 헤더가 요청과 다릅니다"
    );
    let (name, end) = crate::fake_dns::decode_name(response, 12)?;
    ensure!(
        response.len() >= end + 4
            && crate::fake_dns::normalize_domain(&name)? == expected.domain
            && response[end..end + 2] == expected.qtype.to_be_bytes()
            && response[end + 2..end + 4] == expected.qclass.to_be_bytes(),
        "DNS 응답 질문이 요청과 다릅니다"
    );
    let count = |offset| u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    let mut cursor = end + 4;
    for _ in 0..count(6) + count(8) + count(10) {
        let (_, end) = crate::fake_dns::decode_name(response, cursor)?;
        ensure!(response.len() >= end + 10, "DNS 응답 레코드가 잘렸습니다");
        let length = u16::from_be_bytes([response[end + 8], response[end + 9]]) as usize;
        cursor = end.checked_add(10 + length).context("DNS 길이 오버플로")?;
        ensure!(cursor <= response.len(), "DNS 레코드 본문이 잘렸습니다");
    }
    ensure!(
        cursor == response.len(),
        "DNS 응답 뒤에 불필요한 데이터가 있습니다"
    );
    Ok(())
}
