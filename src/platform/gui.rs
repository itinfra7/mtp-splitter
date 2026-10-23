//! 작은 데스크톱 창에서 실제 터널·규칙·서버 패키지를 제어한다.
//! 렌더링 스레드에서는 네트워크·프로세스 열거·디스크 교체 작업을 수행하지 않는다.

use super::{
    guard_lock, processes,
    runtime::{self, RunOptions, RuntimeObserver, RuntimeSnapshot},
};
use crate::{
    client_bundle::ClientBundle,
    config::{self, ProcessRule},
    nat_engine::TunnelState,
    paths::AppPaths,
    process_tracker::{CompiledRule, ProcessIdentity},
    transport::SecurityConfig,
    watchdog,
};
use anyhow::{Context, Result, ensure};
use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;

mod view;

const BG: Color32 = Color32::WHITE;
const PANEL: Color32 = Color32::WHITE;
const BORDER: Color32 = Color32::from_rgb(220, 225, 232);
const TEXT: Color32 = Color32::from_rgb(28, 37, 49);
const MUTED: Color32 = Color32::from_rgb(104, 116, 133);
const ACCENT: Color32 = Color32::from_rgb(37, 86, 151);
const AMBER: Color32 = Color32::from_rgb(158, 101, 18);
const RED: Color32 = Color32::from_rgb(183, 55, 75);

enum Job {
    Probe,
    Import(PathBuf),
    ClearServer,
    SaveRules(Vec<ProcessRule>),
    Processes,
    Inspect,
    Release(u32),
}
enum Event {
    Complete(Result<String>),
    RulesSaved(Vec<ProcessRule>),
    Processes(Vec<ProcessIdentity>),
    Guard(Option<u32>),
    Finished(Result<runtime::RunOutcome>),
    ServerChanged,
}

/// 백그라운드 결과가 도착할 때만 휴면 중인 창을 깨운다.
#[derive(Clone)]
struct EventSender {
    sender: mpsc::Sender<Event>,
    context: egui::Context,
}
impl EventSender {
    fn send(&self, event: Event) -> std::result::Result<(), mpsc::SendError<Event>> {
        self.sender.send(event)?;
        self.context.request_repaint();
        Ok(())
    }
}
#[derive(Default)]
struct RuleEditor {
    index: Option<usize>,
    name: String,
    path: String,
    hash: String,
    children: bool,
}
impl RuleEditor {
    fn from_path(path: &Path) -> Self {
        let normalized = path.to_string_lossy().replace('\\', "/");
        let normalized = normalized.strip_prefix("//?/").unwrap_or(&normalized);
        Self {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            path: globset::escape(normalized),
            children: true,
            ..Self::default()
        }
    }
    fn rule(&self) -> Result<ProcessRule> {
        fn value(text: &str) -> Option<String> {
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_owned())
        }
        let rule = ProcessRule {
            exe_name: value(&self.name),
            path_glob: value(&self.path),
            sha256: value(&self.hash),
            include_children: self.children,
        };
        CompiledRule::new(rule.clone())?;
        Ok(rule)
    }
}

fn active_guard(paths: &AppPaths) -> Result<Option<u32>> {
    let expected = paths.resolve("bin/watchdog.exe")?.canonicalize()?;
    for entry in fs::read_dir(paths.resolve("runtime")?)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        let Some(pid) = name
            .strip_prefix("watchdog-")
            .and_then(|s| s.strip_suffix(".token"))
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if let Ok(process) = processes::observe(pid, 0)
            && process.is_running()?
            && process.identity.image.canonicalize()? == expected
        {
            return Ok(Some(pid));
        }
    }
    Ok(None)
}

fn perform_job(paths: &AppPaths, job: Job, events: &EventSender) -> Result<String> {
    match job {
        Job::Probe => {
            let server = config::load_server(paths)?;
            let security = SecurityConfig::load(paths)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                use tokio::io::AsyncWriteExt;
                let (mut io, settings) =
                    crate::transport::connect(&server, &security, paths).await?;
                ensure!(
                    settings.capabilities & 7 == 7,
                    "서버의 TCP·UDP·DNS 기능이 모두 필요합니다"
                );
                let _ = io.shutdown().await;
                Ok::<_, anyhow::Error>(())
            })?;
            Ok("서버 상호 인증과 TCP·UDP·DNS 기능 협상 성공".into())
        }
        Job::Import(path) => {
            ClientBundle::read(&path)?.install(paths)?;
            let _ = events.send(Event::ServerChanged);
            Ok("서버 설정을 불러왔습니다".into())
        }
        Job::ClearServer => {
            let result = crate::client_bundle::clear_server(paths);
            let _ = events.send(Event::ServerChanged);
            result?;
            Ok("서버 설정을 삭제했습니다".into())
        }
        Job::SaveRules(rules) => {
            for rule in &rules {
                CompiledRule::new(rule.clone())?;
            }
            let _lock = paths
                .lock()
                .context("터널을 정지한 뒤 규칙을 편집하십시오")?;
            drop(guard_lock::root_lock(paths)?);
            paths.atomic_write("config/rules.json", &serde_json::to_vec_pretty(&rules)?)?;
            let _ = events.send(Event::RulesSaved(rules));
            Ok("대상 앱 규칙을 저장했습니다".into())
        }
        Job::Processes => {
            let mut processes = processes::snapshot()?;
            processes.retain(|p| {
                p.pid != std::process::id()
                    && !p
                        .image
                        .file_name()
                        .is_some_and(|s| s.eq_ignore_ascii_case("watchdog.exe"))
            });
            processes.sort_by_key(|p| {
                p.image
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase()
            });
            let _ = events.send(Event::Processes(processes));
            Ok("실행 중인 앱 목록을 갱신했습니다".into())
        }
        Job::Inspect => {
            let _ = events.send(Event::Guard(active_guard(paths)?));
            Ok(String::new())
        }
        Job::Release(pid) => {
            let process =
                processes::observe(pid, 0).context("남은 감시 프로세스를 확인하지 못했습니다")?;
            ensure!(
                process.identity.image.canonicalize()?
                    == paths.resolve("bin/watchdog.exe")?.canonicalize()?,
                "해제할 감시 프로세스의 경로가 다릅니다"
            );
            watchdog::request_release(paths, pid)?;
            let deadline = Instant::now() + Duration::from_secs(15);
            while process.is_running()? {
                ensure!(
                    Instant::now() < deadline,
                    "감시 해제 응답 시간이 초과됐습니다"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            // 같은 GUI 프로세스 안의 실행 작업이 종료된 뒤에만 남은 통지를 정리한다.
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                if let Ok(lock) = paths.lock() {
                    crate::shared_state::remove_idle(paths)?;
                    for suffix in ["token", "release", "stop-main"] {
                        match fs::remove_file(
                            paths.resolve(format!("runtime/watchdog-{pid}.{suffix}"))?,
                        ) {
                            Ok(()) => (),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                            Err(e) => return Err(e.into()),
                        }
                    }
                    let api = super::divert::DivertApi::load(paths)?;
                    super::driver_service::cleanup_idle(paths, &api)?;
                    drop(lock);
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "메인 실행의 정리를 기다리는 중입니다"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = events.send(Event::Guard(None));
            Ok("터널과 감시 차단을 명시적으로 해제했습니다".into())
        }
    }
}

struct Desktop {
    paths: Arc<AppPaths>,
    observer: RuntimeObserver,
    jobs: mpsc::SyncSender<Job>,
    events: mpsc::Receiver<Event>,
    sender: EventSender,
    stop: Option<oneshot::Sender<()>>,
    running: bool,
    busy: bool,
    guard: Option<u32>,
    admin: bool,
    tab: u8,
    rules: Vec<ProcessRule>,
    editor: Option<RuleEditor>,
    process_picker: bool,
    processes: Vec<ProcessIdentity>,
    search: String,
    server_ready: bool,
    endpoint: Option<String>,
    reveal_address: bool,
    probe_ok: bool,
    notice: Option<(String, bool)>,
    activity: VecDeque<(String, String, bool)>,
    _instance: File,
}
impl Desktop {
    fn new(paths: Arc<AppPaths>, instance: File, context: egui::Context) -> Self {
        let (jobs, requests) = mpsc::sync_channel(8);
        let (sender, events) = mpsc::channel();
        let sender = EventSender { sender, context };
        let background_paths = Arc::clone(&paths);
        let background_events = sender.clone();
        std::thread::spawn(move || {
            let mut last_guard = None;
            loop {
                let job = match requests.recv_timeout(Duration::from_secs(2)) {
                    Ok(job) => job,
                    Err(mpsc::RecvTimeoutError::Timeout) => Job::Inspect,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                if matches!(&job, Job::Inspect) {
                    match active_guard(&background_paths) {
                        Ok(pid) if last_guard != Some(pid) => {
                            last_guard = Some(pid);
                            if background_events.send(Event::Guard(pid)).is_err() {
                                break;
                            }
                        }
                        Ok(_) => (),
                        Err(error) => tracing::debug!(%error, "감시 프로세스 조회 실패"),
                    }
                    continue;
                }
                let result = perform_job(&background_paths, job, &background_events);
                if background_events.send(Event::Complete(result)).is_err() {
                    break;
                }
            }
        });
        let rules = config::load_rules(&paths).unwrap_or_default();
        let endpoint = config::load_server(&paths)
            .ok()
            .map(|s| format!("{}:{}", s.host, s.port));
        let server_ready = endpoint.is_some()
            && SecurityConfig::load(&paths)
                .and_then(|s| s.tls_config(&paths))
                .is_ok();
        let app = Self {
            paths,
            observer: Arc::new(Mutex::new(RuntimeSnapshot::default())),
            jobs,
            events,
            sender,
            stop: None,
            running: false,
            busy: false,
            guard: None,
            admin: is_elevated(),
            tab: 0,
            rules,
            editor: None,
            process_picker: false,
            processes: Vec::new(),
            search: String::new(),
            server_ready,
            endpoint,
            reveal_address: false,
            probe_ok: false,
            notice: None,
            activity: VecDeque::new(),
            _instance: instance,
        };
        let _ = app.jobs.try_send(Job::Inspect);
        app
    }
    fn log(&mut self, message: String, error: bool) {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let time = format!(
            "{:02}:{:02}:{:02}",
            (seconds / 3600 + 9) % 24,
            seconds / 60 % 60,
            seconds % 60
        );
        self.activity.push_front((time, message, error));
        self.activity.truncate(160);
    }
    fn submit(&mut self, job: Job) {
        match self.jobs.try_send(job) {
            Ok(()) => self.busy = true,
            Err(_) => self.notice = Some(("이전 작업이 끝난 뒤 다시 시도하십시오".into(), true)),
        }
    }
    fn poll(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Complete(result) => {
                    self.busy = false;
                    self.endpoint = config::load_server(&self.paths)
                        .ok()
                        .map(|s| format!("{}:{}", s.host, s.port));
                    self.server_ready = self.endpoint.is_some()
                        && SecurityConfig::load(&self.paths)
                            .and_then(|s| s.tls_config(&self.paths))
                            .is_ok();
                    match result {
                        Ok(message) if !message.is_empty() => {
                            if message.starts_with("서버 상호 인증") {
                                self.probe_ok = true;
                            }
                            self.endpoint = config::load_server(&self.paths)
                                .ok()
                                .map(|s| format!("{}:{}", s.host, s.port));
                            self.server_ready = self.endpoint.is_some()
                                && SecurityConfig::load(&self.paths)
                                    .and_then(|s| s.tls_config(&self.paths))
                                    .is_ok();
                            self.log(message.clone(), false);
                            self.notice = Some((message, false));
                        }
                        Ok(_) => (),
                        Err(error) => {
                            let message = self.redact(format!("{error:#}"));
                            self.log(message.clone(), true);
                            self.notice = Some((message, true));
                        }
                    }
                }
                Event::RulesSaved(rules) => {
                    self.rules = rules;
                    self.editor = None;
                }
                Event::Processes(processes) => {
                    self.processes = processes;
                    self.process_picker = true;
                }
                Event::Guard(pid) => self.guard = pid,
                Event::ServerChanged => {
                    self.probe_ok = false;
                    self.reveal_address = false;
                }
                Event::Finished(result) => {
                    self.running = false;
                    self.stop = None;
                    match result {
                        Ok(outcome) => {
                            self.guard = (!outcome.released).then_some(outcome.watchdog_pid);
                            self.log(
                                if outcome.released {
                                    "실행을 종료하고 차단을 해제했습니다"
                                } else {
                                    "실행을 정지했습니다. 감시 프로세스가 차단을 유지합니다."
                                }
                                .into(),
                                false,
                            );
                        }
                        Err(error) => {
                            let message = self.redact(format!("{error:#}"));
                            self.notice = Some((message.clone(), true));
                            self.log(message, true);
                            let _ = self.jobs.try_send(Job::Inspect);
                        }
                    }
                }
            }
        }
    }
    fn redact(&self, mut text: String) -> String {
        if let Ok(server) = config::load_server(&self.paths) {
            for private in [&server.secret_hex, &server.host, &server.tls_domain] {
                if !private.is_empty() {
                    text = text.replace(private, "[비공개]");
                }
            }
        }
        text
    }
    fn start(&mut self) {
        if self.running || self.guard.is_some() || self.busy {
            return;
        }
        let (stop, stopped) = oneshot::channel();
        self.stop = Some(stop);
        self.running = true;
        *self.observer.lock().unwrap_or_else(|e| e.into_inner()) = RuntimeSnapshot::default();
        let paths = Arc::clone(&self.paths);
        let observer = Arc::clone(&self.observer);
        let events = self.sender.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<runtime::RunOutcome> {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?;
                rt.block_on(runtime::run_observed(
                    paths,
                    RunOptions::default(),
                    async {
                        let _ = stopped.await;
                        Ok(())
                    },
                    Some(observer),
                ))
            })();
            let _ = events.send(Event::Finished(result));
        });
        self.notice = None;
        self.log("독립 감시와 터널 연결을 시작합니다".into(), false);
    }
    fn editable(&self) -> bool {
        !self.running && self.guard.is_none() && !self.busy
    }
    fn save_rule(&mut self) {
        let result = self
            .editor
            .as_ref()
            .context("편집 중인 규칙이 없습니다")
            .and_then(RuleEditor::rule);
        match result {
            Ok(rule) => {
                let mut rules = self.rules.clone();
                if let Some(index) = self.editor.as_ref().and_then(|e| e.index) {
                    rules[index] = rule;
                } else {
                    rules.retain(|r| {
                        !(r.exe_name.as_deref() == Some("example-target.exe")
                            && r.path_glob.is_none()
                            && r.sha256.is_none())
                    });
                    rules.push(rule);
                }
                self.submit(Job::SaveRules(rules));
            }
            Err(error) => self.notice = Some((format!("규칙 확인: {error:#}"), true)),
        }
    }
    fn dialogs(&mut self, ctx: &egui::Context) {
        if self.editor.is_some() {
            let mut open = true;
            let mut save = false;
            let mut browse = false;
            egui::Window::new("대상 앱 편집")
                .id(egui::Id::new("규칙 편집"))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_width(430.0)
                .show(ctx, |ui| {
                    let editor = self.editor.as_mut().unwrap();
                    ui.horizontal(|ui| {
                        ui.label("실행 파일");
                        if ui.button("파일 선택…").clicked() {
                            browse = true;
                        }
                    });
                    ui.add(
                        egui::TextEdit::singleline(&mut editor.name)
                            .hint_text("예: browser.exe")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(5.0);
                    ui.checkbox(&mut editor.children, "이 앱이 시작한 하위 프로세스도 포함");
                    egui::CollapsingHeader::new("경로·해시 조건").show(ui, |ui| {
                        ui.label(
                            RichText::new("입력한 조건을 모두 만족하는 앱에 적용합니다.")
                                .small()
                                .color(MUTED),
                        );
                        ui.label("실행 경로 패턴");
                        ui.add(
                            egui::TextEdit::singleline(&mut editor.path)
                                .desired_width(f32::INFINITY),
                        );
                        ui.label("SHA-256");
                        ui.add(
                            egui::TextEdit::singleline(&mut editor.hash)
                                .desired_width(f32::INFINITY),
                        );
                    });
                    ui.add_space(8.0);
                    if ui
                        .add_enabled(
                            !self.busy,
                            egui::Button::new(RichText::new("규칙 저장").color(BG)).fill(ACCENT),
                        )
                        .clicked()
                    {
                        save = true;
                    }
                });
            if !open {
                self.editor = None;
            }
            if browse {
                match choose_file(&self.paths, false) {
                    Ok(Some(path)) => {
                        self.editor = Some(RuleEditor {
                            index: self.editor.as_ref().and_then(|e| e.index),
                            ..RuleEditor::from_path(&path)
                        })
                    }
                    Ok(None) => (),
                    Err(e) => self.notice = Some((format!("{e:#}"), true)),
                }
            }
            if save {
                self.save_rule();
            }
        }
        if self.process_picker {
            let mut open = true;
            let mut selected = None;
            egui::Window::new("실행 중인 앱")
                .open(&mut open)
                .collapsible(false)
                .default_size([470.0, 350.0])
                .show(ctx, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("앱 이름 또는 경로 검색")
                            .desired_width(f32::INFINITY),
                    );
                    let search = self.search.to_lowercase();
                    egui::ScrollArea::vertical()
                        .max_height(300.0)
                        .show(ui, |ui| {
                            for process in &self.processes {
                                let path = process.image.to_string_lossy();
                                if !path.to_lowercase().contains(&search) {
                                    continue;
                                }
                                let name = process
                                    .image
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy();
                                if ui
                                    .selectable_label(
                                        false,
                                        format!("{name}    ·    PID {}", process.pid),
                                    )
                                    .on_hover_text(path.as_ref())
                                    .clicked()
                                {
                                    selected = Some(process.image.clone());
                                }
                            }
                        });
                });
            self.process_picker = open;
            if let Some(path) = selected {
                self.process_picker = false;
                self.editor = Some(RuleEditor::from_path(&path));
            }
        }
    }
}
impl Desktop {
    fn draw(&mut self, ctx: &egui::Context) {
        self.poll();
        if self.running {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        let dropped = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect::<Vec<_>>()
        });
        if self.editable() {
            for path in dropped {
                if path
                    .extension()
                    .is_some_and(|s| s.eq_ignore_ascii_case("zip"))
                {
                    self.submit(Job::Import(path));
                    break;
                }
                if path
                    .extension()
                    .is_some_and(|s| s.eq_ignore_ascii_case("exe"))
                {
                    self.editor = Some(RuleEditor::from_path(&path));
                    break;
                }
            }
        }
        let view = self
            .observer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.layout(ctx, &view);
        self.dialogs(ctx);
    }
}
impl eframe::App for Desktop {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.draw(ctx);
    }
    fn on_exit(&mut self) {
        // 창 닫기는 해제 명령이 아니다. 메인 종료 또는 파이프 단절 뒤 감시기가 계속 차단한다.
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
    fn persist_egui_memory(&self) -> bool {
        false
    }
}

fn is_elevated() -> bool {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut length = 0;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    result != 0 && elevation.TokenIsElevated != 0
}
fn choose_file(paths: &AppPaths, zip: bool) -> Result<Option<PathBuf>> {
    use windows_sys::Win32::UI::Controls::Dialogs::*;
    let mut buffer = vec![0u16; 32768];
    let filter: Vec<u16> = if zip {
        "서버 ZIP\0*.zip\0모든 파일\0*.*\0\0"
    } else {
        "실행 파일\0*.exe\0모든 파일\0*.*\0\0"
    }
    .encode_utf16()
    .collect();
    let directory: Vec<_> = paths
        .root()
        .parent()
        .unwrap_or(paths.root())
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    // 파일 선택창을 메인 창에 귀속하고 최근 파일 목록에 등록하지 않는다.
    dialog.hwndOwner =
        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow() };
    dialog.lpstrFilter = filter.as_ptr();
    dialog.lpstrFile = buffer.as_mut_ptr();
    dialog.nMaxFile = buffer.len() as u32;
    dialog.lpstrInitialDir = directory.as_ptr();
    dialog.Flags = OFN_FILEMUSTEXIST
        | OFN_PATHMUSTEXIST
        | OFN_NOCHANGEDIR
        | OFN_EXPLORER
        | OFN_DONTADDTORECENT;
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 {
        let error = unsafe { CommDlgExtendedError() };
        ensure!(error == 0, "파일 선택창 오류: {error}");
        return Ok(None);
    }
    let length = buffer
        .iter()
        .position(|c| *c == 0)
        .context("파일 선택 경로가 잘못됐습니다")?;
    Ok(Some(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length],
    ))))
}

pub fn run(paths: Arc<AppPaths>) -> Result<()> {
    let instance = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(paths.resolve("runtime/gui.lock")?)?;
    fs2::FileExt::try_lock_exclusive(&instance).context("GUI가 이미 열려 있습니다")?;
    let font = fs::read(paths.resolve("bin/fonts/NanumGothic.ttf")?)
        .context("앱 bin/fonts의 한국어 글꼴이 없습니다. 글꼴 준비 스크립트를 실행하십시오")?;
    let persistence = paths.resolve("runtime/gui-state.ron")?;
    let options = native_options(persistence);
    eframe::run_native(
        "mtp-splitter",
        options,
        Box::new(move |creation| {
            let ctx = &creation.egui_ctx;
            if let Some(render) = &creation.wgpu_render_state {
                let adapter = render.adapter.get_info();
                tracing::info!(backend = ?adapter.backend, device_type = ?adapter.device_type, "GUI 렌더러 준비 완료");
            }
            apply_style(ctx, font);
            Ok(Box::new(Desktop::new(paths, instance, ctx.clone())))
        }),
    ).map_err(|error| anyhow::anyhow!("GUI 시작 실패: {error}"))
}

fn native_options(persistence: PathBuf) -> eframe::NativeOptions {
    use eframe::egui_wgpu::{WgpuConfiguration, WgpuSetup, WgpuSetupCreateNew};
    let setup = WgpuSetupCreateNew {
        instance_descriptor: wgpu::InstanceDescriptor {
            backends: wgpu::Backends::DX12,
            ..Default::default()
        },
        power_preference: wgpu::PowerPreference::LowPower,
        ..Default::default()
    };
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([590.0, 410.0])
            .with_min_inner_size([520.0, 350.0])
            .with_decorations(true)
            .with_transparent(false)
            .with_icon(egui::IconData::default()),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: WgpuConfiguration {
            present_mode: wgpu::PresentMode::Fifo,
            desired_maximum_frame_latency: Some(2),
            wgpu_setup: WgpuSetup::CreateNew(setup),
            ..Default::default()
        },
        vsync: true,
        dithering: false,
        persist_window: false,
        persistence_path: Some(persistence),
        ..Default::default()
    }
}

fn apply_style(ctx: &egui::Context, font: Vec<u8>) {
    ctx.set_theme(egui::ThemePreference::Light);
    let mut fonts = egui::FontDefinitions::default();
    fonts
        .font_data
        .insert("한국어".into(), egui::FontData::from_owned(font).into());
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "한국어".into());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("한국어".into());
    ctx.set_fonts(fonts);
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(7.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 5.0);
    style
        .text_styles
        .insert(egui::TextStyle::Body, FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, FontId::proportional(12.0));
    style
        .text_styles
        .insert(egui::TextStyle::Small, FontId::proportional(11.0));
    style.visuals = egui::Visuals::light();
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.window_stroke = Stroke::new(1.0_f32, BORDER);
    style.animation_time = 0.0;
    style.visuals.window_corner_radius = 4.into();
    style.visuals.widgets.inactive.corner_radius = 3.into();
    style.visuals.widgets.hovered.corner_radius = 3.into();
    style.visuals.widgets.active.corner_radius = 3.into();
    style.visuals.selection.bg_fill = ACCENT.gamma_multiply(0.25);
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(237, 240, 244);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(225, 232, 239);
    ctx.set_style(style);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_executable_path_is_a_literal_glob_including_brackets() {
        let path = Path::new(r"C:\Apps\[한국어]\target.exe");
        let editor = RuleEditor::from_path(path);
        let rule = CompiledRule::new(editor.rule().unwrap()).unwrap();
        assert!(rule.matches(path).unwrap());
        assert!(
            !rule
                .matches(Path::new(r"C:\Apps\한국어\target.exe"))
                .unwrap()
        );
    }

    #[test]
    fn idle_window_settles_without_periodic_repaint_or_layout_oscillation() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runtime/tmp")
            .join(format!("gui-idle-{}", rand::random::<u64>()));
        fs::create_dir_all(&root).unwrap();
        let paths = Arc::new(AppPaths::new(root).unwrap());
        paths.prepare().unwrap();
        fs::write(paths.resolve("config/rules.json").unwrap(), b"[]").unwrap();
        let instance = File::create(paths.resolve("runtime/test.lock").unwrap()).unwrap();
        let ctx = egui::Context::default();
        ctx.style_mut(|style| style.animation_time = 0.0);
        let mut app = Desktop::new(paths, instance, ctx.clone());
        let mut last_geometry = None;
        for pass in 0..12 {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(590.0, 410.0),
                    )),
                    time: Some(pass as f64),
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
            if pass >= 8 {
                let delay = output
                    .viewport_output
                    .get(&egui::ViewportId::ROOT)
                    .unwrap()
                    .repaint_delay;
                assert!(
                    delay >= Duration::from_secs(1),
                    "대기 화면이 다시 그리기를 반복합니다: {delay:?}"
                );
                // 고정 입력에서 도형 경계가 번갈아 변하는 레이아웃도 함께 검출한다.
                let geometry: Vec<_> = output
                    .shapes
                    .iter()
                    .map(|shape| shape.shape.visual_bounding_rect())
                    .collect();
                if let Some(previous) = &last_geometry {
                    assert_eq!(previous, &geometry);
                }
                last_geometry = Some(geometry);
            }
        }
    }
}
