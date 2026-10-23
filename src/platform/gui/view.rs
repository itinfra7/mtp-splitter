//! 고정된 도구 모음과 목록을 사용하는 밝은 데스크톱 화면이다.
//! 화면을 그리는 동안 설정 파일이나 인증서를 다시 읽지 않는다.

use super::*;

impl Desktop {
    pub(super) fn layout(&mut self, ctx: &egui::Context, view: &RuntimeSnapshot) {
        egui::TopBottomPanel::bottom("통계")
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .inner_margin(egui::Margin::symmetric(14, 7)),
            )
            .show(ctx, |ui| {
                ui.separator();
                ui.horizontal(|ui| {
                    let text = if self.running {
                        format!(
                            "프로세스 {}   ·   연결 {}   ·   패킷 {}",
                            view.tracked_processes, view.sessions, view.handled_packets
                        )
                    } else if self.guard.is_some() {
                        "차단 유지 중".into()
                    } else {
                        format!("대상 앱 {}개", self.rules.len())
                    };
                    ui.label(RichText::new(text).size(11.0).color(MUTED));
                    if self.busy {
                        ui.label(RichText::new("처리 중…").size(11.0).color(MUTED));
                    }
                });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(14))
            .show(ctx, |ui| {
                self.connection_bar(ui, view);
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    for (index, name) in ["앱 규칙", "서버", "기록"].iter().enumerate() {
                        let active = self.tab as usize == index;
                        let response = ui.add(
                            egui::Button::new(
                                RichText::new(*name)
                                    .color(if active { ACCENT } else { MUTED })
                                    .strong(),
                            )
                            .min_size(Vec2::new(66.0, 28.0))
                            .frame(false),
                        );
                        if active {
                            ui.painter().hline(
                                response.rect.x_range(),
                                response.rect.bottom(),
                                Stroke::new(2.0_f32, ACCENT),
                            );
                        }
                        if response.clicked() {
                            self.tab = index as u8;
                        }
                    }
                });
                ui.add_space(10.0);
                if let Some((message, error)) = self.notice.clone() {
                    ui.horizontal(|ui| {
                        let available = (ui.available_width() - 25.0).max(80.0);
                        ui.add_sized(
                            [available, 20.0],
                            egui::Label::new(RichText::new(&message).size(11.0).color(if error {
                                RED
                            } else {
                                ACCENT
                            }))
                            .truncate(),
                        )
                        .on_hover_text(&message);
                        if ui.small_button("×").clicked() {
                            self.notice = None;
                        }
                    });
                    ui.add_space(5.0);
                }
                match self.tab {
                    0 => self.app_list(ui),
                    1 => self.server_details(ui),
                    _ => self.activity_list(ui),
                }
            });
    }

    fn connection_bar(&mut self, ui: &mut egui::Ui, view: &RuntimeSnapshot) {
        let (label, color) = if self.running {
            match view.state {
                TunnelState::Connected => ("연결됨", ACCENT),
                TunnelState::Reconnecting => ("재연결 중 · 직접 연결 차단", AMBER),
                TunnelState::Down => ("연결 준비 중", MUTED),
            }
        } else if self.guard.is_some() {
            ("연결 중지 · 차단 유지", AMBER)
        } else {
            ("연결 안 됨", TEXT)
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new("●").size(10.0).color(color));
            ui.label(RichText::new(label).size(17.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.running {
                    if ui
                        .add_enabled(
                            self.stop.is_some(),
                            egui::Button::new("중지 · 차단 유지").min_size(Vec2::new(122.0, 30.0)),
                        )
                        .on_hover_text("터널을 정지하고 대상 앱의 직접 연결 차단은 유지합니다")
                        .clicked()
                        && let Some(stop) = self.stop.take()
                    {
                        let _ = stop.send(());
                    }
                } else if ui
                    .add_enabled(
                        self.editable()
                            && self.admin
                            && self.server_ready
                            && !self.rules.is_empty(),
                        egui::Button::new(RichText::new("연결 시작").color(Color32::WHITE))
                            .fill(ACCENT)
                            .min_size(Vec2::new(92.0, 30.0)),
                    )
                    .on_hover_text("선택한 앱의 TCP·UDP·DNS를 서버로 연결합니다")
                    .clicked()
                {
                    self.start();
                }
                let pid = view.watchdog_pid.filter(|_| self.running).or(self.guard);
                if pid.is_some()
                    && ui
                        .add_enabled(!self.busy, egui::Button::new("종료 · 차단 해제"))
                        .on_hover_text(
                            "터널과 감시를 종료하고 대상 앱의 일반 인터넷 연결을 허용합니다",
                        )
                        .clicked()
                    && let Some(pid) = pid
                {
                    self.submit(Job::Release(pid));
                }
            });
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let state = if !self.admin {
                "관리자 권한으로 다시 실행하세요"
            } else if self.server_ready {
                "서버 설정됨"
            } else {
                "서버 설정을 불러오세요"
            };
            ui.label(RichText::new(state).size(12.0).color(if !self.admin {
                AMBER
            } else {
                MUTED
            }));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(self.editable(), egui::Button::new("ZIP 불러오기…"))
                    .on_hover_text("서버에서 내려받은 설정 ZIP을 선택합니다")
                    .clicked()
                {
                    match choose_file(&self.paths, true) {
                        Ok(Some(path)) => self.submit(Job::Import(path)),
                        Ok(None) => (),
                        Err(error) => self.notice = Some((format!("{error:#}"), true)),
                    }
                }
            });
        });
    }

    fn app_list(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.editable(), egui::Button::new("앱 추가…"))
                .clicked()
            {
                match choose_file(&self.paths, false) {
                    Ok(Some(path)) => self.editor = Some(RuleEditor::from_path(&path)),
                    Ok(None) => (),
                    Err(error) => self.notice = Some((format!("{error:#}"), true)),
                }
            }
            if ui
                .add_enabled(self.editable(), egui::Button::new("실행 중인 앱…"))
                .clicked()
            {
                self.submit(Job::Processes);
            }
            if ui
                .add_enabled(
                    self.editable(),
                    egui::Button::new("이름으로 추가").frame(false),
                )
                .clicked()
            {
                self.editor = Some(RuleEditor {
                    children: true,
                    ..Default::default()
                });
            }
        });
        ui.add_space(8.0);
        ui.separator();
        let mut edit = None;
        let mut remove = None;
        egui::ScrollArea::vertical()
            .id_salt("앱 목록")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.rules.is_empty() {
                    ui.add_space(20.0);
                    ui.label(RichText::new("터널로 연결할 앱을 추가하세요.").color(MUTED));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("EXE 파일을 이 창에 놓아도 추가할 수 있습니다.")
                            .size(12.0)
                            .color(MUTED),
                    );
                }
                for (index, rule) in self.rules.iter().enumerate() {
                    ui.push_id(index, |ui| {
                        ui.add_space(7.0);
                        let available = ui.available_width();
                        ui.horizontal(|ui| {
                            ui.allocate_ui_with_layout(
                                Vec2::new((available - 104.0).max(180.0), 40.0),
                                egui::Layout::top_down(egui::Align::Min),
                                |ui| {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(
                                                rule.exe_name
                                                    .as_deref()
                                                    .unwrap_or("경로·해시 규칙"),
                                            )
                                            .strong(),
                                        )
                                        .truncate(),
                                    );
                                    let detail = rule.path_glob.as_deref().unwrap_or(
                                        if rule.include_children {
                                            "자식 프로세스 포함"
                                        } else {
                                            "이 프로세스만"
                                        },
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(detail).size(11.0).color(MUTED),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(detail);
                                },
                            );
                            if ui
                                .add_enabled(
                                    self.editable(),
                                    egui::Button::new("편집").frame(false),
                                )
                                .clicked()
                            {
                                edit = Some(index);
                            }
                            if ui
                                .add_enabled(
                                    self.editable(),
                                    egui::Button::new("삭제").frame(false),
                                )
                                .clicked()
                            {
                                remove = Some(index);
                            }
                        });
                        ui.add_space(4.0);
                        ui.separator();
                    });
                }
            });
        if let Some(index) = edit {
            let rule = &self.rules[index];
            self.editor = Some(RuleEditor {
                index: Some(index),
                name: rule.exe_name.clone().unwrap_or_default(),
                path: rule.path_glob.clone().unwrap_or_default(),
                hash: rule.sha256.clone().unwrap_or_default(),
                children: rule.include_children,
            });
        }
        if let Some(index) = remove {
            let mut rules = self.rules.clone();
            rules.remove(index);
            self.submit(Job::SaveRules(rules));
        }
    }

    fn server_details(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("서버 설정")
            .num_columns(2)
            .spacing([24.0, 12.0])
            .show(ui, |ui| {
                ui.label(RichText::new("접속 주소").color(MUTED));
                ui.label(if self.reveal_address {
                    self.endpoint.as_deref().unwrap_or("설정 없음")
                } else if self.endpoint.is_some() {
                    "설정됨 · 주소 숨김"
                } else {
                    "설정 없음"
                });
                ui.end_row();
                ui.label(RichText::new("전송").color(MUTED));
                ui.label("TCP · UDP · DNS");
                ui.end_row();
                ui.label(RichText::new("인증서").color(MUTED));
                ui.label(if self.server_ready {
                    "설정됨"
                } else {
                    "서버 ZIP 필요"
                });
                ui.end_row();
                ui.label(RichText::new("연결 검사").color(MUTED));
                ui.label(if self.probe_ok {
                    "통과"
                } else {
                    "검사 전"
                });
                ui.end_row();
            });
        ui.add_space(10.0);
        ui.checkbox(&mut self.reveal_address, "서버 주소 표시");
        ui.add_space(8.0);
        if ui
            .add_enabled(
                self.editable(),
                egui::Button::new("서버 설정 삭제").fill(Color32::TRANSPARENT),
            )
            .on_hover_text("서버 구성·인증서를 삭제합니다. 앱 규칙과 원본 ZIP은 유지합니다.")
            .clicked()
        {
            self.submit(Job::ClearServer);
        }
        if ui
            .add_enabled(
                !self.busy && self.server_ready,
                egui::Button::new("연결 검사"),
            )
            .clicked()
        {
            self.submit(Job::Probe);
        }
        ui.add_space(14.0);
        ui.label(
            RichText::new("설정 변경: 위의 ZIP 불러오기 또는 ZIP 파일 끌어 놓기")
                .size(12.0)
                .color(MUTED),
        );
        if !self.editable() {
            ui.label(
                RichText::new("변경하려면 터널을 중지하고 차단을 해제하세요.")
                    .size(12.0)
                    .color(AMBER),
            );
        }
    }

    fn activity_list(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("기록")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.activity.is_empty() {
                    ui.label(RichText::new("기록 없음").color(MUTED));
                }
                for (time, message, error) in &self.activity {
                    ui.horizontal_top(|ui| {
                        ui.label(RichText::new(time).size(11.0).color(MUTED));
                        ui.add(
                            egui::Label::new(RichText::new(message).size(12.0).color(if *error {
                                RED
                            } else {
                                TEXT
                            }))
                            .wrap(),
                        );
                    });
                    ui.add_space(5.0);
                }
            });
    }
}
