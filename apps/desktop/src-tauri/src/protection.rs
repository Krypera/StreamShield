use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use core_capture::WindowsPrimaryDisplaySource;
use core_detect::WalletSecretDetector;
use core_obs::{LocalObsController, StubTransport, WebSocketObsTransport};
use core_ocr::LocalOcrEngine;
use core_policy::DefaultPolicyEngine;
use core_redact::OverlayRedactionRenderer;
use core_runtime::{PipelineRuntime, RuntimeScanOutcome};
use core_types::{AppConfig, ConfidenceLevel, PanicBehavior};
use device_query::{DeviceQuery, DeviceState, Keycode};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProtectionStatusSnapshot {
    pub running: bool,
    pub ocr_ready: bool,
    pub last_scan_timestamp_ms: Option<u64>,
    pub last_findings_count: usize,
    pub last_redaction_targets: usize,
    pub last_confidence: String,
    pub panic_latched: bool,
    pub obs_locked: bool,
    pub hotkey_triggers: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct ProtectionStatus {
    running: bool,
    ocr_ready: bool,
    last_scan_timestamp_ms: Option<u64>,
    last_findings_count: usize,
    last_redaction_targets: usize,
    last_confidence: ConfidenceLevel,
    panic_latched: bool,
    obs_locked: bool,
    hotkey_triggers: u64,
    last_error: Option<String>,
}

impl Default for ProtectionStatus {
    fn default() -> Self {
        Self {
            running: false,
            ocr_ready: false,
            last_scan_timestamp_ms: None,
            last_findings_count: 0,
            last_redaction_targets: 0,
            last_confidence: ConfidenceLevel::Low,
            panic_latched: false,
            obs_locked: false,
            hotkey_triggers: 0,
            last_error: None,
        }
    }
}

impl ProtectionStatus {
    fn snapshot(&self) -> ProtectionStatusSnapshot {
        ProtectionStatusSnapshot {
            running: self.running,
            ocr_ready: self.ocr_ready,
            last_scan_timestamp_ms: self.last_scan_timestamp_ms,
            last_findings_count: self.last_findings_count,
            last_redaction_targets: self.last_redaction_targets,
            last_confidence: format!("{:?}", self.last_confidence),
            panic_latched: self.panic_latched,
            obs_locked: self.obs_locked,
            hotkey_triggers: self.hotkey_triggers,
            last_error: self.last_error.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct HotkeySpec {
    require_ctrl: bool,
    require_shift: bool,
    require_alt: bool,
    primary: Keycode,
}

impl HotkeySpec {
    fn parse(raw: &str) -> Option<Self> {
        let mut require_ctrl = false;
        let mut require_shift = false;
        let mut require_alt = false;
        let mut primary: Option<Keycode> = None;

        for part in raw.split('+').map(|p| p.trim().to_ascii_lowercase()) {
            match part.as_str() {
                "ctrl" | "control" => require_ctrl = true,
                "shift" => require_shift = true,
                "alt" => require_alt = true,
                other => {
                    primary = parse_keycode(other);
                }
            }
        }

        Some(Self {
            require_ctrl,
            require_shift,
            require_alt,
            primary: primary?,
        })
    }

    fn is_pressed(&self, keys: &[Keycode]) -> bool {
        if self.require_ctrl
            && !(keys.contains(&Keycode::LControl) || keys.contains(&Keycode::RControl))
        {
            return false;
        }
        if self.require_shift && !(keys.contains(&Keycode::LShift) || keys.contains(&Keycode::RShift))
        {
            return false;
        }
        if self.require_alt && !(keys.contains(&Keycode::LAlt) || keys.contains(&Keycode::RAlt)) {
            return false;
        }
        keys.contains(&self.primary)
    }
}

fn parse_keycode(token: &str) -> Option<Keycode> {
    match token {
        "pause" => Some(Keycode::Pause),
        "f1" => Some(Keycode::F1),
        "f2" => Some(Keycode::F2),
        "f3" => Some(Keycode::F3),
        "f4" => Some(Keycode::F4),
        "f5" => Some(Keycode::F5),
        "f6" => Some(Keycode::F6),
        "f7" => Some(Keycode::F7),
        "f8" => Some(Keycode::F8),
        "f9" => Some(Keycode::F9),
        "f10" => Some(Keycode::F10),
        "f11" => Some(Keycode::F11),
        "f12" => Some(Keycode::F12),
        "0" => Some(Keycode::Key0),
        "1" => Some(Keycode::Key1),
        "2" => Some(Keycode::Key2),
        "3" => Some(Keycode::Key3),
        "4" => Some(Keycode::Key4),
        "5" => Some(Keycode::Key5),
        "6" => Some(Keycode::Key6),
        "7" => Some(Keycode::Key7),
        "8" => Some(Keycode::Key8),
        "9" => Some(Keycode::Key9),
        "a" => Some(Keycode::A),
        "b" => Some(Keycode::B),
        "c" => Some(Keycode::C),
        "d" => Some(Keycode::D),
        "e" => Some(Keycode::E),
        "f" => Some(Keycode::F),
        "g" => Some(Keycode::G),
        "h" => Some(Keycode::H),
        "i" => Some(Keycode::I),
        "j" => Some(Keycode::J),
        "k" => Some(Keycode::K),
        "l" => Some(Keycode::L),
        "m" => Some(Keycode::M),
        "n" => Some(Keycode::N),
        "o" => Some(Keycode::O),
        "p" => Some(Keycode::P),
        "q" => Some(Keycode::Q),
        "r" => Some(Keycode::R),
        "s" => Some(Keycode::S),
        "t" => Some(Keycode::T),
        "u" => Some(Keycode::U),
        "v" => Some(Keycode::V),
        "w" => Some(Keycode::W),
        "x" => Some(Keycode::X),
        "y" => Some(Keycode::Y),
        "z" => Some(Keycode::Z),
        _ => None,
    }
}

pub struct ProtectionService {
    stop_flag: Option<Arc<AtomicBool>>,
    clear_latch_flag: Option<Arc<AtomicBool>>,
    manual_panic_flag: Option<Arc<AtomicBool>>,
    handle: Option<JoinHandle<()>>,
    status: Arc<Mutex<ProtectionStatus>>,
}

impl Default for ProtectionService {
    fn default() -> Self {
        Self {
            stop_flag: None,
            clear_latch_flag: None,
            manual_panic_flag: None,
            handle: None,
            status: Arc::new(Mutex::new(ProtectionStatus::default())),
        }
    }
}

impl ProtectionService {
    pub fn snapshot(&self) -> ProtectionStatusSnapshot {
        self.status
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or(ProtectionStatus::default().snapshot())
    }

    pub fn start(
        &mut self,
        config: Arc<Mutex<AppConfig>>,
        panic_active: Arc<Mutex<bool>>,
        recent_events: Arc<Mutex<Vec<String>>>,
    ) -> Result<(), String> {
        if self.handle.is_some() {
            return Ok(());
        }

        let stop = Arc::new(AtomicBool::new(false));
        let clear_latch = Arc::new(AtomicBool::new(false));
        let manual_panic = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);
        let clear_clone = Arc::clone(&clear_latch);
        let manual_panic_clone = Arc::clone(&manual_panic);
        let status = Arc::clone(&self.status);

        let handle = thread::Builder::new()
            .name("streamshield-protection-loop".to_string())
            .spawn(move || {
                if let Ok(mut s) = status.lock() {
                    s.running = true;
                    s.last_error = None;
                }

                let source = WindowsPrimaryDisplaySource::new();
                let detector = WalletSecretDetector;
                let policy = DefaultPolicyEngine;
                let renderer = OverlayRedactionRenderer::default();

                let obs_controller = create_obs_controller();

                let ocr = match LocalOcrEngine::new_tesseract(None, "eng") {
                    Ok(engine) => {
                        if let Ok(mut s) = status.lock() {
                            s.ocr_ready = true;
                            s.last_error = None;
                        }
                        engine
                    }
                    Err(err) => {
                        if let Ok(mut s) = status.lock() {
                            s.ocr_ready = false;
                            s.last_error = Some(format!(
                                "Local OCR initialization failed. Install Tesseract and tessdata: {err}"
                            ));
                        }
                        push_event(&recent_events, "OCR backend unavailable; protection loop paused");
                        while !stop_clone.load(Ordering::Relaxed) {
                            thread::sleep(Duration::from_millis(500));
                        }
                        if let Ok(mut s) = status.lock() {
                            s.running = false;
                        }
                        return;
                    }
                };

                let mut runtime =
                    PipelineRuntime::new(source, ocr, detector, policy, renderer, obs_controller);

                let keyboard = DeviceState::new();
                let mut hotkey_was_down = false;

                while !stop_clone.load(Ordering::Relaxed) {
                    if clear_clone.swap(false, Ordering::Relaxed) {
                        if runtime.clear_alert_latch().is_ok() {
                            if let Ok(mut panic_state) = panic_active.lock() {
                                *panic_state = false;
                            }
                            push_event(&recent_events, "Panic latch cleared");
                        }
                    }

                    let cfg = config.lock().map(|g| g.clone()).unwrap_or_default();

                    if manual_panic_clone.swap(false, Ordering::Relaxed) {
                        match runtime.trigger_manual_panic(&cfg) {
                            Ok(()) => {
                                if let Ok(mut panic_state) = panic_active.lock() {
                                    *panic_state = true;
                                }
                                push_event(
                                    &recent_events,
                                    &format!(
                                        "Manual panic requested ({})",
                                        panic_behavior_label(cfg.panic_behavior)
                                    ),
                                );
                            }
                            Err(err) => {
                                if let Ok(mut s) = status.lock() {
                                    s.last_error = Some(format!("manual panic failed: {err}"));
                                }
                            }
                        }
                    }

                    if let Some(hotkey) = HotkeySpec::parse(&cfg.panic_hotkey) {
                        let keys = keyboard.get_keys();
                        let hotkey_pressed = hotkey.is_pressed(&keys);
                        if hotkey_pressed && !hotkey_was_down {
                            match runtime.trigger_manual_panic(&cfg) {
                                Ok(()) => {
                                    if let Ok(mut panic_state) = panic_active.lock() {
                                        *panic_state = true;
                                    }
                                    if let Ok(mut s) = status.lock() {
                                        s.hotkey_triggers = s.hotkey_triggers.saturating_add(1);
                                    }
                                    push_event(
                                        &recent_events,
                                        &format!(
                                            "Manual panic hotkey triggered ({})",
                                            panic_behavior_label(cfg.panic_behavior)
                                        ),
                                    );
                                }
                                Err(err) => {
                                    if let Ok(mut s) = status.lock() {
                                        s.last_error = Some(format!("manual panic failed: {err}"));
                                    }
                                }
                            }
                        }
                        hotkey_was_down = hotkey_pressed;
                    }

                    let scan_result = runtime.scan_once(&cfg);
                    let now_ms = current_epoch_ms();

                    match scan_result {
                        Ok(outcome) => {
                            update_status_success(&status, now_ms, &outcome);
                            if outcome.findings_count > 0 {
                                push_event(
                                    &recent_events,
                                    &format!(
                                        "Risk finding(s): count={}, confidence={:?}",
                                        outcome.findings_count, outcome.max_confidence
                                    ),
                                );
                            }
                            if outcome.redaction_target_count > 0 {
                                push_event(
                                    &recent_events,
                                    &format!(
                                        "Region redaction active for {} target(s)",
                                        outcome.redaction_target_count
                                    ),
                                );
                            }
                            if outcome.panic_latched {
                                if let Ok(mut panic_state) = panic_active.lock() {
                                    *panic_state = true;
                                }
                                push_event(&recent_events, "Panic shield latched due to critical risk");
                            }
                            if outcome.obs_locked {
                                push_event(&recent_events, "OBS safe scene lock is active");
                            }
                        }
                        Err(err) => {
                            if let Ok(mut s) = status.lock() {
                                s.last_error = Some(format!("Protection scan error: {err}"));
                                s.last_scan_timestamp_ms = Some(now_ms);
                            }
                            push_event(&recent_events, "Protection loop encountered a scan error");
                        }
                    }

                    thread::sleep(Duration::from_millis(cfg.scan_interval_ms.clamp(150, 5000)));
                }

                if let Ok(mut s) = status.lock() {
                    s.running = false;
                }
            })
            .map_err(|e| format!("failed to start protection loop thread: {e}"))?;

        self.stop_flag = Some(stop);
        self.clear_latch_flag = Some(clear_latch);
        self.manual_panic_flag = Some(manual_panic);
        self.handle = Some(handle);

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(flag) = &self.stop_flag {
            flag.store(true, Ordering::Relaxed);
        }

        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| "failed to join protection loop thread".to_string())?;
        }

        self.stop_flag = None;
        self.clear_latch_flag = None;
        self.manual_panic_flag = None;

        if let Ok(mut s) = self.status.lock() {
            s.running = false;
        }

        Ok(())
    }

    pub fn request_clear_latch(&self) {
        if let Some(flag) = &self.clear_latch_flag {
            flag.store(true, Ordering::Relaxed);
        }
    }

    pub fn request_manual_panic(&self) {
        if let Some(flag) = &self.manual_panic_flag {
            flag.store(true, Ordering::Relaxed);
        }
    }
}

fn create_obs_controller() -> LocalObsController {
    match WebSocketObsTransport::new() {
        Ok(ws) => LocalObsController::new(ws),
        Err(_) => LocalObsController::new(StubTransport),
    }
}

fn panic_behavior_label(v: PanicBehavior) -> &'static str {
    match v {
        PanicBehavior::ShieldOnly => "shield-only",
        PanicBehavior::ObsOnly => "obs-only",
        PanicBehavior::ShieldAndObs => "shield-and-obs",
    }
}

fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn update_status_success(status: &Arc<Mutex<ProtectionStatus>>, now_ms: u64, outcome: &RuntimeScanOutcome) {
    if let Ok(mut s) = status.lock() {
        s.last_error = None;
        s.last_scan_timestamp_ms = Some(now_ms);
        s.last_findings_count = outcome.findings_count;
        s.last_redaction_targets = outcome.redaction_target_count;
        s.last_confidence = outcome.max_confidence;
        s.panic_latched = outcome.panic_latched;
        s.obs_locked = outcome.obs_locked;
    }
}

fn push_event(recent_events: &Arc<Mutex<Vec<String>>>, event: &str) {
    if let Ok(mut events) = recent_events.lock() {
        events.push(event.to_string());
        if events.len() > 20 {
            let _ = events.drain(0..events.len() - 20);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HotkeySpec, Keycode};

    #[test]
    fn parses_default_panic_hotkey() {
        let parsed = HotkeySpec::parse("Ctrl+Shift+Pause").expect("hotkey should parse");
        assert!(parsed.require_ctrl);
        assert!(parsed.require_shift);
        assert_eq!(parsed.primary, Keycode::Pause);
    }

    #[test]
    fn hotkey_matching_requires_modifiers() {
        let parsed = HotkeySpec::parse("Ctrl+Shift+K").expect("hotkey should parse");
        assert!(!parsed.is_pressed(&[Keycode::K]));
        assert!(!parsed.is_pressed(&[Keycode::LControl, Keycode::K]));
        assert!(parsed.is_pressed(&[Keycode::LControl, Keycode::LShift, Keycode::K]));
    }
}
