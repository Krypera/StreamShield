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
use core_types::{AppConfig, ConfidenceLevel};
use device_query::{DeviceQuery, DeviceState};
use serde::Serialize;

use crate::hotkey::{panic_behavior_label, HotkeySpec};

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

#[derive(Default)]
struct EventThrottle {
    last_event: Option<String>,
    last_event_ts_ms: u64,
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
                let mut throttle = EventThrottle::default();

                while !stop_clone.load(Ordering::Relaxed) {
                    if clear_clone.swap(false, Ordering::Relaxed) {
                        if runtime.clear_alert_latch().is_ok() {
                            if let Ok(mut panic_state) = panic_active.lock() {
                                *panic_state = false;
                            }
                            push_event_throttled(
                                &recent_events,
                                &mut throttle,
                                "Panic latch cleared",
                                500,
                            );
                        }
                    }

                    let cfg = config.lock().map(|g| g.clone()).unwrap_or_default();

                    if manual_panic_clone.swap(false, Ordering::Relaxed) {
                        match runtime.trigger_manual_panic(&cfg) {
                            Ok(()) => {
                                if let Ok(mut panic_state) = panic_active.lock() {
                                    *panic_state = true;
                                }
                                push_event_throttled(
                                    &recent_events,
                                    &mut throttle,
                                    &format!(
                                        "Manual panic requested ({})",
                                        panic_behavior_label(cfg.panic_behavior)
                                    ),
                                    500,
                                );
                            }
                            Err(err) => {
                                if let Ok(mut s) = status.lock() {
                                    s.last_error = Some(format!("manual panic failed: {err}"));
                                }
                            }
                        }
                    }

                    if let Ok(hotkey) = HotkeySpec::parse(&cfg.panic_hotkey) {
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
                                    push_event_throttled(
                                        &recent_events,
                                        &mut throttle,
                                        &format!(
                                            "Manual panic hotkey triggered ({})",
                                            panic_behavior_label(cfg.panic_behavior)
                                        ),
                                        500,
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
                                push_event_throttled(
                                    &recent_events,
                                    &mut throttle,
                                    &format!(
                                        "Risk finding(s): count={}, confidence={:?}",
                                        outcome.findings_count, outcome.max_confidence
                                    ),
                                    1200,
                                );
                            }
                            if outcome.redaction_target_count > 0 {
                                push_event_throttled(
                                    &recent_events,
                                    &mut throttle,
                                    &format!(
                                        "Region redaction active for {} target(s)",
                                        outcome.redaction_target_count
                                    ),
                                    1200,
                                );
                            }
                            if outcome.panic_latched {
                                if let Ok(mut panic_state) = panic_active.lock() {
                                    *panic_state = true;
                                }
                                push_event_throttled(
                                    &recent_events,
                                    &mut throttle,
                                    "Panic shield latched due to critical risk",
                                    1200,
                                );
                            }
                            if outcome.obs_locked {
                                push_event_throttled(
                                    &recent_events,
                                    &mut throttle,
                                    "OBS safe scene lock is active",
                                    1500,
                                );
                            }
                        }
                        Err(err) => {
                            if let Ok(mut s) = status.lock() {
                                s.last_error = Some(format!("Protection scan error: {err}"));
                                s.last_scan_timestamp_ms = Some(now_ms);
                            }
                            push_event_throttled(
                                &recent_events,
                                &mut throttle,
                                "Protection loop encountered a scan error",
                                1500,
                            );
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

fn push_event_throttled(
    recent_events: &Arc<Mutex<Vec<String>>>,
    throttle: &mut EventThrottle,
    event: &str,
    min_interval_ms: u64,
) {
    let now = current_epoch_ms();
    let same_as_last = throttle.last_event.as_deref() == Some(event);
    if same_as_last && now.saturating_sub(throttle.last_event_ts_ms) < min_interval_ms {
        return;
    }

    throttle.last_event = Some(event.to_string());
    throttle.last_event_ts_ms = now;
    push_event(recent_events, event);
}
