#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod protection;

use std::{path::PathBuf, sync::{Arc, Mutex}};

use core_obs::{LocalObsController, StubTransport};
use core_types::{AppConfig, ObsController, PanicBehavior, ProtectionMode, RedactionStyle};
use protection::{ProtectionService, ProtectionStatusSnapshot};
use serde::Serialize;
use tauri::State;

struct AppState {
    config_path: PathBuf,
    config: Arc<Mutex<AppConfig>>,
    panic_active: Arc<Mutex<bool>>,
    recent_events: Arc<Mutex<Vec<String>>>,
    protection: Mutex<ProtectionService>,
}

#[derive(Debug, Serialize)]
struct DashboardSnapshot {
    protection_enabled: bool,
    mode: String,
    scan_interval_ms: u64,
    ocr_backend_status: String,
    obs_status: String,
    panic_active: bool,
    recent_events: Vec<String>,
    protection_runtime: ProtectionStatusSnapshot,
}

#[tauri::command]
fn get_dashboard_snapshot(state: State<'_, AppState>) -> Result<DashboardSnapshot, String> {
    let cfg = state
        .config
        .lock()
        .map_err(|_| "config lock failed")?
        .clone();
    let panic_active = *state
        .panic_active
        .lock()
        .map_err(|_| "panic lock failed")?;
    let events = state
        .recent_events
        .lock()
        .map_err(|_| "event lock failed")?
        .clone();
    let runtime = state
        .protection
        .lock()
        .map_err(|_| "protection lock failed")?
        .snapshot();

    Ok(DashboardSnapshot {
        protection_enabled: cfg.protection_enabled,
        mode: format!("{:?}", cfg.mode),
        scan_interval_ms: cfg.scan_interval_ms,
        ocr_backend_status: if runtime.ocr_ready {
            "Local OCR backend available".to_string()
        } else {
            "Local OCR backend unavailable".to_string()
        },
        obs_status: if cfg.obs.enabled {
            "Configured".to_string()
        } else {
            "Disabled".to_string()
        },
        panic_active,
        recent_events: events,
        protection_runtime: runtime,
    })
}

#[tauri::command]
fn start_protection_loop(state: State<'_, AppState>) -> Result<String, String> {
    let mut protection = state
        .protection
        .lock()
        .map_err(|_| "protection lock failed")?;
    protection.start(
        Arc::clone(&state.config),
        Arc::clone(&state.panic_active),
        Arc::clone(&state.recent_events),
    )?;
    append_event(&state, "Protection loop started");
    Ok("Protection loop started".to_string())
}

#[tauri::command]
fn stop_protection_loop(state: State<'_, AppState>) -> Result<String, String> {
    let mut protection = state
        .protection
        .lock()
        .map_err(|_| "protection lock failed")?;
    protection.stop()?;
    append_event(&state, "Protection loop stopped");
    Ok("Protection loop stopped".to_string())
}

#[tauri::command]
fn set_protection_enabled(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let mut cfg = state.config.lock().map_err(|_| "config lock failed")?;
    cfg.protection_enabled = enabled;
    config::save(&state.config_path, &cfg).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_mode(state: State<'_, AppState>, mode: String) -> Result<(), String> {
    let mut cfg = state.config.lock().map_err(|_| "config lock failed")?;
    cfg.mode = match mode.as_str() {
        "Balanced" => ProtectionMode::Balanced,
        "Strict" => ProtectionMode::Strict,
        "Paranoid" => ProtectionMode::Paranoid,
        _ => return Err("invalid mode".to_string()),
    };
    config::save(&state.config_path, &cfg).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_scan_interval(state: State<'_, AppState>, interval_ms: u64) -> Result<(), String> {
    let mut cfg = state.config.lock().map_err(|_| "config lock failed")?;
    cfg.scan_interval_ms = interval_ms.clamp(150, 5000);
    config::save(&state.config_path, &cfg).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_redaction_style(state: State<'_, AppState>, style: String) -> Result<(), String> {
    let mut cfg = state.config.lock().map_err(|_| "config lock failed")?;
    cfg.redaction_style = match style.as_str() {
        "Blur" => RedactionStyle::Blur,
        "BlackBox" => RedactionStyle::BlackBox,
        "Pixelate" => RedactionStyle::Pixelate,
        _ => return Err("invalid redaction style".to_string()),
    };
    config::save(&state.config_path, &cfg).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_panic_behavior(state: State<'_, AppState>, behavior: String) -> Result<(), String> {
    let mut cfg = state.config.lock().map_err(|_| "config lock failed")?;
    cfg.panic_behavior = match behavior.as_str() {
        "ShieldOnly" => PanicBehavior::ShieldOnly,
        "ObsOnly" => PanicBehavior::ObsOnly,
        "ShieldAndObs" => PanicBehavior::ShieldAndObs,
        _ => return Err("invalid panic behavior".to_string()),
    };
    config::save(&state.config_path, &cfg).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_obs_settings(
    state: State<'_, AppState>,
    enabled: bool,
    host: String,
    port: u16,
    password: Option<String>,
    safe_scene: String,
    lock_safe_scene_until_clear: bool,
) -> Result<(), String> {
    let mut cfg = state.config.lock().map_err(|_| "config lock failed")?;
    cfg.obs.enabled = enabled;
    cfg.obs.host = host;
    cfg.obs.port = port;
    cfg.obs.password = password;
    cfg.obs.safe_scene = safe_scene;
    cfg.obs.lock_safe_scene_until_clear = lock_safe_scene_until_clear;
    config::save(&state.config_path, &cfg).map_err(|e| e.to_string())
}

#[tauri::command]
fn test_obs_connection(state: State<'_, AppState>) -> Result<String, String> {
    let cfg = state.config.lock().map_err(|_| "config lock failed")?.clone();
    let mut obs = LocalObsController::new(StubTransport);
    obs.test_connection(&cfg.obs)
        .map_err(|e| format!("OBS connection test failed: {e}"))?;
    append_event(&state, "OBS connection test succeeded");
    Ok("OBS connection successful".to_string())
}

#[tauri::command]
fn trigger_panic(state: State<'_, AppState>) -> Result<(), String> {
    *state
        .panic_active
        .lock()
        .map_err(|_| "panic lock failed")? = true;
    append_event(&state, "Panic shield triggered manually");
    Ok(())
}

#[tauri::command]
fn clear_panic(state: State<'_, AppState>) -> Result<(), String> {
    *state
        .panic_active
        .lock()
        .map_err(|_| "panic lock failed")? = false;

    if let Ok(service) = state.protection.lock() {
        service.request_clear_latch();
    }

    append_event(&state, "Panic shield clear requested");
    Ok(())
}

fn append_event(state: &AppState, event: &str) {
    if let Ok(mut events) = state.recent_events.lock() {
        events.push(event.to_string());
        if events.len() > 20 {
            let _ = events.drain(0..events.len() - 20);
        }
    }
}

fn main() {
    let config_path = config::default_config_path();
    let config = config::load_or_create(&config_path).unwrap_or_default();

    let app_state = AppState {
        config_path,
        config: Arc::new(Mutex::new(config.clone())),
        panic_active: Arc::new(Mutex::new(false)),
        recent_events: Arc::new(Mutex::new(vec!["Protection service initialized".to_string()])),
        protection: Mutex::new(ProtectionService::default()),
    };

    if config.protection_enabled {
        if let Ok(mut service) = app_state.protection.lock() {
            let _ = service.start(
                Arc::clone(&app_state.config),
                Arc::clone(&app_state.panic_active),
                Arc::clone(&app_state.recent_events),
            );
        }
    }

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_dashboard_snapshot,
            start_protection_loop,
            stop_protection_loop,
            set_protection_enabled,
            update_mode,
            update_scan_interval,
            update_redaction_style,
            update_panic_behavior,
            update_obs_settings,
            test_obs_connection,
            trigger_panic,
            clear_panic,
        ])
        .run(tauri::generate_context!())
        .expect("error while running StreamShield desktop shell");
}
