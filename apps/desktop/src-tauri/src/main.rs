#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;

use std::{path::PathBuf, sync::Mutex};

use core_obs::{LocalObsController, StubTransport};
use core_types::{AppConfig, ObsController, PanicBehavior, ProtectionMode, RedactionStyle};
use serde::Serialize;
use tauri::State;

struct AppState {
    config_path: PathBuf,
    config: Mutex<AppConfig>,
    obs: Mutex<LocalObsController<StubTransport>>,
    panic_active: Mutex<bool>,
    recent_events: Mutex<Vec<String>>,
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
}

#[tauri::command]
fn get_dashboard_snapshot(state: State<'_, AppState>) -> Result<DashboardSnapshot, String> {
    let cfg = state.config.lock().map_err(|_| "config lock failed")?.clone();
    let panic_active = *state.panic_active.lock().map_err(|_| "panic lock failed")?;
    let events = state
        .recent_events
        .lock()
        .map_err(|_| "event lock failed")?
        .clone();

    Ok(DashboardSnapshot {
        protection_enabled: cfg.protection_enabled,
        mode: format!("{:?}", cfg.mode),
        scan_interval_ms: cfg.scan_interval_ms,
        ocr_backend_status: "Local OCR backend available".to_string(),
        obs_status: if cfg.obs.enabled {
            "Configured".to_string()
        } else {
            "Disabled".to_string()
        },
        panic_active,
        recent_events: events,
    })
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
    let mut obs = state.obs.lock().map_err(|_| "obs lock failed")?;
    obs.test_connection(&cfg.obs)
        .map_err(|e| format!("OBS connection test failed: {e}"))?;
    append_event(&state, "OBS connection test succeeded");
    Ok("OBS connection successful".to_string())
}

#[tauri::command]
fn trigger_panic(state: State<'_, AppState>) -> Result<(), String> {
    *state.panic_active.lock().map_err(|_| "panic lock failed")? = true;
    append_event(&state, "Panic shield triggered");
    Ok(())
}

#[tauri::command]
fn clear_panic(state: State<'_, AppState>) -> Result<(), String> {
    *state.panic_active.lock().map_err(|_| "panic lock failed")? = false;
    append_event(&state, "Panic shield cleared");
    Ok(())
}

fn append_event(state: &AppState, event: &str) {
    if let Ok(mut events) = state.recent_events.lock() {
        events.push(event.to_string());
        if events.len() > 10 {
            let _ = events.drain(0..events.len() - 10);
        }
    }
}

fn main() {
    let config_path = config::default_config_path();
    let config = config::load_or_create(&config_path).unwrap_or_default();

    tauri::Builder::default()
        .manage(AppState {
            config_path,
            config: Mutex::new(config),
            obs: Mutex::new(LocalObsController::new(StubTransport)),
            panic_active: Mutex::new(false),
            recent_events: Mutex::new(vec!["Protection service initialized".to_string()]),
        })
        .invoke_handler(tauri::generate_handler![
            get_dashboard_snapshot,
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
