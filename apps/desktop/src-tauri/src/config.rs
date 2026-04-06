use std::{fs, path::PathBuf};

use anyhow::Result;
use core_types::AppConfig;

pub fn default_config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("StreamShield").join("config.json")
}

pub fn load_or_create(path: &PathBuf) -> Result<AppConfig> {
    if path.exists() {
        let data = fs::read_to_string(path)?;
        let config: AppConfig = serde_json::from_str(&data)?;
        Ok(config)
    } else {
        let config = AppConfig::default();
        save(path, &config)?;
        Ok(config)
    }
}

pub fn save(path: &PathBuf, config: &AppConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(config)?;
    fs::write(path, json)?;
    Ok(())
}
