use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use core_types::AppConfig;
use keyring::Entry;

const KEYRING_SERVICE: &str = "StreamShield";
const KEYRING_OBS_ACCOUNT: &str = "obs_password";

pub fn default_config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("StreamShield").join("config.json")
}

pub fn load_or_create(path: &PathBuf) -> Result<AppConfig> {
    let mut config = if path.exists() {
        let data = fs::read_to_string(path)?;
        serde_json::from_str::<AppConfig>(&data)?
    } else {
        let config = AppConfig::default();
        save(path, &config)?;
        config
    };

    if let Some(secret) = load_obs_password()? {
        config.obs.password = Some(secret);
    }

    Ok(config)
}

pub fn save(path: &PathBuf, config: &AppConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut on_disk = config.clone();
    match &config.obs.password {
        Some(password) if !password.trim().is_empty() => {
            store_obs_password(password)?;
        }
        _ => {
            // Explicitly clear when password is None or empty to prevent stale secret resurrection.
            clear_obs_password()?;
        }
    }

    // Never persist OBS password in plain config.
    on_disk.obs.password = None;

    let json = serde_json::to_string_pretty(&on_disk)?;
    fs::write(path, json).context("failed writing config file")?;
    Ok(())
}

fn store_obs_password(secret: &str) -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_OBS_ACCOUNT)?;
    entry.set_password(secret)?;
    Ok(())
}

fn load_obs_password() -> Result<Option<String>> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_OBS_ACCOUNT)?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn clear_obs_password() -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_OBS_ACCOUNT)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(err.into()),
    }
}
