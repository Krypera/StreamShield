use anyhow::anyhow;
use core_types::{ObsConfig, ObsController};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObsError {
    #[error("OBS unavailable")]
    Unavailable,
    #[error("OBS authentication failed")]
    AuthFailed,
    #[error("OBS operation failed: {0}")]
    Other(String),
}

pub trait ObsTransport: Send {
    fn connect(&mut self, config: &ObsConfig) -> Result<(), ObsError>;
    fn switch_scene(&mut self, scene_name: &str) -> Result<(), ObsError>;
}

#[derive(Debug, Default)]
pub struct StubTransport;

impl ObsTransport for StubTransport {
    fn connect(&mut self, _config: &ObsConfig) -> Result<(), ObsError> {
        Ok(())
    }

    fn switch_scene(&mut self, _scene_name: &str) -> Result<(), ObsError> {
        Ok(())
    }
}

pub struct WebSocketObsTransport {
    runtime: tokio::runtime::Runtime,
    connected: Option<ObsConfig>,
}

impl WebSocketObsTransport {
    pub fn new() -> Result<Self, ObsError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| ObsError::Other(format!("tokio runtime build failed: {e}")))?;
        Ok(Self {
            runtime,
            connected: None,
        })
    }

    fn connect_client(&self, config: &ObsConfig) -> Result<obws::Client, ObsError> {
        self.runtime
            .block_on(async {
                obws::Client::connect(&config.host, config.port, config.password.as_deref()).await
            })
            .map_err(|e| map_obs_error(&e.to_string()))
    }
}

impl ObsTransport for WebSocketObsTransport {
    fn connect(&mut self, config: &ObsConfig) -> Result<(), ObsError> {
        let _ = self.connect_client(config)?;
        self.connected = Some(config.clone());
        Ok(())
    }

    fn switch_scene(&mut self, scene_name: &str) -> Result<(), ObsError> {
        let Some(config) = self.connected.clone() else {
            return Err(ObsError::Other(
                "not connected; call connect() before switch_scene()".to_string(),
            ));
        };

        let client = self.connect_client(&config)?;
        self.runtime
            .block_on(async { client.scenes().set_current_program_scene(scene_name).await })
            .map_err(|e| map_obs_error(&e.to_string()))
    }
}

fn map_obs_error(msg: &str) -> ObsError {
    let lower = msg.to_lowercase();
    if lower.contains("auth") || lower.contains("password") {
        ObsError::AuthFailed
    } else if lower.contains("connect") || lower.contains("refused") || lower.contains("timeout") {
        ObsError::Unavailable
    } else {
        ObsError::Other(msg.to_string())
    }
}

pub struct LocalObsController {
    transport: Box<dyn ObsTransport>,
    max_retries: u8,
}

impl LocalObsController {
    pub fn new<T: ObsTransport + 'static>(transport: T) -> Self {
        Self {
            transport: Box::new(transport),
            max_retries: 2,
        }
    }
}

impl ObsController for LocalObsController {
    fn test_connection(&mut self, config: &ObsConfig) -> anyhow::Result<()> {
        self.transport
            .connect(config)
            .map_err(|e| anyhow!("obs_test_connection_failed: {e}"))
    }

    fn switch_to_safe_scene(&mut self, config: &ObsConfig) -> anyhow::Result<()> {
        self.transport
            .connect(config)
            .map_err(|e| anyhow!("obs_connect_failed: {e}"))?;

        let mut last_err: Option<ObsError> = None;
        for _ in 0..=self.max_retries {
            match self.transport.switch_scene(&config.safe_scene) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
        }

        Err(anyhow!(
            "obs_scene_switch_failed: {}",
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown error".to_string())
        ))
    }
}

#[cfg(test)]
mod tests {
    use core_types::{ObsConfig, ObsController};

    use super::{LocalObsController, ObsError, ObsTransport};

    #[derive(Default)]
    struct MockTransport {
        connect_calls: usize,
        switch_calls: usize,
        fail_connect: bool,
        fail_switch_attempts: usize,
    }

    impl ObsTransport for MockTransport {
        fn connect(&mut self, _config: &ObsConfig) -> Result<(), ObsError> {
            self.connect_calls += 1;
            if self.fail_connect {
                Err(ObsError::AuthFailed)
            } else {
                Ok(())
            }
        }

        fn switch_scene(&mut self, _scene_name: &str) -> Result<(), ObsError> {
            self.switch_calls += 1;
            if self.switch_calls <= self.fail_switch_attempts {
                Err(ObsError::Unavailable)
            } else {
                Ok(())
            }
        }
    }

    fn obs_config() -> ObsConfig {
        ObsConfig {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 4455,
            password: Some("fake-password".to_string()),
            safe_scene: "SAFE".to_string(),
            lock_safe_scene_until_clear: true,
        }
    }

    #[test]
    fn mock_connection_success() {
        let transport = MockTransport::default();
        let mut obs = LocalObsController::new(transport);
        assert!(obs.test_connection(&obs_config()).is_ok());
    }

    #[test]
    fn scene_switch_invoked() {
        let transport = MockTransport::default();
        let mut obs = LocalObsController::new(transport);
        assert!(obs.switch_to_safe_scene(&obs_config()).is_ok());
    }

    #[test]
    fn retry_behavior_until_success() {
        let transport = MockTransport {
            fail_switch_attempts: 2,
            ..Default::default()
        };
        let mut obs = LocalObsController::new(transport);
        assert!(obs.switch_to_safe_scene(&obs_config()).is_ok());
    }

    #[test]
    fn returns_error_when_auth_fails() {
        let transport = MockTransport {
            fail_connect: true,
            ..Default::default()
        };
        let mut obs = LocalObsController::new(transport);
        assert!(obs.switch_to_safe_scene(&obs_config()).is_err());
    }
}
