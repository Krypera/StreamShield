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

pub struct LocalObsController<T: ObsTransport> {
    transport: T,
    max_retries: u8,
}

impl<T: ObsTransport> LocalObsController<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            max_retries: 2,
        }
    }
}

impl<T: ObsTransport> ObsController for LocalObsController<T> {
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
