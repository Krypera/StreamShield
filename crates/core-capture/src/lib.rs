use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use core_types::{CapturedFrame, FrameSource};
use screenshots::Screen;

pub struct WindowsPrimaryDisplaySource {
    cached_primary: Option<Screen>,
    last_refresh: Option<Instant>,
}

impl WindowsPrimaryDisplaySource {
    pub fn new() -> Self {
        Self {
            cached_primary: None,
            last_refresh: None,
        }
    }

    fn pick_primary_screen() -> Result<Screen> {
        let screens = Screen::all().context("failed to enumerate screens")?;
        if screens.is_empty() {
            return Err(anyhow!("no display detected for capture"));
        }

        let primary = screens
            .iter()
            .find(|s| s.display_info.is_primary)
            .copied()
            .unwrap_or(screens[0]);

        Ok(primary)
    }

    fn refresh_if_needed(&mut self, force: bool) -> Result<()> {
        let stale = self
            .last_refresh
            .map(|at| at.elapsed() > Duration::from_secs(2))
            .unwrap_or(true);

        if force || self.cached_primary.is_none() || stale {
            self.cached_primary = Some(Self::pick_primary_screen()?);
            self.last_refresh = Some(Instant::now());
        }

        Ok(())
    }
}

impl Default for WindowsPrimaryDisplaySource {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameSource for WindowsPrimaryDisplaySource {
    fn capture_primary_display(&mut self) -> Result<CapturedFrame> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;

        self.refresh_if_needed(false)?;
        let screen = self
            .cached_primary
            .ok_or_else(|| anyhow!("primary display is not available"))?;

        let image = match screen.capture() {
            Ok(img) => img,
            Err(_) => {
                self.refresh_if_needed(true)?;
                let refreshed = self
                    .cached_primary
                    .ok_or_else(|| anyhow!("primary display is not available after refresh"))?;
                refreshed
                    .capture()
                    .context("failed to capture primary display after refresh")?
            }
        };

        Ok(CapturedFrame {
            width: image.width(),
            height: image.height(),
            timestamp_ms: ts,
            rgba: image.into_raw(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_initializes() {
        let _ = WindowsPrimaryDisplaySource::new();
    }
}
