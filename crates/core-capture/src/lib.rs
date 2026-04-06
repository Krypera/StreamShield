use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use core_types::{CapturedFrame, FrameSource};
use screenshots::Screen;

pub struct WindowsPrimaryDisplaySource;

impl WindowsPrimaryDisplaySource {
    pub fn new() -> Self {
        Self
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
}

impl Default for WindowsPrimaryDisplaySource {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameSource for WindowsPrimaryDisplaySource {
    fn capture_primary_display(&mut self) -> Result<CapturedFrame> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let screen = Self::pick_primary_screen()?;
        let image = screen.capture().context("failed to capture primary display")?;

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
