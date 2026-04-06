use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use core_types::{CapturedFrame, FrameSource};

pub struct WindowsPrimaryDisplaySource {
    width: u32,
    height: u32,
}

impl WindowsPrimaryDisplaySource {
    pub fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }
}

impl Default for WindowsPrimaryDisplaySource {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
        }
    }
}

impl FrameSource for WindowsPrimaryDisplaySource {
    fn capture_primary_display(&mut self) -> Result<CapturedFrame> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let rgba = vec![0_u8; (self.width * self.height * 4) as usize];
        Ok(CapturedFrame {
            width: self.width,
            height: self.height,
            timestamp_ms: ts,
            rgba,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_primary_display_frame_shape() {
        let mut source = WindowsPrimaryDisplaySource::new(1280, 720);
        let frame = source.capture_primary_display().expect("capture should succeed");
        assert_eq!(frame.width, 1280);
        assert_eq!(frame.height, 720);
        assert_eq!(frame.rgba.len(), 1280 * 720 * 4);
    }
}
