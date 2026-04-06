use core_types::PanicBehavior;
use device_query::Keycode;

#[derive(Debug, Clone)]
pub struct HotkeySpec {
    pub require_ctrl: bool,
    pub require_shift: bool,
    pub require_alt: bool,
    pub primary: Keycode,
}

impl HotkeySpec {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut require_ctrl = false;
        let mut require_shift = false;
        let mut require_alt = false;
        let mut primary: Option<Keycode> = None;

        for part in raw.split('+').map(|p| p.trim().to_ascii_lowercase()) {
            if part.is_empty() {
                continue;
            }
            match part.as_str() {
                "ctrl" | "control" => require_ctrl = true,
                "shift" => require_shift = true,
                "alt" => require_alt = true,
                other => {
                    primary = parse_keycode(other);
                    if primary.is_none() {
                        return Err(format!("unknown hotkey token: {other}"));
                    }
                }
            }
        }

        let Some(primary) = primary else {
            return Err("hotkey must include a primary key (example: Ctrl+Shift+Pause)".to_string());
        };

        if !(require_ctrl || require_shift || require_alt) {
            return Err("hotkey must include at least one modifier key (Ctrl/Shift/Alt)".to_string());
        }

        Ok(Self {
            require_ctrl,
            require_shift,
            require_alt,
            primary,
        })
    }

    pub fn is_pressed(&self, keys: &[Keycode]) -> bool {
        if self.require_ctrl
            && !(keys.contains(&Keycode::LControl) || keys.contains(&Keycode::RControl))
        {
            return false;
        }
        if self.require_shift && !(keys.contains(&Keycode::LShift) || keys.contains(&Keycode::RShift)) {
            return false;
        }
        if self.require_alt && !(keys.contains(&Keycode::LAlt) || keys.contains(&Keycode::RAlt)) {
            return false;
        }
        keys.contains(&self.primary)
    }
}

pub fn panic_behavior_label(v: PanicBehavior) -> &'static str {
    match v {
        PanicBehavior::ShieldOnly => "shield-only",
        PanicBehavior::ObsOnly => "obs-only",
        PanicBehavior::ShieldAndObs => "shield-and-obs",
    }
}

fn parse_keycode(token: &str) -> Option<Keycode> {
    match token {
        "pause" => Some(Keycode::Pause),
        "f1" => Some(Keycode::F1),
        "f2" => Some(Keycode::F2),
        "f3" => Some(Keycode::F3),
        "f4" => Some(Keycode::F4),
        "f5" => Some(Keycode::F5),
        "f6" => Some(Keycode::F6),
        "f7" => Some(Keycode::F7),
        "f8" => Some(Keycode::F8),
        "f9" => Some(Keycode::F9),
        "f10" => Some(Keycode::F10),
        "f11" => Some(Keycode::F11),
        "f12" => Some(Keycode::F12),
        "0" => Some(Keycode::Key0),
        "1" => Some(Keycode::Key1),
        "2" => Some(Keycode::Key2),
        "3" => Some(Keycode::Key3),
        "4" => Some(Keycode::Key4),
        "5" => Some(Keycode::Key5),
        "6" => Some(Keycode::Key6),
        "7" => Some(Keycode::Key7),
        "8" => Some(Keycode::Key8),
        "9" => Some(Keycode::Key9),
        "a" => Some(Keycode::A),
        "b" => Some(Keycode::B),
        "c" => Some(Keycode::C),
        "d" => Some(Keycode::D),
        "e" => Some(Keycode::E),
        "f" => Some(Keycode::F),
        "g" => Some(Keycode::G),
        "h" => Some(Keycode::H),
        "i" => Some(Keycode::I),
        "j" => Some(Keycode::J),
        "k" => Some(Keycode::K),
        "l" => Some(Keycode::L),
        "m" => Some(Keycode::M),
        "n" => Some(Keycode::N),
        "o" => Some(Keycode::O),
        "p" => Some(Keycode::P),
        "q" => Some(Keycode::Q),
        "r" => Some(Keycode::R),
        "s" => Some(Keycode::S),
        "t" => Some(Keycode::T),
        "u" => Some(Keycode::U),
        "v" => Some(Keycode::V),
        "w" => Some(Keycode::W),
        "x" => Some(Keycode::X),
        "y" => Some(Keycode::Y),
        "z" => Some(Keycode::Z),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{HotkeySpec, Keycode};

    #[test]
    fn parse_valid_hotkey() {
        let spec = HotkeySpec::parse("Ctrl+Shift+Pause").expect("hotkey should parse");
        assert!(spec.require_ctrl);
        assert!(spec.require_shift);
        assert_eq!(spec.primary, Keycode::Pause);
    }

    #[test]
    fn reject_hotkey_without_modifier() {
        let err = HotkeySpec::parse("Pause").expect_err("must fail");
        assert!(err.contains("modifier"));
    }

    #[test]
    fn reject_unknown_token() {
        let err = HotkeySpec::parse("Ctrl+Hyper+K").expect_err("must fail");
        assert!(err.contains("unknown hotkey token"));
    }
}
