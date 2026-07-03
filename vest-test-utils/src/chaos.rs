use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static CHAOS_MODE: AtomicBool = AtomicBool::new(false);

pub fn enable_chaos() {
    CHAOS_MODE.store(true, Ordering::Relaxed);
}
pub fn disable_chaos() {
    CHAOS_MODE.store(false, Ordering::Relaxed);
}
pub fn is_chaos() -> bool {
    CHAOS_MODE.load(Ordering::Relaxed)
}

pub async fn maybe_delay() {
    if is_chaos() {
        let ms = rand::random::<u64>() % 50;
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

pub fn maybe_panic(probability: f64) {
    if is_chaos() && rand::random::<f64>() < probability {
        panic!("Chaos monkey says hello!");
    }
}

pub fn malformed_tomls() -> Vec<String> {
    vec![
        String::new(),
        "{".into(),
        "[invalid".into(),
        "\x00\x00\x00\x00".into(),
        "key = ".into(),
        "=".into(),
        "[section\nkey = value".into(),
        "[section]\nkey = \n".into(),
        "\n\n\n\n\n".into(),
    ]
}

pub fn malformed_jsons() -> Vec<String> {
    vec![
        String::new(),
        "{".into(),
        "[}".into(),
        r#"{"key": undefined}"#.into(),
        r#"{"key": NaN}"#.into(),
        r#"{"key": Infinity}"#.into(),
        r#"{"key": }"#.into(),
        r#"{"key": ,}"#.into(),
        "[,]".into(),
        r#"{"\x00": "value"}"#.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chaos_default_disabled() {
        assert!(!is_chaos());
    }

    #[test]
    fn test_chaos_toggle() {
        enable_chaos();
        assert!(is_chaos());
        disable_chaos();
        assert!(!is_chaos());
    }

    #[test]
    fn test_malformed_tomls_not_empty() {
        assert!(!malformed_tomls().is_empty());
    }

    #[test]
    fn test_malformed_jsons_not_empty() {
        assert!(!malformed_jsons().is_empty());
    }
}
