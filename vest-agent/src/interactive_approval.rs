//! TTY one-shot interactive approval for `RequireInteractive` decisions.
//!
//! Non-TTY stdin never prompts (fail closed). Prefer CLI effect pre-grants
//! (`--approve-writes` / `--approve-exploits` / `--approve-effect`) for
//! non-interactive sessions.

use crate::policy::NormalisedToolCall;
use std::io::{self, BufRead, IsTerminal, Write};

/// Prompt on a TTY for a one-shot allow. Returns false when stdin is not a TTY,
/// on I/O error, or when the operator does not answer yes.
pub fn prompt_tty_one_shot_allow(call: &NormalisedToolCall, reason: &str) -> bool {
    if !io::stdin().is_terminal() {
        return false;
    }
    let mut stderr = io::stderr().lock();
    prompt_allow_once(call, reason, &mut io::stdin().lock(), &mut stderr)
}

/// Testable prompt: write the question to `writer`, read a line from `reader`.
pub fn prompt_allow_once(
    call: &NormalisedToolCall,
    reason: &str,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> bool {
    let _ = writeln!(
        writer,
        "vest: approval required for tool '{}' (effect {}, target {})\n  {}\nAllow once? [y/N]: ",
        call.tool_id, call.effect, call.normalised_target, reason
    );
    let _ = writer.flush();
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vest_core::auth::{DataEgressClass, ToolEffect};

    fn sample_call() -> NormalisedToolCall {
        NormalisedToolCall::from_parts(
            "write_file",
            ToolEffect::LocalWrite,
            DataEgressClass::PotentiallySecretBearing,
            &serde_json::json!({"path": "/tmp/x", "content": "a"}),
        )
    }

    #[test]
    fn yes_allows() {
        let call = sample_call();
        let mut input = "yes\n".as_bytes();
        let mut out = Vec::new();
        assert!(prompt_allow_once(&call, "test", &mut input, &mut out));
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("approval required"));
    }

    #[test]
    fn no_and_empty_deny() {
        let call = sample_call();
        for reply in ["n\n", "\n", "no\n", "maybe\n"] {
            let mut input = reply.as_bytes();
            let mut out = Vec::new();
            assert!(!prompt_allow_once(&call, "test", &mut input, &mut out));
        }
    }
}
