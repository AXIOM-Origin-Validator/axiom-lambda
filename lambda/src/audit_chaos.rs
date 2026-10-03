//! Dev-only §23.14 audit chaos — `docs/AXIOM_DESIGN_AuditChaos.md`, YP §23.14 AS BUILT item 10a.
//!
//! Compiled ONLY with the `audit-chaos` cargo feature (the dev build passes it; no production
//! recipe may — preflight refuses one). Makes THIS validator answer authenticated peer-audit
//! requests dishonestly so a soak can prove the auditors catch it:
//!   `lie`    signed raw fields with `amount + 1`     → auditor bans `HashMismatch`
//!   `silent` no answer at all                       → auditor bans `NonResponds` after the deadline
//!   `forget` signed `NotHeld` although we hold it   → auditor bans `NotHeldByCoWitness` (or clears)
//!
//! The switch is a plain file, `<config dir>/audit-chaos`: one line, `off` | `lie` | `silent` |
//! `forget`, optionally `every=N` (inject on every Nth authenticated request, default 1). Missing
//! file = off. Re-read on every request so a harness can flip it without a restart (a restart would
//! clear the very bans under test).
#![cfg(feature = "audit-chaos")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Lie,
    Silent,
    Forget,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Lie => "lie",
            Mode::Silent => "silent",
            Mode::Forget => "forget",
        }
    }
}

static SWITCH: OnceLock<PathBuf> = OnceLock::new();
static SEEN: AtomicU64 = AtomicU64::new(0);
static LIE: AtomicU64 = AtomicU64::new(0);
static SILENT: AtomicU64 = AtomicU64::new(0);
static FORGET: AtomicU64 = AtomicU64::new(0);

/// Set once at startup: the switch file beside this Lambda's config.
pub fn set_switch_path(path: PathBuf) {
    let _ = SWITCH.set(path);
}

/// `lie every=3` → `Some((Lie, 3))`; `off`, blank, unknown → `None`.
pub fn parse(text: &str) -> Option<(Mode, u64)> {
    let line = text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).find(|l| !l.is_empty())?;
    let mut words = line.split_whitespace();
    let mode = match words.next()? {
        "lie" => Mode::Lie,
        "silent" => Mode::Silent,
        "forget" => Mode::Forget,
        _ => return None,
    };
    let every = words
        .find_map(|w| w.strip_prefix("every="))
        .and_then(|n| n.parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1);
    Some((mode, every))
}

/// Called once per AUTHENTICATED peer-audit request: the fault to inject, if any. Counts it.
pub fn decide() -> Option<Mode> {
    let text = std::fs::read_to_string(SWITCH.get()?).ok()?;
    decide_from(&text)
}

fn decide_from(text: &str) -> Option<Mode> {
    let (mode, every) = parse(text)?;
    let n = SEEN.fetch_add(1, Ordering::Relaxed) + 1;
    if n % every != 0 {
        return None;
    }
    match mode {
        Mode::Lie => &LIE,
        Mode::Silent => &SILENT,
        Mode::Forget => &FORGET,
    }
    .fetch_add(1, Ordering::Relaxed);
    Some(mode)
}

/// `/audit` field: the switch's current mode and the injected counts.
pub fn json() -> String {
    let mode = SWITCH
        .get()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| parse(&t))
        .map(|(m, _)| m.as_str())
        .unwrap_or("off");
    format!(
        r#"{{"mode":"{}","lie":{},"silent":{},"forget":{}}}"#,
        mode,
        LIE.load(Ordering::Relaxed),
        SILENT.load(Ordering::Relaxed),
        FORGET.load(Ordering::Relaxed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modes_and_every() {
        assert_eq!(parse("lie\n"), Some((Mode::Lie, 1)));
        assert_eq!(parse("  silent every=3 # comment"), Some((Mode::Silent, 3)));
        assert_eq!(parse("# header\nforget every=0"), Some((Mode::Forget, 1)), "every=0 means every request");
        assert_eq!(parse("off"), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("explode"), None);
    }

    #[test]
    fn every_n_injects_on_the_nth_request_and_counts_it() {
        let before = LIE.load(Ordering::Relaxed);
        SEEN.store(0, Ordering::Relaxed);
        let got: Vec<_> = (0..6).map(|_| decide_from("lie every=3")).collect();
        assert_eq!(got.iter().filter(|m| m.is_some()).count(), 2);
        assert_eq!(got[2], Some(Mode::Lie));
        assert_eq!(LIE.load(Ordering::Relaxed) - before, 2);
        assert_eq!(decide_from("off"), None);
    }
}
