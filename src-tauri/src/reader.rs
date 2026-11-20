//! PC/SC reader access (macOS PCSC.framework, Windows WinSCard, Linux pcsc-lite).

use crate::cfs::Apdu;
use pcsc::{Card, Context, Disposition, Protocols, ReaderState, Scope, ShareMode, State};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub enum Event {
    Present { reader: String, uid: String },
    Removed,
    Status(String),
}

pub fn list() -> Vec<String> {
    Context::establish(Scope::User)
        .and_then(|ctx| ctx.list_readers_owned())
        .map(|r| r.into_iter().map(|n| n.to_string_lossy().into_owned()).collect())
        .unwrap_or_default()
}

/// Reader name for people: "ACS ACR122U PICC Interface 00 00" -> "ACS ACR122U".
pub fn display_name(name: &str) -> String {
    let mut words: Vec<&str> = name.split_whitespace().collect();
    // pcsc-lite appends slot numbers as separate words ("… 00 00"); model numbers stay
    while words.last().is_some_and(|w| w.chars().all(|c| c.is_ascii_digit())) {
        words.pop();
    }
    words.join(" ").trim_end_matches("PICC Interface").trim_end_matches("Interface").trim().to_string()
}

/// "04 a2 b3 c4 90 00" -> "04A2B3C4" (strip status word, uppercase hex).
pub fn uid_hex(resp: &[u8]) -> Option<String> {
    (resp.len() > 2 && resp.ends_with(&[0x90, 0x00]))
        .then(|| resp[..resp.len() - 2].iter().map(|b| format!("{b:02X}")).collect())
}

fn get_uid(card: &Card) -> Result<String, String> {
    let mut buf = [0u8; 64];
    let r = card.transmit(&[0xFF, 0xCA, 0x00, 0x00, 0x00], &mut buf).map_err(|e| e.to_string())?;
    uid_hex(r).ok_or_else(|| "Tag nicht lesbar".into())
}

fn connect(ctx: &Context, reader: &str) -> Result<Card, String> {
    let name = CString::new(reader).map_err(|e| e.to_string())?;
    ctx.connect(&name, ShareMode::Shared, Protocols::ANY).map_err(|e| format!("Keine Verbindung zum Tag: {e}"))
}

/// Run card I/O on the tag `uid` lying on `reader`. `busy` pauses the poller meanwhile,
/// so the reselects a failed MIFARE auth needs don't count as a new tap.
pub fn with_card<T>(reader: &str, uid: &str, busy: &AtomicBool, f: impl FnOnce(&dyn Fn(&[u8]) -> Result<Vec<u8>, String>) -> Result<T, String>) -> Result<T, String> {
    busy.store(true, Ordering::SeqCst);
    let result = (|| {
        let ctx = Context::establish(Scope::User).map_err(|e| e.to_string())?;
        let card = connect(&ctx, reader).map_err(|_| format!("Tag {uid} auf den Reader legen."))?;
        if get_uid(&card)? != uid {
            return Err(format!("Anderer Tag aufgelegt – bitte Tag {uid} auflegen."));
        }
        let out = {
            let tx = |apdu: &[u8]| {
                let mut buf = [0u8; 300];
                card.transmit(apdu, &mut buf).map(|r| r.to_vec()).map_err(|e| e.to_string())
            };
            f(&tx)
        };
        let _ = card.disconnect(Disposition::LeaveCard);
        out
    })();
    busy.store(false, Ordering::SeqCst);
    result
}

/// Adapter so cfs::{read,write,wipe} can run on the closure `with_card` hands out.
pub struct Tx<'a>(pub &'a dyn Fn(&[u8]) -> Result<Vec<u8>, String>);
impl Apdu for Tx<'_> {
    fn tx(&self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        (self.0)(apdu)
    }
}

/// Poll the chosen reader (or the first one) and report tag taps/removals.
/// ponytail: 300 ms poll of the reader state; survives replugging without PnP bookkeeping.
pub fn spawn(wanted: Arc<Mutex<Option<String>>>, busy: Arc<AtomicBool>, emit: impl Fn(Event) + Send + 'static) {
    thread::spawn(move || {
        let mut present = false;
        let mut last = String::new();
        let status = |last: &mut String, s: String, emit: &dyn Fn(Event)| {
            if *last != s {
                *last = s.clone();
                emit(Event::Status(s));
            }
        };
        loop {
            thread::sleep(Duration::from_millis(300));
            if busy.load(Ordering::SeqCst) {
                continue;
            }
            let Ok(ctx) = Context::establish(Scope::User) else {
                status(&mut last, "PC/SC-Dienst nicht verfügbar".into(), &emit);
                continue;
            };
            let readers = ctx.list_readers_owned().unwrap_or_default();
            let want = wanted.lock().unwrap().clone();
            let chosen = match &want {
                Some(w) => readers.iter().find(|r| r.to_string_lossy() == *w),
                None => readers.first(),
            };
            let Some(reader) = chosen.cloned() else {
                if present {
                    present = false;
                    emit(Event::Removed);
                }
                status(&mut last, want.map(|w| format!("Reader „{w}“ nicht verbunden")).unwrap_or("Kein NFC-Reader gefunden".into()), &emit);
                continue;
            };
            let name = reader.to_string_lossy().into_owned();
            let mut rs = [ReaderState::new(reader, State::UNAWARE)];
            if ctx.get_status_change(Duration::from_millis(0), &mut rs).is_err() {
                continue;
            }
            let now = rs[0].event_state().contains(State::PRESENT);
            if now && !present {
                match connect(&ctx, &name).and_then(|c| get_uid(&c)) {
                    Ok(uid) => emit(Event::Present { reader: name.clone(), uid }),
                    Err(e) => status(&mut last, format!("Tag nicht lesbar: {e}"), &emit),
                }
            }
            if !now && present {
                emit(Event::Removed);
                last.clear();
            }
            if !now {
                status(&mut last, format!("Bereit – {}", display_name(&name)), &emit);
            }
            present = now;
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn uid_parsing() {
        assert_eq!(super::uid_hex(&[0x04, 0xA2, 0xB3, 0x90, 0x00]).as_deref(), Some("04A2B3"));
        assert_eq!(super::uid_hex(&[0x63, 0x00]), None);
        assert_eq!(super::uid_hex(&[0x04, 0x6A, 0x81]), None);
        assert_eq!(super::display_name("ACS ACR122U PICC Interface"), "ACS ACR122U");
        assert_eq!(super::display_name("ACS ACR122U PICC Interface 00 00"), "ACS ACR122U");
        assert_eq!(super::display_name("SCM Microsystems SCL3711"), "SCM Microsystems SCL3711");
    }
}
