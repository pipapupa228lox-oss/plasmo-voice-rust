//! `voice_mutes.json`: where the server mutes are kept, in the shape Java's
//! `JsonMuteStorage` writes — Gson's rendering of
//! `Map<UUID, ServerMuteInfo>`:
//!
//! ```json
//! {"8f4c2d1e-…":{"playerUUID":"8f4c2d1e-…","mutedByPlayerUUID":null,
//!                "mutedAtTime":1762…,"mutedToTime":0,"reason":"being loud",
//!                "silent":null}}
//! ```
//!
//! Reading that shape matters: an owner who moves a server off the Java plugin
//! keeps the mutes they already handed out. Writing it back means Java would
//! read this file too, and `mutedToTime` (unix milliseconds, `0` for a
//! permanent mute) is exactly what both expiry ticks compare.
//!
//! There is no JSON dependency here on purpose: the file holds one map of
//! small objects, and a parser for anything more would be a library. What this
//! reader does not understand it skips — an unknown field or a whole entry
//! with a broken UUID — so a hand-edited file or a future Java version still
//! starts the server.

use std::io;
use std::path::Path;

use pv_proto::Uuid;
use pv_proto::bytes::uuid_to_string;

/// One entry of the file: what `ServerMuteInfo` holds, minus who did the
/// muting (a Horizon server mutes from its console, which is not a player).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMute {
    pub player: Uuid,
    /// `mutedAtTime`, unix milliseconds.
    pub muted_at: u64,
    /// `mutedToTime`, unix milliseconds; `0` is a permanent mute.
    pub until: u64,
    pub reason: Option<String>,
    /// `silent`: the player was not told about the mute (`notifications.muted`
    /// off). `false` also stands for Java's `null`, the field's old form.
    pub silent: bool,
}

impl StoredMute {
    /// Whether the mute still holds at `now` (unix milliseconds), as
    /// `VoiceMuteManager.isMuteValid` decides it.
    pub fn valid(&self, now: u64) -> bool {
        self.until == 0 || self.until > now
    }
}

/// Every mute in `path`, or none when the file is not there. A file that is
/// there and unreadable is an `InvalidData` error: the caller logs it and
/// carries on with no mutes, rather than refusing to start the relay.
pub fn load(path: &Path) -> io::Result<Vec<StoredMute>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    parse(&text).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Writes every mute to `path`, all at once: a half-written file would be
/// unreadable at the next start, so it goes to a temporary name and is renamed
/// over the real one.
pub fn save(path: &Path, mutes: &[StoredMute]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut out = String::from("{");
    for (index, mute) in mutes.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_entry(&mut out, mute);
    }
    out.push('}');
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, out)?;
    // On Windows this replaces the file in one step too, which `write` on the
    // real name would not.
    std::fs::rename(&temporary, path)
}

fn write_entry(out: &mut String, mute: &StoredMute) {
    let uuid = uuid_to_string(mute.player);
    out.push('"');
    out.push_str(&uuid);
    out.push_str("\":{\"playerUUID\":\"");
    out.push_str(&uuid);
    // No player muted this one: the console did, and Java writes `null` for
    // the same case (a mute from the console has no `mutedBy`).
    out.push_str("\",\"mutedByPlayerUUID\":null,\"mutedAtTime\":");
    out.push_str(&mute.muted_at.to_string());
    out.push_str(",\"mutedToTime\":");
    out.push_str(&mute.until.to_string());
    out.push_str(",\"reason\":");
    match &mute.reason {
        Some(reason) => push_string(out, reason),
        None => out.push_str("null"),
    }
    out.push_str(",\"silent\":");
    out.push_str(if mute.silent { "true" } else { "false" });
    out.push('}');
}

/// A JSON string literal: `"`, `\` and the control characters escaped, the
/// rest as it stands (Gson writes UTF-8 as it is, so a Cyrillic reason stays
/// readable in the file).
fn push_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The entries of a `voice_mutes.json` text.
fn parse(text: &str) -> Result<Vec<StoredMute>, String> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    let root = reader.value()?;
    let Value::Object(entries) = root else {
        return Err("the file is not a JSON object".into());
    };
    let mut mutes = Vec::with_capacity(entries.len());
    for (key, entry) in entries {
        let Value::Object(fields) = entry else {
            continue;
        };
        let field = |name: &str| {
            fields
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value)
        };
        // The map's key and `playerUUID` say the same thing; either is enough
        // for an entry to be understood.
        let uuid = match field("playerUUID") {
            Some(Value::Text(uuid)) => Some(uuid.clone()),
            _ => Some(key),
        };
        let Some(player) = uuid.as_deref().and_then(parse_uuid) else {
            continue;
        };
        let number = |name: &str| match field(name) {
            Some(Value::Number(value)) => value.parse::<u64>().ok(),
            _ => None,
        };
        mutes.push(StoredMute {
            player,
            muted_at: number("mutedAtTime").unwrap_or(0),
            until: number("mutedToTime").unwrap_or(0),
            reason: match field("reason") {
                Some(Value::Text(reason)) => Some(reason.clone()),
                _ => None,
            },
            silent: matches!(field("silent"), Some(Value::Bool(true))),
        });
    }
    Ok(mutes)
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, or the same 32 hex digits without
/// the hyphens (Java's `UUID.fromString` accepts only the first form).
fn parse_uuid(text: &str) -> Option<Uuid> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut uuid: Uuid = [0; 16];
    for (index, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(uuid)
}

#[derive(Debug, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    List(Vec<Value>),
    Object(Vec<(String, Value)>),
}

/// A reader for the JSON the file holds: objects, lists, strings, numbers,
/// `true`/`false`/`null`. Nothing else can appear in a file Gson writes, and a
/// file it did not write is skipped by the caller, not parsed here.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn value(&mut self) -> Result<Value, String> {
        self.space();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.list(),
            Some(b'"') => self.text().map(Value::Text),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            other => Err(format!("unexpected {other:?} at byte {}", self.at)),
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.at += 1; // `{`
        let mut entries = Vec::new();
        loop {
            self.space();
            match self.peek() {
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(entries));
                }
                Some(b'"') => {}
                other => return Err(format!("expected a key, found {other:?}")),
            }
            let key = self.text()?;
            self.space();
            if self.peek() != Some(b':') {
                return Err("expected `:`".into());
            }
            self.at += 1;
            let value = self.value()?;
            entries.push((key, value));
            self.space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {}
                other => return Err(format!("expected `,` or `}}`, found {other:?}")),
            }
        }
    }

    fn list(&mut self) -> Result<Value, String> {
        self.at += 1; // `[`
        let mut items = Vec::new();
        loop {
            self.space();
            match self.peek() {
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::List(items));
                }
                Some(_) => items.push(self.value()?),
                None => return Err("a list that never ends".into()),
            }
            self.space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {}
                other => return Err(format!("expected `,` or `]`, found {other:?}")),
            }
        }
    }

    fn text(&mut self) -> Result<String, String> {
        self.at += 1; // the opening quote
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err("a string that never ends".into());
            };
            self.at += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err("a string that ends in a backslash".into());
                    };
                    self.at += 1;
                    match escaped {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let digits = self
                                .bytes
                                .get(self.at..self.at + 4)
                                .ok_or("a `\\u` escape that is cut short")?;
                            let code = u32::from_str_radix(
                                std::str::from_utf8(digits).map_err(|_| "a bad `\\u`")?,
                                16,
                            )
                            .map_err(|_| "a bad `\\u`")?;
                            self.at += 4;
                            out.push(char::from_u32(code).ok_or("a `\\u` that is not a char")?);
                        }
                        other => return Err(format!("an escape this file cannot hold: {other:?}")),
                    }
                }
                // Everything else is UTF-8 and is taken byte by byte into a
                // buffer, so a multi-byte character survives.
                _ => {
                    self.at -= 1;
                    let rest = std::str::from_utf8(&self.bytes[self.at..])
                        .map_err(|_| "the file is not UTF-8")?;
                    let character = rest.chars().next().ok_or("a string that never ends")?;
                    self.at += character.len_utf8();
                    out.push(character);
                }
            }
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.at;
        while matches!(self.peek(), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|_| "a number that is not text")?
            .to_owned();
        if text.is_empty() {
            return Err("a number that is not there".into());
        }
        Ok(Value::Number(text))
    }

    fn literal(&mut self, text: &str, value: Value) -> Result<Value, String> {
        if self.bytes[self.at..].starts_with(text.as_bytes()) {
            self.at += text.len();
            Ok(value)
        } else {
            Err(format!("expected `{text}`"))
        }
    }

    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u128) -> Uuid {
        n.to_be_bytes()
    }

    #[test]
    fn a_file_is_written_in_the_shape_java_writes_and_read_back() {
        let dir = std::env::temp_dir().join(format!("pv-mutes-roundtrip-{}", std::process::id()));
        let path = dir.join("voice_mutes.json");
        let mutes = vec![
            StoredMute {
                player: uuid(1),
                muted_at: 1_700_000_000_000,
                until: 0,
                reason: Some("being \"loud\"\nand rude".into()),
                silent: false,
            },
            StoredMute {
                player: uuid(2),
                muted_at: 1_700_000_000_000,
                until: 1_700_000_300_000,
                reason: None,
                silent: true,
            },
        ];
        save(&path, &mutes).expect("write");
        let text = std::fs::read_to_string(&path).expect("read");
        // The names and the shape are Java's, so the plugin could read it.
        assert!(text.contains("\"mutedByPlayerUUID\":null"), "{text}");
        assert!(text.contains("\"mutedToTime\":0"), "{text}");
        assert!(text.contains("\"reason\":null"), "{text}");
        assert!(text.contains("\"silent\":true"), "{text}");
        assert!(text.contains("00000000-0000-0000-0000-000000000001"), "{text}");
        assert_eq!(load(&path).expect("load"), mutes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_java_file_is_read_as_it_is() {
        // Two entries as `JsonMuteStorage` writes them, one of them the old
        // shape without `silent`, and an unknown field Java might add.
        let text = r#"{
          "8f4c2d1e-6d3a-4b7c-9f4e-1a2b3c4d5e6f": {
            "playerUUID": "8f4c2d1e-6d3a-4b7c-9f4e-1a2b3c4d5e6f",
            "mutedByPlayerUUID": null,
            "mutedAtTime": 1762000000000,
            "mutedToTime": 0,
            "reason": "being loud",
            "silent": null
          },
          "8f4c2d1e-6d3a-4b7c-9f4e-1a2b3c4d5e70": {
            "playerUUID": "8f4c2d1e-6d3a-4b7c-9f4e-1a2b3c4d5e70",
            "mutedByPlayerUUID": "8f4c2d1e-6d3a-4b7c-9f4e-1a2b3c4d5e71",
            "mutedAtTime": 1762000000000,
            "mutedToTime": 1762000300000,
            "reason": null,
            "somethingNew": [1, 2, {"no": true}]
          }
        }"#;
        let mutes = parse(text).expect("the file parses");
        assert_eq!(mutes.len(), 2);
        assert_eq!(mutes[0].reason.as_deref(), Some("being loud"));
        assert!(!mutes[0].silent, "`silent: null` is false");
        assert_eq!(mutes[0].until, 0, "a permanent mute");
        assert_eq!(mutes[1].until, 1_762_000_300_000);
        assert_eq!(mutes[1].reason, None);
    }

    #[test]
    fn an_entry_without_a_usable_uuid_is_skipped() {
        let text = r#"{
          "not a uuid": {"mutedToTime": 0},
          "8f4c2d1e6d3a4b7c9f4e1a2b3c4d5e70": {"mutedToTime": 1762000300000}
        }"#;
        let mutes = parse(text).expect("the file parses");
        assert_eq!(mutes.len(), 1, "32 hex digits without hyphens are a UUID");
        assert_eq!(mutes[0].until, 1_762_000_300_000);
    }

    #[test]
    fn a_missing_file_is_no_mutes_and_a_broken_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("pv-mutes-missing-{}", std::process::id()));
        let path = dir.join("voice_mutes.json");
        assert!(load(&path).expect("a missing file is empty").is_empty());
        std::fs::create_dir_all(&dir).expect("a directory");
        std::fs::write(&path, "{not json").expect("write");
        let error = load(&path).expect_err("a broken file is refused");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_mute_that_has_not_run_out_is_valid() {
        let permanent = StoredMute {
            player: uuid(1),
            muted_at: 0,
            until: 0,
            reason: None,
            silent: false,
        };
        assert!(permanent.valid(10_000));
        let timed = StoredMute {
            until: 5_000,
            ..permanent.clone()
        };
        assert!(timed.valid(4_999));
        assert!(!timed.valid(5_000), "the second it ends, it is over");
    }
}
