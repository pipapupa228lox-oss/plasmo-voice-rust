//! Java's `VoiceServerLanguages`, without Crowdin: the strings the relay
//! ships, and the owner's own files merged over them.
//!
//! Java keeps a `languages` folder beside its config, one TOML file per
//! language — `en_us.toml` in the jar, the owner's file on top of it — and
//! answers a `LanguageRequest` with the `[client]` scope of one, flattened into
//! `pv.activation.proximity`-style keys
//! (`VoiceServerLanguages.getClientLanguage`). This is the same catalogue: the
//! two files it ships are compiled in, the folder is seeded with them on the
//! first start, and a file the owner writes wins key by key.
//!
//! The other half of a file, `[server]`, is the words the server says itself;
//! Java registers it in the platform's translator, and [`Catalogue::server`]
//! gives the game the same table so it can render its own messages in the
//! recipient's language.

use std::collections::BTreeMap;
use std::path::Path;

/// The languages compiled into the relay: Java's `languages/en_us.toml`
/// verbatim, and a Russian translation of it (Java downloads that one from
/// Crowdin; a relay has no business fetching files, so it travels here).
pub const BUILTIN: &[(&str, &str)] = &[
    ("en_us", include_str!("../languages/en_us.toml")),
    ("ru_ru", include_str!("../languages/ru_ru.toml")),
];

/// `FALLBACK_LANGUAGE` in `VoiceServerLanguages`: a language that has no file
/// of its own is answered with this one's strings, as Java's `fillMissing`
/// merges it into every language it loads.
const FALLBACK: &str = "en_us";

/// One language's strings, by scope.
#[derive(Clone, Debug, Default)]
pub struct Language {
    /// `[client]`: what a `LanguageRequest` is answered with.
    client: BTreeMap<String, String>,
    /// `[server]`: what the server says itself — the mute notices, the
    /// mod-required kick, `/vmute`'s own answers. Java registers this scope in
    /// its platform translator, which renders a `translate` component in the
    /// recipient's language before it is sent; [`Catalogue::server`] is that
    /// same table for the game to render with.
    server: BTreeMap<String, String>,
}

/// Every language the relay knows, by lowercased name.
#[derive(Clone, Debug)]
pub struct Catalogue {
    languages: BTreeMap<String, Language>,
}

impl Catalogue {
    /// The catalogue with only what is compiled in: no folder, nothing to
    /// read, and a `LanguageRequest` answered with Java's own default strings.
    pub fn builtin() -> Catalogue {
        let mut languages: BTreeMap<String, Language> = BTreeMap::new();
        for (name, text) in BUILTIN {
            // A file that will not parse is not offered; for the two compiled
            // in it cannot happen — a test parses both.
            if let Ok(language) = Language::parse(text) {
                languages.insert((*name).to_string(), language);
            }
        }
        let mut catalogue = Catalogue { languages };
        catalogue.fill_missing();
        catalogue
    }

    /// The catalogue a relay starts with: the built-in languages, `dir` seeded
    /// with any of them that is not there yet (an owner's file is never
    /// overwritten), and every `.toml` in it merged over the built-ins. The
    /// returned lines are warnings for the log, as the relay prefixes nothing.
    pub fn load(dir: Option<&Path>) -> (Catalogue, Vec<String>) {
        let mut catalogue = Catalogue::builtin();
        let mut warnings = Vec::new();
        let Some(dir) = dir else {
            return (catalogue, warnings);
        };
        if let Err(error) = std::fs::create_dir_all(dir) {
            warnings.push(format!(
                "voice: could not create {}: {error}; using the compiled-in languages",
                dir.display()
            ));
            return (catalogue, warnings);
        }
        // `VoiceServerLanguages.register` writes every language it loaded back
        // to the folder, so the owner has a file to edit. Writing only the
        // missing ones keeps a file that was edited.
        for (name, text) in BUILTIN {
            let path = dir.join(format!("{name}.toml"));
            if path.exists() {
                continue;
            }
            if let Err(error) = std::fs::write(&path, text) {
                warnings.push(format!(
                    "voice: could not write {}: {error}; {} stays compiled in",
                    path.display(),
                    name
                ));
            }
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            warnings.push(format!("voice: could not read {}", dir.display()));
            return (catalogue, warnings);
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("toml") {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|stem| stem.to_str()) else {
                continue;
            };
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(error) => {
                    warnings.push(format!(
                        "voice: could not read {}: {error}; {} keeps the compiled-in strings",
                        path.display(),
                        name
                    ));
                    continue;
                }
            };
            match Language::parse(&text) {
                // The owner's file wins key by key, and a language the relay
                // does not ship is added as it is.
                Ok(language) => catalogue
                    .languages
                    .entry(name.to_ascii_lowercase())
                    .or_default()
                    .merge_over(&language),
                Err(error) => warnings.push(format!(
                    "voice: {} is not a language file: {error}",
                    path.display()
                )),
            }
        }
        catalogue.fill_missing();
        (catalogue, warnings)
    }

    /// `VoiceServerLanguages.getClientLanguage`: the `[client]` scope flattened
    /// into dotted keys, sorted. `forced_language` wins over what the client
    /// asked for and gets nothing when it names a language the relay does not
    /// have (Java's `languages[forced] ?: ImmutableMap.of()`); a name neither
    /// of them knows is answered with `default_language`'s strings.
    pub fn client(
        &self,
        requested: &str,
        default: &str,
        forced: Option<&str>,
    ) -> Vec<(String, String)> {
        self.scope(requested, default, forced, Language::client_pairs)
    }

    /// `VoiceServerLanguages.getServerLanguage`, resolved by the same rule: the
    /// `[server]` scope of `forced_language`, else of the language the
    /// recipient asked for, else of `default_language`. The game renders its
    /// own messages with it (`ServerLanguages.translate`): a key here becomes
    /// text in that language, a key it lacks is left for the client to resolve.
    pub fn server(
        &self,
        requested: &str,
        default: &str,
        forced: Option<&str>,
    ) -> Vec<(String, String)> {
        self.scope(requested, default, forced, Language::server_pairs)
    }

    /// One scope of one language: Java's `getLanguage(name, scope)`, which both
    /// scopes share — a `forced_language` wins over the name, and a name the
    /// catalogue does not have falls back to `default_language`.
    fn scope(
        &self,
        requested: &str,
        default: &str,
        forced: Option<&str>,
        pick: fn(&Language) -> Vec<(String, String)>,
    ) -> Vec<(String, String)> {
        if let Some(forced) = forced {
            return self
                .languages
                .get(&forced.trim().to_ascii_lowercase())
                .map(pick)
                .unwrap_or_default();
        }
        self.languages
            .get(&requested.trim().to_ascii_lowercase())
            .or_else(|| self.languages.get(&default.trim().to_ascii_lowercase()))
            .map(pick)
            .unwrap_or_default()
    }

    /// The language names the catalogue answers from, for the log: an admin
    /// who added `languages/de_de.toml` and sees no `de_de` here has a file
    /// that did not parse, and the warning says why.
    pub fn names(&self) -> Vec<&str> {
        self.languages.keys().map(|name| name.as_str()).collect()
    }

    /// Every key a language is missing is filled from `en_us`, as Java's
    /// `fillMissing` does, so a partial translation falls back word by word
    /// rather than sending a client nothing.
    fn fill_missing(&mut self) {
        let Some(fallback) = self.languages.get(FALLBACK).cloned() else {
            return;
        };
        for (name, language) in self.languages.iter_mut() {
            if name == FALLBACK {
                continue;
            }
            for (key, value) in fallback.client.iter() {
                language
                    .client
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
            for (key, value) in fallback.server.iter() {
                language
                    .server
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }
}

impl Language {
    fn client_pairs(&self) -> Vec<(String, String)> {
        pairs(&self.client)
    }

    fn server_pairs(&self) -> Vec<(String, String)> {
        pairs(&self.server)
    }

    /// The owner's file on top of the compiled-in strings: a key it has
    /// replaces the one here, a key it leaves out keeps it.
    fn merge_over(&mut self, other: &Language) {
        for (key, value) in other.client.iter() {
            self.client.insert(key.clone(), value.clone());
        }
        for (key, value) in other.server.iter() {
            self.server.insert(key.clone(), value.clone());
        }
    }

    /// A language file: `[client]` and `[server]` tables of string keys. Every
    /// other table Java's files never have is parsed and dropped.
    fn parse(text: &str) -> Result<Language, String> {
        let mut language = Language::default();
        for (path, value) in entries(text)? {
            if let Some(key) = path.strip_prefix("client.") {
                language.client.insert(key.to_string(), value);
            } else if let Some(key) = path.strip_prefix("server.") {
                language.server.insert(key.to_string(), value);
            }
        }
        Ok(language)
    }
}

fn pairs(map: &BTreeMap<String, String>) -> Vec<(String, String)> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// A TOML subset, enough for a language file: `[a.b]` tables, `key = "value"`
/// (basic, literal and both multi-line strings), comments, and bare scalars
/// read as text (Java's `value.toString()`). Anything else — arrays, inline
/// tables, dates — is refused rather than guessed at, and a file that is
/// refused is reported and skipped.
fn entries(text: &str) -> Result<Vec<(String, String)>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0;
    let mut table: Vec<String> = Vec::new();
    let mut out = Vec::new();
    while let Some(&ch) = chars.get(index) {
        match ch {
            '\n' | '\r' | ' ' | '\t' => index += 1,
            '#' => {
                while chars.get(index).is_some_and(|ch| *ch != '\n') {
                    index += 1;
                }
            }
            '[' => {
                let open = index + 1;
                let close = (open..chars.len())
                    .find(|at| chars[*at] == ']')
                    .ok_or_else(|| {
                        format!("the table header at character {index} is not closed")
                    })?;
                let header: String = chars[open..close].iter().collect();
                table = header
                    .split('.')
                    .map(|part| part.trim().trim_matches('"').to_string())
                    .filter(|part| !part.is_empty())
                    .collect();
                index = close + 1;
            }
            _ => {
                let start = index;
                let equals = (index..chars.len())
                    .find(|at| chars[*at] == '=' || chars[*at] == '\n')
                    .ok_or_else(|| format!("the key at character {start} has no value"))?;
                if chars[equals] != '=' {
                    return Err(format!("the line at character {start} has no `=`"));
                }
                let key: String = chars[start..equals].iter().collect();
                let key = key.trim().trim_matches('"').to_string();
                if key.is_empty() {
                    return Err(format!("the line at character {start} has no key"));
                }
                index = equals + 1;
                let value = value_at(&chars, &mut index)?;
                let mut path = table.clone();
                path.push(key);
                out.push((path.join("."), value));
            }
        }
    }
    Ok(out)
}

/// The value after a `=`: a quoted string (with TOML's escapes, either on one
/// line or between `"""`/`'''`), or a bare scalar read as text up to the end of
/// the line.
fn value_at(chars: &[char], index: &mut usize) -> Result<String, String> {
    while let Some(&ch) = chars.get(*index) {
        if ch == ' ' || ch == '\t' {
            *index += 1;
        } else {
            break;
        }
    }
    let opens = |at: usize, delimiter: &str| -> bool {
        delimiter
            .chars()
            .enumerate()
            .all(|(offset, want)| chars.get(at + offset) == Some(&want))
    };
    match chars.get(*index) {
        Some('"') if opens(*index, "\"\"\"") => {
            *index += 3;
            // TOML drops one newline right after the opening delimiter.
            if opens(*index, "\r\n") {
                *index += 2;
            } else if chars.get(*index) == Some(&'\n') {
                *index += 1;
            }
            let mut out = String::new();
            loop {
                match chars.get(*index) {
                    None => return Err("a `\"\"\"` string is not closed".into()),
                    Some('"') if opens(*index, "\"\"\"") => {
                        *index += 3;
                        return Ok(out);
                    }
                    Some('\\') => out.push(escape(chars, index)?),
                    Some(&ch) => {
                        out.push(ch);
                        *index += 1;
                    }
                }
            }
        }
        Some('"') => {
            *index += 1;
            let mut out = String::new();
            loop {
                match chars.get(*index) {
                    None | Some('\n') => return Err("a string is not closed".into()),
                    Some('"') => {
                        *index += 1;
                        return Ok(out);
                    }
                    Some('\\') => out.push(escape(chars, index)?),
                    Some(&ch) => {
                        out.push(ch);
                        *index += 1;
                    }
                }
            }
        }
        Some('\'') if opens(*index, "'''") => {
            *index += 3;
            if opens(*index, "\r\n") {
                *index += 2;
            } else if chars.get(*index) == Some(&'\n') {
                *index += 1;
            }
            let mut out = String::new();
            loop {
                match chars.get(*index) {
                    None => return Err("a `'''` string is not closed".into()),
                    Some('\'') if opens(*index, "'''") => {
                        *index += 3;
                        return Ok(out);
                    }
                    Some(&ch) => {
                        out.push(ch);
                        *index += 1;
                    }
                }
            }
        }
        Some('\'') => {
            *index += 1;
            let mut out = String::new();
            loop {
                match chars.get(*index) {
                    None | Some('\n') => return Err("a literal string is not closed".into()),
                    Some('\'') => {
                        *index += 1;
                        return Ok(out);
                    }
                    Some(&ch) => {
                        out.push(ch);
                        *index += 1;
                    }
                }
            }
        }
        _ => {
            let start = *index;
            while let Some(&ch) = chars.get(*index) {
                if ch == '\n' || ch == '\r' || ch == '#' {
                    break;
                }
                *index += 1;
            }
            let raw: String = chars[start..*index].iter().collect();
            Ok(raw.trim().to_string())
        }
    }
}

/// One escape of a basic string, `\` included: TOML's own set, and the two
/// `\u`/`\U` forms for anything outside ASCII.
fn escape(chars: &[char], index: &mut usize) -> Result<char, String> {
    *index += 1; // the backslash
    let Some(&ch) = chars.get(*index) else {
        return Err("a string ends on a `\\`".into());
    };
    *index += 1;
    Ok(match ch {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        'b' => '\u{8}',
        'f' => '\u{c}',
        '"' => '"',
        '\\' => '\\',
        'u' | 'U' => {
            let digits = if ch == 'u' { 4 } else { 8 };
            let mut code = 0u32;
            for _ in 0..digits {
                let Some(&digit) = chars.get(*index) else {
                    return Err(format!("`\\{ch}` has fewer than {digits} digits"));
                };
                let value = digit
                    .to_digit(16)
                    .ok_or_else(|| format!("`{digit}` is not a hex digit after `\\{ch}`"))?;
                code = code * 16 + value;
                *index += 1;
            }
            char::from_u32(code).ok_or_else(|| format!("`\\{ch}{code:X}` is not a character"))?
        }
        other => return Err(format!("`\\{other}` is not an escape TOML has")),
    })
}
