//! The relay itself: one UDP socket, one session table, and the loop that
//! moves audio between them.
//!
//! The game owns a [`Relay`], which is only a pair of channels and the bound
//! address; the socket, the sessions and every decision live on the
//! `horizon-voice` thread, so a tick never waits on the network.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pv_proto::Config as VoiceConfig;
use pv_proto::{
    CaptureInfo, CodecInfo, EncryptionInfo, PROXIMITY_NAME, PlayerIconConfig, Pos3d, SourceInfo,
    TcpPacket, UdpBody, UdpPacket, Uuid, VoiceActivation, VoicePlayerInfo, VoiceSourceLine,
    source_line_id,
};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::pkcs8::DecodePublicKey;

use crate::crypto::Cipher;
use crate::languages::Catalogue;
use crate::mutes::{self, StoredMute};
use crate::session::Session;

/// Datagrams and control messages one pass of the loop takes before it looks
/// at the clock: enough to keep up with a full server, few enough that a
/// flood cannot hold the timeouts back for long.
const PER_PASS: usize = 64;
/// Largest datagram read at all. [`Config::max_datagram_bytes`] is clamped to
/// it, and anything longer is dropped before it is decoded.
const DATAGRAM: usize = 2048;
/// How long a `recv_from` waits before the loop looks at the clock again.
const IDLE: Duration = Duration::from_millis(20);
/// How often the sessions are checked for silence and retries.
const SWEEP: Duration = Duration::from_secs(1);
/// `NettyUdpKeepAlive`'s schedule: a `PingPacket` about every 1.5–3 s, the
/// lower bound here plus a jitter of up to [`PING_JITTER`]. It has to be well
/// under the seven seconds after which a Java client calls itself timed out.
const PING_FIRST: Duration = Duration::from_millis(1_500);
/// The jitter a ping's schedule is sprinkled with, in milliseconds, so a
/// hundred sessions do not all answer in the same millisecond.
const PING_JITTER: u32 = 1_500;

/// `ProximityServerActivation.register`: the icon Java names for the proximity
/// activation. A full resource location, because that is what a client parses
/// (`ResourceLocationUtil.parse(activation.getIcon())`) — a short name is a
/// valid location in the default namespace and renders as the missing-texture
/// checkerboard.
const ACTIVATION_ICON: &str = "plasmovoice:textures/icons/microphone.png";
/// The same for the proximity source line: Java's speaker icon.
const SOURCE_LINE_ICON: &str = "plasmovoice:textures/icons/speaker.png";

/// What the relay is told and what it must respect.
#[derive(Clone, Debug)]
pub struct Config {
    /// Where to bind. Port 0 takes the system's choice, which
    /// [`Relay::local_addr`] reports for the `ConnectionPacket`.
    pub bind: SocketAddr,
    /// `ConfigPacket.capture.sample_rate`: 48 kHz, what every PV client sends.
    pub sample_rate: i32,
    /// `ConfigPacket.capture.mtu_size`: the largest frame a client may encode.
    pub mtu: i32,
    /// `[voice.opus] mode`, sent in `CaptureInfo.encoder`.
    pub opus_mode: String,
    /// `[voice.opus] bitrate`, sent in `CaptureInfo.encoder`.
    pub opus_bitrate: i32,
    /// `proximity.distances`: the distances the proximity activation offers.
    pub distances: Vec<i32>,
    /// `playerIcon.visibility`: icons a client hides. Empty shows them all.
    pub player_icon_visibility: Vec<String>,
    /// `playerIcon.yOffset`: how far above the head the icon sits.
    pub player_icon_y_offset: f64,
    /// `clientModMinVersion`: a client older than this is never configured,
    /// as in Java (which does not kick it either).
    pub client_mod_min_version: String,
    /// `clientModRequired`: a player who never sends a control packet has no
    /// mod installed and is kicked from the Minecraft server, which Java's
    /// `ModRequiredKickHandler` does after
    /// [`Config::client_mod_required_check`]. The game does the kicking; this
    /// side only says who and when ([`Event::ModMissing`]).
    pub client_mod_required: bool,
    /// `clientModRequiredCheckTimeoutMs`, 3 s in Java: how long a joining
    /// player has to send the mod's first packet.
    pub client_mod_required_check: Duration,
    /// `defaultLanguage`: the language name a `LanguageRequest` gets when the
    /// client asks for nothing in particular.
    pub default_language: String,
    /// `forcedLanguage`: one language for every client. Java answers a
    /// `LanguageRequest` with this instead of the client's own choice.
    pub forced_language: Option<String>,
    /// The farthest a speaker is heard, whatever distance their activation
    /// asks for. It bounds the choices a client is offered, not the relaying:
    /// listeners reach is `min(distance + extra_broadcast_distance, distance
    /// * 2)`, as `VoiceServerProximitySource.getListeners` computes it.
    pub max_distance: i32,
    /// `VoiceServerConfig.Voice.maxExtraAudioBroadcastDistance` (16 by
    /// default): audio is relayed past the activation's own distance by this
    /// much, but never past twice that distance. A 16-block activation is
    /// heard at 32, which is why a whisper two metres away is not silent
    /// because a position update was a second old.
    pub extra_broadcast_distance: i32,
    /// `ConfigPacket`'s default proximity distance (8, 16 or 32 in PV).
    pub default_distance: i32,
    /// A session that sends nothing for this long is dropped.
    /// `keepAliveTimeoutMs` in PlasmoVoice is 15 000: the client pings once a
    /// second, so a quiet player is never the one that times out first.
    pub session_timeout: Duration,
    /// Sessions at most; a join past it is refused and logged.
    pub max_sessions: usize,
    /// Listeners a single audio frame is copied to at most, so one speaker
    /// among a hundred cannot spend the server's bandwidth in one tick.
    pub max_recipients: usize,
    /// What `ConnectionPacket.ip` says. Empty means `"0.0.0.0"`, which is how
    /// PlasmoVoice spells "use the Minecraft server's own host": a client
    /// replaces exactly that string with the address it reached the server at,
    /// and an empty one it would resolve to loopback instead.
    pub announce_ip: String,
    /// The largest datagram worth reading: the MTU the clients were given,
    /// plus the header and the AES block padding. Anything longer is dropped
    /// before it is parsed.
    pub max_datagram_bytes: usize,
    /// Datagrams one session may send each second, refilled continuously. A
    /// 20 ms Opus frame is 50 a second and the keep-alive 2, so this is room
    /// for four times a normal talker. `0` lifts the cap.
    pub datagrams_per_second: u32,
    /// Commands the game may have in flight. A full queue drops the oldest
    /// positions (a newer one supersedes them) rather than growing with the
    /// tick rate.
    pub queue: usize,
    /// Events the relay may have waiting for the game. A full queue drops the
    /// oldest: for a burst of audio the oldest is the one already too late to
    /// play.
    pub events: usize,
    /// The shared AES key, when the owner pinned one (`voice-key` in
    /// `server.properties`). `None` makes a new one at every start, which is
    /// what a server that restarts more often than it changes keys wants.
    pub key: Option<[u8; 16]>,
    /// `voice_mutes.json` (Java's `JsonMuteStorage` keeps the same name and
    /// shape): where the server mutes are read at start and written on every
    /// change, so a mute survives a restart as it does with the plugin.
    /// `None` keeps them in memory.
    pub mute_file: Option<PathBuf>,
    /// `languages/` (Java's `VoiceServerLanguages` folder): one `.toml` per
    /// language, seeded with the two the relay ships and merged over them, so
    /// a `LanguageRequest` is answered from a file the owner can edit. `None`
    /// keeps to the strings compiled in.
    pub languages_dir: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            sample_rate: 48_000,
            mtu: 1024,
            max_distance: 32,
            opus_mode: "VOIP".into(),
            opus_bitrate: -1000,
            // `proximity.distances` in PlasmoVoice: whisper, normal, shout.
            distances: vec![8, 16, 32],
            player_icon_visibility: Vec::new(),
            player_icon_y_offset: 0.0,
            client_mod_min_version: "2.0.0".into(),
            client_mod_required: false,
            client_mod_required_check: Duration::from_millis(3_000),
            default_language: "en_us".into(),
            forced_language: None,
            extra_broadcast_distance: 16,
            default_distance: 16,
            // The Java server's `keepAliveTimeoutMs` (15 000): a client that
            // says nothing for that long is dropped and asked to reconnect.
            session_timeout: Duration::from_secs(15),
            max_sessions: 256,
            max_recipients: 32,
            // `[host] ip` in Java, whose default is "0.0.0.0".
            announce_ip: "0.0.0.0".into(),
            max_datagram_bytes: 1088,
            datagrams_per_second: 200,
            queue: 256,
            events: 1024,
            key: None,
            // No file unless the owner asks for one: the tests and the library
            // stay free of the working directory.
            mute_file: None,
            languages_dir: None,
        }
    }
}

impl Config {
    /// The defaults, listening on `port` (`0` for the system's choice).
    pub fn on_port(port: u16) -> Self {
        Config {
            bind: SocketAddr::from(([0, 0, 0, 0], port)),
            ..Config::default()
        }
    }
}

/// Any place in the world, as the server tick knows it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Place {
    /// The dimension's index in the game's own list; two players in different
    /// dimensions never hear each other.
    pub dimension: u32,
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Place {
    /// Squared distance, which is all the relay compares.
    pub fn distance2(&self, other: &Place) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        let dz = self.z - other.z;
        dx * dx + dy * dy + dz * dz
    }
}

/// A player's place in the world, as the server tick knows it.
#[derive(Clone, Copy, Debug)]
pub struct Position {
    pub player: Uuid,
    /// The dimension's index in the game's own list; two players in different
    /// dimensions never hear each other.
    pub dimension: u32,
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Position {
    pub fn place(&self) -> Place {
        Place {
            dimension: self.dimension,
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }
}

/// A source that is not a player's microphone: a block (a jukebox), an entity,
/// or a stream an addon feeds. Its record is what `SourceInfoRequest` is
/// answered with, and its place is where a listener has to be to hear it.
#[derive(Clone, Debug)]
pub struct Source {
    /// The `SourceInfo` the clients get: `STATIC` and `ENTITY` records carry
    /// their own tail, which [`pv_proto::SourceInfo::static_source`] writes.
    pub info: SourceInfo,
    pub place: Place,
    /// The farthest it is heard, in blocks, whatever a client's own setting
    /// says: the server owns who hears whom. Zero or less is a direct source
    /// (music, an addon's stream): it has no place, and every session hears
    /// it.
    pub distance: i16,
}

/// A log line's severity, named as the server's log names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARN",
        }
    }
}

/// The unit a `/vmute` length was given in: Java prints the same unit back
/// (`MuteDurationUnit.translationKey`), so the player a moderator muted for
/// five minutes is told "for 5 min", not "for 300 sec".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuteUnit {
    Seconds,
    Minutes,
    Hours,
    Days,
    Weeks,
}

impl MuteUnit {
    /// The translation key a client resolves for this unit.
    pub fn translation(self) -> &'static str {
        match self {
            MuteUnit::Seconds => "pv.mutes.durations.seconds",
            MuteUnit::Minutes => "pv.mutes.durations.minutes",
            MuteUnit::Hours => "pv.mutes.durations.hours",
            MuteUnit::Days => "pv.mutes.durations.days",
            MuteUnit::Weeks => "pv.mutes.durations.weeks",
        }
    }

    fn millis(self) -> u64 {
        match self {
            MuteUnit::Seconds => 1_000,
            MuteUnit::Minutes => 60_000,
            MuteUnit::Hours => 3_600_000,
            MuteUnit::Days => 86_400_000,
            MuteUnit::Weeks => 604_800_000,
        }
    }
}

/// How long a server mute lasts, as the admin typed it: `5m` is
/// `MuteDuration { unit: Minutes, amount: 5 }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuteDuration {
    pub unit: MuteUnit,
    pub amount: u64,
}

impl MuteDuration {
    /// The wall-clock length. A length past the end of time saturates rather
    /// than overflowing: `/vmute Alice 999999999w` must not panic a thread.
    pub fn length(self) -> Duration {
        Duration::from_millis(self.amount.saturating_mul(self.unit.millis()))
    }
}

/// What the relay needs the game to do. Every one is drained with
/// [`Relay::drain`] on the tick's thread; nothing is called back.
#[derive(Debug)]
pub enum Event {
    /// A `plasmo:voice/v2` payload for this player's Minecraft connection.
    Send { player: Uuid, payload: Vec<u8> },
    /// A line for `logs/latest.log`.
    Log { level: Level, message: String },
    /// `clientModRequired`: this player joined, has not sent the mod's first
    /// control packet in time, and is to be kicked
    /// (`pv.error.mod_missing_kick_message`). `ModRequiredKickHandler` kicks
    /// instead of leaving the player without a voice session.
    ModMissing { player: Uuid, name: String },
    /// A server mute went on or off — `/vmute`, `/vunmute`, or a temporary
    /// mute whose time ran out. The game tells the player, unless
    /// `voice-notify-muted`/`voice-notify-unmuted` says not to (Java's
    /// `[notifications]`).
    Mute {
        player: Uuid,
        name: String,
        muted: bool,
        /// The length the admin gave, for `pv.mutes.temporarily_muted`;
        /// `None` for a permanent mute and for an unmute.
        duration: Option<MuteDuration>,
        /// When the mute ends, unix milliseconds — what `/vmutelist` prints
        /// (`pv.command.mute_list.expire_at`). `None` is `never` in Java's
        /// line, and also what an unmute carries.
        until: Option<u64>,
        reason: Option<String>,
        /// `silent`: the player is not to be told (Java's `[notifications]
        /// muted` off at the time of the mute, or a mute restored from the
        /// file with `silent` set).
        silent: bool,
    },
}

/// The game's handle on the relay thread.
pub struct Relay {
    commands: Arc<Commands>,
    events: Arc<Events>,
    address: SocketAddr,
    thread: Option<JoinHandle<()>>,
    /// The languages the relay reads: the game renders its own messages with
    /// them too (`[server]` scope), so the catalogue is shared rather than
    /// read twice from the same folder.
    catalogue: Arc<Catalogue>,
}

impl Relay {
    /// Binds the socket and starts the thread. The `Err` is a bind failure,
    /// which a caller reports and carries on without voice.
    pub fn start(config: Config) -> io::Result<Relay> {
        let socket = UdpSocket::bind(config.bind)?;
        socket.set_read_timeout(Some(IDLE))?;
        let address = socket.local_addr()?;

        let commands = Arc::new(Commands::new(config.queue));
        let events = Arc::new(Events::new(config.events));
        // One AES key for the whole server: every client gets it wrapped with
        // its own RSA key, and the relay copies sealed payloads between them.
        let key = config.key.unwrap_or_else(crate::secret);
        // `voice_mutes.json`, read before the thread starts: a file that does
        // not parse is a warning and no mutes, never a relay that refuses to
        // run.
        let mut restored = Vec::new();
        let saver = match config.mute_file.clone() {
            Some(path) => {
                match mutes::load(&path) {
                    Ok(stored) => restored = stored,
                    Err(error) => events.push(Event::Log {
                        level: Level::Warn,
                        message: format!(
                            "voice: could not read {}: {error}; starting with no mutes",
                            path.display()
                        ),
                    }),
                }
                Some(Saver::start(path, Arc::clone(&events)))
            }
            None => None,
        };
        let mut worker = Worker::new(socket, config, Arc::clone(&events), key);
        worker.saver = saver;
        worker.restore(restored);
        // `languages/`: read before the thread starts, so the first
        // `LanguageRequest` of a client that is already waiting is answered
        // from the file the owner edited. A file that does not parse is a
        // warning, never a relay that refuses to run.
        let (catalogue, warnings) = Catalogue::load(worker.config.languages_dir.as_deref());
        let catalogue = Arc::new(catalogue);
        for message in warnings {
            events.push(Event::Log {
                level: Level::Warn,
                message,
            });
        }
        events.push(Event::Log {
            level: Level::Info,
            message: format!(
                "voice: languages: {} (from {})",
                catalogue.names().join(", "),
                match worker.config.languages_dir.as_deref() {
                    Some(dir) => dir.display().to_string(),
                    None => "the strings compiled in".into(),
                }
            ),
        });
        worker.catalogue = Arc::clone(&catalogue);
        let queue = Arc::clone(&commands);
        let thread = thread::Builder::new()
            .name("horizon-voice".into())
            .spawn(move || worker.run(&queue))?;

        Ok(Relay {
            commands,
            events,
            address,
            thread: Some(thread),
            catalogue,
        })
    }

    /// The UDP address players are told to send audio to.
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// The languages the relay loaded, `[server]` scope included: what the game
    /// renders its own messages with, in the language of the player they are
    /// for (`ServerLanguages.getServerLanguage`).
    pub fn languages(&self) -> Arc<Catalogue> {
        Arc::clone(&self.catalogue)
    }

    /// A player joined the world: they are asked for their key at once.
    pub fn join(&self, player: Uuid, name: &str) {
        self.commands.push(Command::Join {
            player,
            name: name.to_string(),
        });
    }

    /// A player left (or their world closed): the session goes, and the rest
    /// are told.
    pub fn leave(&self, player: Uuid) {
        self.commands.push(Command::Leave { player });
    }

    /// One `plasmo:voice/v2` payload from a player's connection.
    pub fn channel(&self, player: Uuid, payload: &[u8]) {
        self.commands.push(Command::Channel {
            player,
            data: payload.to_vec(),
        });
    }

    /// The players' places, pushed about once a second: proximity is decided
    /// here, from the server's own positions rather than from anything a
    /// client claims. A newer set replaces one that has not been read yet.
    pub fn positions(&self, positions: Vec<Position>) {
        self.commands.push(Command::Positions(positions));
    }

    /// The sources that are not players: blocks and entities the server wants
    /// heard, with the place each is heard from. Pushed like the positions — a
    /// newer set replaces one that has not been read yet — and empty when the
    /// server has none, which costs the relay one comparison.
    pub fn sources(&self, sources: Vec<Source>) {
        self.commands.push(Command::Sources(sources));
    }

    /// Audio for one of those sources, as an Opus frame the relay seals with
    /// the shared key: nothing on the network sends frames for a source that
    /// is not a player's microphone, so the server is the only producer.
    pub fn source_audio(&self, source: Uuid, sequence_number: i64, frame: &[u8]) {
        self.commands.push(Command::SourceAudio {
            source,
            sequence_number,
            frame: frame.to_vec(),
        });
    }

    /// `/vmute`: the player's audio stops reaching anyone and every client is
    /// told `muted`, which is the icon `HIDE_SERVER_MUTED` hides. `None` for
    /// `duration` is a permanent mute, as `permanent` is in Java's
    /// `/vmute <player> [duration] [reason]`.
    ///
    /// The mute belongs to the player, not to the session: a muted player who
    /// reconnects is still muted, as `MuteStorage` keeps it in Java.
    pub fn mute(
        &self,
        player: Uuid,
        duration: Option<MuteDuration>,
        reason: Option<&str>,
        silent: bool,
    ) {
        self.commands.push(Command::Mute {
            player,
            duration,
            reason: reason.map(str::to_owned),
            silent,
        });
    }

    /// `/vunmute`: the mute is lifted and the player can be heard again.
    pub fn unmute(&self, player: Uuid) {
        self.commands.push(Command::Unmute { player });
    }

    /// A new shared AES key, without a restart: every configured session is
    /// handed a fresh `ConfigPacket` with it, so clients pick it up on their
    /// next frame, and every session after this one starts on it. `voice-key`
    /// changed in `server.properties` is what a server calls this from.
    pub fn rotate_key(&self, key: [u8; 16]) {
        self.commands.push(Command::Key(key));
    }

    /// Every event waiting, without blocking. `limit` bounds one call, so a
    /// burst cannot stretch a tick; the rest arrives on the next one.
    pub fn drain(&self, limit: usize) -> Vec<Event> {
        self.events.drain(limit)
    }

    /// How many commands and events a full queue threw away so far, for the
    /// log: a number that only moves when the game is far behind the relay.
    pub fn dropped(&self) -> (u64, u64) {
        (self.commands.dropped(), self.events.dropped())
    }

    /// Stops the thread and waits for it: the socket is closed when this
    /// returns. [`Drop`] does not wait, so closing a world on the tick never
    /// stalls it.
    pub fn shutdown(mut self) {
        self.commands.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // Closing rather than sending a `Shutdown` command: the queue may be
        // full, and a stop must not be the thing that gets dropped.
        self.commands.close();
        // Deliberately no `join`: the thread wakes from the condvar at once
        // and exits on its own, and a tick is not held for it.
    }
}

/// What the game sends to the relay thread.
#[derive(Debug)]
pub(crate) enum Command {
    Join {
        player: Uuid,
        name: String,
    },
    Leave {
        player: Uuid,
    },
    Channel {
        player: Uuid,
        data: Vec<u8>,
    },
    Positions(Vec<Position>),
    Sources(Vec<Source>),
    SourceAudio {
        source: Uuid,
        sequence_number: i64,
        frame: Vec<u8>,
    },
    Mute {
        player: Uuid,
        duration: Option<MuteDuration>,
        reason: Option<String>,
        silent: bool,
    },
    Unmute {
        player: Uuid,
    },
    Key([u8; 16]),
}

/// The queue between the tick and the relay thread, bounded.
///
/// `std::sync::mpsc` is unbounded, so a relay thread that falls behind would
/// grow the game's memory by every tick it missed. The policy is drop-oldest,
/// and positions coalesce on the way in: a snapshot supersedes the one before
/// it, so a hundred ticks of positions leave one entry, and a burst of channel
/// packets keeps the newest of them rather than the oldest.
pub(crate) struct Commands {
    inner: Mutex<CommandsInner>,
    ready: Condvar,
    capacity: usize,
}

struct CommandsInner {
    items: VecDeque<Command>,
    closed: bool,
    dropped: u64,
}

impl Commands {
    pub(crate) fn new(capacity: usize) -> Commands {
        Commands {
            inner: Mutex::new(CommandsInner {
                items: VecDeque::with_capacity(capacity.min(64)),
                closed: false,
                dropped: 0,
            }),
            ready: Condvar::new(),
            // A queue shorter than a tick's worth of calls would drop control
            // packets under normal load; eight is the floor.
            capacity: capacity.max(8),
        }
    }

    pub(crate) fn push(&self, command: Command) {
        let mut inner = lock(&self.inner);
        if inner.closed {
            return;
        }
        if matches!(command, Command::Positions(_)) {
            if let Some(slot) = inner
                .items
                .iter_mut()
                .find(|queued| matches!(queued, Command::Positions(_)))
            {
                *slot = command;
                drop(inner);
                self.ready.notify_one();
                return;
            }
        }
        // The sources are a snapshot of their own, coalesced the same way: a
        // newer list of what is audible replaces the one before it.
        if matches!(command, Command::Sources(_)) {
            if let Some(slot) = inner
                .items
                .iter_mut()
                .find(|queued| matches!(queued, Command::Sources(_)))
            {
                *slot = command;
                drop(inner);
                self.ready.notify_one();
                return;
            }
        }
        // Full: the oldest goes. For a burst that is the packet whose turn has
        // passed; a stale snapshot is the one the arriving `Positions`
        // supersedes anyway.
        while inner.items.len() >= self.capacity {
            inner.items.pop_front();
            inner.dropped += 1;
        }
        inner.items.push_back(command);
        drop(inner);
        self.ready.notify_one();
    }

    /// Waits up to `timeout` for a command, so an idle relay thread sleeps
    /// instead of spinning between two empty polls.
    fn pop(&self, timeout: Duration) -> Option<Command> {
        let mut inner = lock(&self.inner);
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(command) = inner.items.pop_front() {
                return Some(command);
            }
            if inner.closed {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let waited = self.ready.wait_timeout(inner, deadline - now);
            let (guard, _) = match waited {
                Ok(waited) => waited,
                Err(poisoned) => poisoned.into_inner(),
            };
            inner = guard;
        }
    }

    pub(crate) fn try_pop(&self) -> Option<Command> {
        lock(&self.inner).items.pop_front()
    }

    fn close(&self) {
        let mut inner = lock(&self.inner);
        inner.closed = true;
        drop(inner);
        self.ready.notify_all();
    }

    fn is_closed(&self) -> bool {
        lock(&self.inner).closed
    }

    pub(crate) fn dropped(&self) -> u64 {
        lock(&self.inner).dropped
    }
}

/// What the relay sends back to the game, bounded the same way: the oldest
/// event goes when it is full.
struct Events {
    inner: Mutex<EventsInner>,
    capacity: usize,
}

struct EventsInner {
    items: VecDeque<Event>,
    dropped: u64,
}

impl Events {
    fn new(capacity: usize) -> Events {
        Events {
            inner: Mutex::new(EventsInner {
                items: VecDeque::with_capacity(capacity.min(64)),
                dropped: 0,
            }),
            capacity: capacity.max(8),
        }
    }

    fn push(&self, event: Event) {
        let mut inner = lock(&self.inner);
        while inner.items.len() >= self.capacity {
            inner.items.pop_front();
            inner.dropped += 1;
        }
        inner.items.push_back(event);
    }

    fn drain(&self, limit: usize) -> Vec<Event> {
        let mut inner = lock(&self.inner);
        let take = limit.min(inner.items.len());
        inner.items.drain(..take).collect()
    }

    fn dropped(&self) -> u64 {
        lock(&self.inner).dropped
    }
}

/// A poisoned lock is not a reason to take the server down: the state behind
/// it is a queue, and the worst a torn push could do is lose one packet.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The relay thread's own state.
/// A server mute: the player's audio is not relayed and their record says
/// `muted`, which is what a client shows as the muted-speaker icon.
struct Mute {
    /// `None` is permanent; a temporary mute is lifted by [`Worker::sweep`]
    /// once this passes (`VoiceMuteManager.tick`).
    until: Option<Instant>,
    /// The same end as unix milliseconds, `0` for never: what
    /// `voice_mutes.json` stores as `mutedToTime`.
    until_unix: u64,
    /// `mutedAtTime`.
    muted_at: u64,
    reason: Option<String>,
    /// `silent`: the player was not told (`notifications.muted` was off).
    silent: bool,
}

/// Unix milliseconds, the clock `voice_mutes.json` is written with.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

/// Writes `voice_mutes.json` off the relay thread: a disk that stalls must not
/// stall the audio. Only the newest snapshot matters — two mutes in a row
/// leave one write to do — so a newer one replaces a pending one.
struct Saver {
    pending: Arc<(Mutex<Option<Vec<StoredMute>>>, Condvar)>,
    path: PathBuf,
}

impl Saver {
    fn start(path: PathBuf, events: Arc<Events>) -> Saver {
        let pending: Arc<(Mutex<Option<Vec<StoredMute>>>, Condvar)> =
            Arc::new((Mutex::new(None), Condvar::new()));
        let slot = Arc::clone(&pending);
        let written = path.clone();
        let _ = thread::Builder::new()
            .name("horizon-voice-mutes".into())
            .spawn(move || {
                let (lock, ready) = &*slot;
                loop {
                    let batch = {
                        let mut guard = match lock.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        // A timeout rather than a plain `wait`: a lost wake-up
                        // would leave the file stale forever.
                        if guard.is_none() {
                            let (next, _) = match ready.wait_timeout(guard, IDLE) {
                                Ok(pair) => pair,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            guard = next;
                        }
                        guard.take()
                    };
                    let Some(batch) = batch else {
                        continue;
                    };
                    if let Err(error) = mutes::save(&written, &batch) {
                        events.push(Event::Log {
                            level: Level::Warn,
                            message: format!(
                                "voice: could not write {}: {error}",
                                written.display()
                            ),
                        });
                    }
                }
            });
        Saver { pending, path }
    }

    fn save(&self, mutes: Vec<StoredMute>) {
        let (lock, ready) = &*self.pending;
        let mut guard = match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(mutes);
        drop(guard);
        ready.notify_one();
    }
}

struct Worker {
    socket: UdpSocket,
    config: Config,
    events: Arc<Events>,
    sessions: HashMap<Uuid, Session>,
    /// Secret to player: the header's index into `sessions`.
    by_secret: HashMap<Uuid, Uuid>,
    positions: HashMap<Uuid, Position>,
    /// Blocks and entities the server wants heard, by the id in their record.
    sources: HashMap<Uuid, Source>,
    /// Players the server muted (`/vmute`). Beside the sessions rather than in
    /// them: Java's `MuteStorage` is per player, so a muted player who
    /// reconnects stays muted.
    mutes: HashMap<Uuid, Mute>,
    /// The `voice_mutes.json` writer, when the owner keeps mutes in a file.
    saver: Option<Saver>,
    /// The strings a `LanguageRequest` is answered with, Java's
    /// `languages/*.toml` merged over the two this relay ships. Shared with
    /// the game, which renders its own messages from the `[server]` scope.
    catalogue: Arc<Catalogue>,
    /// The shared AES key: handed to every client, and used here only to seal
    /// the frames of a source the server itself feeds.
    key: [u8; 16],
    cipher: Cipher,
    server_id: Uuid,
    /// One datagram's bytes, reused for every listener of every frame.
    datagram: Vec<u8>,
    /// The listeners of the frame being forwarded, reused the same way.
    listeners: Vec<(SocketAddr, Uuid)>,
    address: SocketAddr,
    last_sweep: Instant,
    /// Kinds of refusal already in the log: a flood is thousands of the same
    /// line a second otherwise.
    warned: HashSet<&'static str>,
    stopped: bool,
}

impl Worker {
    fn new(socket: UdpSocket, config: Config, events: Arc<Events>, key: [u8; 16]) -> Self {
        let address = socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        Worker {
            socket,
            config,
            events,
            sessions: HashMap::new(),
            by_secret: HashMap::new(),
            mutes: HashMap::new(),
            saver: None,
            // Replaced by `Relay::start` once the folder is read; a worker
            // built without one still answers the built-in strings.
            catalogue: Arc::new(Catalogue::builtin()),
            positions: HashMap::new(),
            sources: HashMap::new(),
            cipher: Cipher::new(key),
            key,
            server_id: pv_proto::name_uuid("horizon:voice"),
            datagram: Vec::with_capacity(DATAGRAM),
            listeners: Vec::with_capacity(32),
            address,
            last_sweep: Instant::now(),
            warned: HashSet::new(),
            stopped: false,
        }
    }

    fn run(&mut self, commands: &Commands) {
        self.log(
            Level::Info,
            format!("voice: relay listening on {} (udp)", self.address),
        );
        let mut buffer = [0u8; DATAGRAM];
        while !self.stopped {
            let mut taken = 0;
            while taken < PER_PASS {
                let Some(command) = commands.try_pop() else {
                    break;
                };
                taken += 1;
                self.command(command);
            }

            let mut heard = false;
            for _ in 0..PER_PASS {
                match self.socket.recv_from(&mut buffer) {
                    Ok((size, from)) => {
                        heard = true;
                        self.datagram(&buffer[..size], from);
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    // The read timeout: nothing waiting, so look at the clock.
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(error) => {
                        // Windows reports an ICMP port unreachable from a peer
                        // that has gone as `WSAECONNRESET` on the next read.
                        // Nothing is broken — the session that owned the port
                        // is what the sweep notices — and logging it once per
                        // dead peer is noise.
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                        ) {
                            continue;
                        }
                        self.log(Level::Warn, format!("voice: udp read: {error}"));
                        break;
                    }
                }
            }

            // Nothing to do either way: wait for a command instead of
            // spinning, and wake at least every `IDLE` to read the socket
            // again. A moving microphone keeps `heard` true, so audio never
            // waits on this.
            if !heard && taken == 0 {
                if let Some(command) = commands.pop(IDLE) {
                    self.command(command);
                }
            }

            if commands.is_closed() {
                self.stopped = true;
            }
            let now = Instant::now();
            self.keepalive(now);
            if self.last_sweep.elapsed() >= SWEEP {
                self.sweep(now);
            }
        }
        // The file is left as it is now: the writer thread may not have got to
        // the last change, and a stop is not a place to lose a mute.
        if let Some(saver) = &self.saver {
            if let Err(error) = mutes::save(&saver.path, &self.stored_mutes()) {
                self.log(
                    Level::Warn,
                    format!("voice: could not write {}: {error}", saver.path.display()),
                );
            }
        }
        self.log(Level::Info, "voice: relay stopped".into());
    }

    // ---------------------------------------------------------------- control

    fn command(&mut self, command: Command) {
        match command {
            Command::Join { player, name } => self.join(player, &name),
            Command::Leave { player } => self.leave(player),
            Command::Channel { player, data } => self.channel(player, &data),
            Command::Positions(positions) => {
                self.positions.clear();
                self.positions
                    .extend(positions.into_iter().map(|p| (p.player, p)));
            }
            Command::Sources(sources) => {
                self.sources.clear();
                self.sources
                    .extend(sources.into_iter().map(|s| (s.info.id, s)));
            }
            Command::SourceAudio {
                source,
                sequence_number,
                frame,
            } => self.source_audio(source, sequence_number, &frame),
            Command::Mute {
                player,
                duration,
                reason,
                silent,
            } => self.mute(player, duration, reason, silent),
            // `/vunmute` is never silent itself: whether the player is told is
            // `notifications.unmuted`, which the game applies (`silent` here
            // is the mute's own, which an expiry keeps and a command does not).
            Command::Unmute { player } => self.unmute(player, false),
            Command::Key(key) => self.rotate(key),
        }
    }

    /// `VoiceMuteManager.mute`: the mute is stored, everyone is told the new
    /// state, and the game is asked to tell the player (the message is the
    /// game's, because it is Minecraft chat, not a voice packet).
    fn mute(
        &mut self,
        player: Uuid,
        duration: Option<MuteDuration>,
        reason: Option<String>,
        silent: bool,
    ) {
        let now = Instant::now();
        let unix = now_unix();
        let length = duration
            .map(|duration| duration.length())
            .filter(|length| !length.is_zero());
        // `0s` is permanent in Java too: `duration > 0` fails there.
        let until = length.map(|length| now + length);
        let until_unix = length.map_or(0, |length| unix.saturating_add(length.as_millis() as u64));
        let name = self
            .sessions
            .get(&player)
            .map(|session| session.name.clone())
            .unwrap_or_default();
        self.mutes.insert(
            player,
            Mute {
                until,
                until_unix,
                muted_at: unix,
                reason: reason.clone(),
                silent,
            },
        );
        self.broadcast_info(player);
        self.log(
            Level::Info,
            match &reason {
                Some(reason) => format!("voice: {name} muted by the server ({reason})"),
                None => format!("voice: {name} muted by the server"),
            },
        );
        self.events.push(Event::Mute {
            player,
            name,
            muted: true,
            duration,
            until: length.map(|_| until_unix),
            reason,
            silent,
        });
        self.save_mutes();
    }

    /// `VoiceMuteManager.unmute`: only a player who was muted changes
    /// anything, so an `unmute` of a free player sends nothing.
    fn unmute(&mut self, player: Uuid, silent: bool) {
        let Some(mute) = self.mutes.remove(&player) else {
            return;
        };
        let name = self
            .sessions
            .get(&player)
            .map(|session| session.name.clone())
            .unwrap_or_default();
        self.broadcast_info(player);
        // An unmute can be for a player who is not online (a mute read back
        // from the file, lifted by `/vunmute <uuid>`): the session table has no
        // name for them, so the line does without one.
        self.log(
            Level::Info,
            if name.is_empty() {
                "voice: unmuted".to_owned()
            } else {
                format!("voice: {name} unmuted")
            },
        );
        self.events.push(Event::Mute {
            player,
            name,
            muted: false,
            duration: None,
            until: None,
            reason: mute.reason,
            silent,
        });
        self.save_mutes();
    }

    /// The mutes read from `voice_mutes.json` at start: the expired ones are
    /// dropped (as `JsonMuteStorage.init` drops them) and every other one is
    /// announced to the game, so its own `/vmutelist` knows them before a
    /// player has joined.
    fn restore(&mut self, stored: Vec<StoredMute>) {
        let unix = now_unix();
        let mut expired = false;
        for mute in stored {
            if !mute.valid(unix) {
                expired = true;
                continue;
            }
            let left = mute.until.saturating_sub(unix);
            let until = (mute.until != 0).then(|| Instant::now() + Duration::from_millis(left));
            let duration = (mute.until != 0).then(|| MuteDuration {
                // The file holds an end, not a length; the notice says how much
                // of it is left, where Java prints the date.
                unit: MuteUnit::Seconds,
                amount: left.div_ceil(1_000).max(1),
            });
            self.mutes.insert(
                mute.player,
                Mute {
                    until,
                    until_unix: mute.until,
                    muted_at: mute.muted_at,
                    reason: mute.reason.clone(),
                    silent: mute.silent,
                },
            );
            self.events.push(Event::Mute {
                player: mute.player,
                // Names are not in the file; the game fills this in when the
                // player joins.
                name: String::new(),
                muted: true,
                duration,
                until: (mute.until != 0).then_some(mute.until),
                reason: mute.reason,
                silent: mute.silent,
            });
        }
        // A file with a mute that ran out while the server was down is written
        // back without it, as `JsonMuteStorage.init` does.
        if expired {
            self.save_mutes();
        }
    }

    /// The file's view of the mutes: every mute, as `JsonMuteStorage.save`
    /// writes them.
    fn stored_mutes(&self) -> Vec<StoredMute> {
        let mut stored: Vec<StoredMute> = self
            .mutes
            .iter()
            .map(|(player, mute)| StoredMute {
                player: *player,
                muted_at: mute.muted_at,
                until: mute.until_unix,
                reason: mute.reason.clone(),
                silent: mute.silent,
            })
            .collect();
        // Stable output: the file is read by a human as much as by the plugin.
        stored.sort_by_key(|mute| mute.player);
        stored
    }

    /// Hands the mutes to the writer thread; a server without a file does
    /// nothing here.
    fn save_mutes(&self) {
        if let Some(saver) = &self.saver {
            saver.save(self.stored_mutes());
        }
    }

    /// `PacketTcpManager.broadcastPlayerInfoUpdate`: everyone who is
    /// configured gets the player's new record, which is where the muted icon
    /// comes from.
    fn broadcast_info(&self, player: Uuid) {
        let Some(session) = self.sessions.get(&player) else {
            return;
        };
        let info = self.info(session);
        for other in self.sessions.values().filter(|s| s.configured) {
            self.send_control(
                other.player,
                &TcpPacket::PlayerInfoUpdate {
                    player: info.clone(),
                },
            );
        }
    }

    /// Whether the server muted this player (`/vmute`), which is what the
    /// `muted` flag of a `VoicePlayerInfo` means — not the client's own
    /// microphone switch.
    fn muted(&self, player: Uuid) -> bool {
        self.mutes.contains_key(&player)
    }

    /// The record `PlayerListPacket`, `PlayerInfoUpdatePacket` and the
    /// `PLAYER` source describe the player with.
    fn info(&self, session: &Session) -> VoicePlayerInfo {
        session.info(self.muted(session.player))
    }

    fn join(&mut self, player: Uuid, name: &str) {
        if self.sessions.contains_key(&player) {
            return;
        }
        if self.sessions.len() >= self.config.max_sessions {
            self.log(
                Level::Warn,
                format!(
                    "voice: {name} not admitted, {} sessions",
                    self.config.max_sessions
                ),
            );
            return;
        }
        let now = Instant::now();
        let secret = crate::secret();
        let mut session = Session::new(player, name, secret, now);
        session.asked(now);
        // `ModRequiredKickHandler.handlePlayerJoin`: the clock starts with the
        // join, and the first packet the player sends stops it.
        if self.config.client_mod_required {
            session.expect_answer(now, self.config.client_mod_required_check);
        }
        self.sessions.insert(player, session);
        self.by_secret.insert(secret, player);
        // `PlayerInfoRequestScheduler`: the server asks first, and a client
        // that answers with a real key is the only way a session starts.
        self.send_control(player, &TcpPacket::PlayerInfoRequest);
        self.log(
            Level::Info,
            format!("voice: {name} joined the voice server"),
        );
    }

    fn leave(&mut self, player: Uuid) {
        let Some(session) = self.sessions.remove(&player) else {
            return;
        };
        self.by_secret.remove(&session.secret);
        self.positions.remove(&player);
        self.log(
            Level::Info,
            format!("voice: {} left the voice server", session.name),
        );
        for other in self.sessions.values() {
            self.send_control(
                other.player,
                &TcpPacket::PlayerDisconnect { player_id: player },
            );
        }
    }

    /// A `plasmo:voice/v2` payload: one control packet, or several.
    fn channel(&mut self, player: Uuid, data: &[u8]) {
        let Some(session) = self.sessions.get(&player) else {
            return;
        };
        let name = session.name.clone();
        let packets = match TcpPacket::decode_all(data) {
            Ok(packets) => packets,
            Err(error) => {
                self.log(
                    Level::Warn,
                    format!("voice: {name} sent a channel payload that was refused: {error}"),
                );
                return;
            }
        };
        // Any control packet counts as the mod's answer: Java cancels the kick
        // on `TcpPacketReceivedEvent`, whatever the packet was.
        if let Some(session) = self.sessions.get_mut(&player) {
            session.settle_check();
        }
        for packet in packets {
            self.control(player, packet);
        }
    }

    fn control(&mut self, player: Uuid, packet: TcpPacket) {
        match packet {
            // The answer to our request: a real X.509 key, or the session
            // never gets a config.
            TcpPacket::PlayerInfo {
                voice_disabled,
                microphone_muted,
                version,
                public_key,
                ..
            } => {
                // `clientModMinVersion`: an old client is never configured.
                // Java does not kick it either; it simply never gets a voice
                // session, and the log says which version it runs.
                if let Some(false) =
                    Self::version_at_least(&version, &self.config.client_mod_min_version)
                {
                    let name = self
                        .sessions
                        .get(&player)
                        .map(|session| session.name.clone())
                        .unwrap_or_default();
                    self.log(
                        Level::Warn,
                        format!(
                            "voice: {name} runs PlasmoVoice {version}, older than {}; not configured",
                            self.config.client_mod_min_version
                        ),
                    );
                    return;
                }
                let key = match RsaPublicKey::from_public_key_der(&public_key) {
                    Ok(key) => key,
                    Err(error) => {
                        self.log(
                            Level::Warn,
                            format!("voice: a public key that is not RSA/X.509: {error}"),
                        );
                        return;
                    }
                };
                // A second `PlayerInfo` from a session that already has a key
                // is a re-key: the client lost its config, or its socket, and
                // is starting over on the same Minecraft connection. A fresh
                // secret is what makes that safe — datagrams sealed with the
                // old one stop reaching anyone, and the new `ConnectionPacket`
                // tells the client what to seal with now.
                let (secret, name, reconfigured) = {
                    let Some(session) = self.sessions.get_mut(&player) else {
                        return;
                    };
                    let old = session.secret;
                    let reconfigured = session.key.is_some();
                    let secret = if reconfigured {
                        let fresh = crate::secret();
                        self.by_secret.remove(&old);
                        fresh
                    } else {
                        old
                    };
                    session.key = Some(key);
                    session.secret = secret;
                    session.muted = microphone_muted;
                    session.voice_disabled = voice_disabled;
                    // The config has to be handed out again for the new key.
                    session.configured = false;
                    (secret, session.name.clone(), reconfigured)
                };
                self.by_secret.insert(secret, player);
                if reconfigured {
                    self.log(
                        Level::Info,
                        format!("voice: {name} re-keyed, a new secret was issued"),
                    );
                }
                // `ConnectionPacket`: the secret and where to send audio. The
                // config follows the first datagram, as the Java server does.
                let connection = TcpPacket::Connection {
                    secret,
                    // `NettyUdpClient.connect`: a client replaces "0.0.0.0" with
                    // the Minecraft server's own host and connects to anything
                    // else as it stands. Sending no ip at all (empty, which is
                    // what `HORIZON_VOICE_IP` defaults to) would make the Java
                    // client resolve it to its own loopback and never reach a
                    // server on another machine; "0.0.0.0" is the spelling
                    // `ServerConfig.Host.ip` uses for "whatever the client used".
                    ip: if self.config.announce_ip.is_empty() {
                        "0.0.0.0".to_string()
                    } else {
                        self.config.announce_ip.clone()
                    },
                    port: i32::from(self.address.port()),
                };
                self.send_control(player, &connection);
            }
            TcpPacket::PlayerState {
                voice_disabled,
                microphone_muted,
            } => {
                let muted = self.muted(player);
                let Some(session) = self.sessions.get_mut(&player) else {
                    return;
                };
                session.voice_disabled = voice_disabled;
                session.muted = microphone_muted;
                let info = session.info(muted);
                for other in self.sessions.values().filter(|s| s.player != player) {
                    self.send_control(
                        other.player,
                        &TcpPacket::PlayerInfoUpdate {
                            player: info.clone(),
                        },
                    );
                }
            }
            TcpPacket::PlayerActivationDistances { distances } => {
                if let Some(session) = self.sessions.get_mut(&player) {
                    session.distances = distances;
                }
            }
            // The burst ended: the listeners' speaker icons fade.
            TcpPacket::PlayerAudioEnd {
                sequence_number, ..
            } => {
                for other in self.sessions.values().filter(|s| s.player != player) {
                    self.send_control(
                        other.player,
                        &TcpPacket::SourceAudioEnd {
                            source_id: player,
                            sequence_number,
                        },
                    );
                }
            }
            // `SourceInfoRequestPacket`: who is behind this source. A player's
            // record is made here from the session; a block's or an entity's
            // is the one the server registered, its own tail included.
            TcpPacket::SourceInfoRequest { source_id } => {
                let record = match self.sessions.get(&source_id) {
                    Some(source) => self.player_source(source),
                    None => match self.sources.get(&source_id) {
                        Some(source) => source.info.clone(),
                        // Unknown: the client asks once and stops.
                        None => return,
                    },
                };
                self.send_control(player, &TcpPacket::SourceInfo { source: record });
            }
            // `PlayerChannelHandler.handle(LanguageRequestPacket)` →
            // `sendLanguage`: the name echoed back is the one the client asked
            // for (`requestedLanguage`, or the server's default when it asked
            // for nothing). `forcedLanguage` changes the strings, never the
            // name — Java sends `requestedLanguage` there too. The strings are
            // the `[client]` scope of `languages/<name>.toml`, flattened into
            // the dotted keys the mod looks up: a key the client's own
            // resource pack has stays the client's (Java's translator only
            // fills what is missing), so the file is how a server renames what
            // it names itself.
            TcpPacket::LanguageRequest { language } => {
                let requested = if language.trim().is_empty() {
                    self.config.default_language.clone()
                } else {
                    language
                };
                let strings = self.catalogue.client(
                    &requested,
                    &self.config.default_language,
                    self.config.forced_language.as_deref(),
                );
                self.send_control(
                    player,
                    &TcpPacket::Language {
                        name: requested,
                        language: strings,
                    },
                );
            }
            // `PlayerList`/`ActivationRegister`/`SourceLineRegister` and the
            // rest are the server's to send; from a client they mean nothing.
            _ => {}
        }
    }

    /// The config a client gets once it has spoken on UDP: the shared key
    /// wrapped with its own RSA key, the proximity activation and the main
    /// source line.
    fn config_for(&self, session: &Session) -> Option<VoiceConfig> {
        let key = session.key.as_ref()?;
        let mut random = rsa::rand_core::OsRng;
        let data = match key.encrypt(&mut random, Pkcs1v15Encrypt, &self.key) {
            Ok(data) => data,
            Err(error) => {
                self.log(Level::Warn, format!("voice: rsa: {error}"));
                return None;
            }
        };
        Some(VoiceConfig {
            server_id: self.server_id,
            capture: CaptureInfo {
                sample_rate: self.config.sample_rate,
                mtu_size: self.config.mtu,
                encoder: Some(CodecInfo {
                    name: "opus".into(),
                    // `VoiceTcpServerConnectionManager.sendConfigInfo`: the mode
                    // and the bitrate from `[voice.opus]`, and nothing else.
                    params: vec![
                        ("mode".into(), self.config.opus_mode.clone()),
                        ("bitrate".into(), self.config.opus_bitrate.to_string()),
                    ],
                }),
            },
            encryption: Some(EncryptionInfo {
                algorithm: "AES/CBC/PKCS5Padding".into(),
                data,
            }),
            // `ProximityServerActivation.register`: Java builds one source
            // line, the proximity one, with the speaker icon. The icon is the
            // full resource location, not a short name: a client parses it as
            // it is (`HudIconRenderer`), and anything it cannot resolve is
            // drawn as Minecraft's missing-texture checkerboard.
            source_lines: vec![VoiceSourceLine {
                name: PROXIMITY_NAME.into(),
                translation: "pv.activation.proximity".into(),
                icon: SOURCE_LINE_ICON.into(),
                default_volume: 1.0,
                weight: 1,
                id: source_line_id(PROXIMITY_NAME),
                players: None,
            }],
            activations: vec![VoiceActivation {
                name: PROXIMITY_NAME.into(),
                translation: "pv.activation.proximity".into(),
                icon: ACTIVATION_ICON.into(),
                id: VoiceActivation::proximity_id(),
                // `proximity.distances`, already sorted and cut at the server's
                // cap by `VoiceSettings::offered_distances`.
                distances: self.config.distances.clone(),
                // `validateDefaultDistance`: a default the list does not hold
                // becomes one it does.
                default_distance: VoiceActivation::validated_default_distance(
                    &self.config.distances,
                    self.config.default_distance,
                ),
                proximity: true,
                // `ProximityServerActivation` sets both by hand; the builder's
                // defaults are the opposite.
                transitive: true,
                stereo_supported: false,
                encoder: None,
                weight: 1,
            }],
            // Everyone who can join may talk; a permission plugin would fill
            // this in.
            permissions: vec![("pv.activate".into(), true)],
            // `playerIcon`: which icons a client hides and how high they sit.
            // `None` is a 2.1.6 server; 2.1.7+ always sends it.
            player_icon: Some(PlayerIconConfig {
                visibility: self.config.player_icon_visibility.clone(),
                offset: Pos3d {
                    x: 0.0,
                    y: self.config.player_icon_y_offset,
                    z: 0.0,
                },
            }),
        })
    }

    // ------------------------------------------------------------------- udp

    fn datagram(&mut self, bytes: &[u8], from: SocketAddr) {
        // The cap comes before the decode, so a flood of oversized datagrams
        // costs one comparison each rather than an allocation and a parse.
        let cap = self.config.max_datagram_bytes.min(DATAGRAM);
        if bytes.len() > cap {
            self.refuse(
                "oversized",
                format!(
                    "voice: dropped a {}-byte datagram from {from}; the cap is {cap}",
                    bytes.len()
                ),
            );
            return;
        }
        let packet = match UdpPacket::decode(bytes) {
            Ok(packet) => packet,
            // Not ours, or a version this build does not read: dropped, as the
            // Java codec drops it before it reaches a handler.
            Err(_) => return,
        };
        let Some(player) = self.by_secret.get(&packet.secret).copied() else {
            return;
        };

        let now = Instant::now();
        let rate = self.config.datagrams_per_second;
        let over = {
            let Some(session) = self.sessions.get_mut(&player) else {
                return;
            };
            // Every datagram keeps the session alive, audio included: a client
            // that talks without pinging is not a client that left.
            session.touch(now, from);
            if rate == 0 || session.spend(now, rate) {
                None
            } else {
                Some((session.name.clone(), session.flooded))
            }
        };
        if let Some((name, refused)) = over {
            self.refuse(
                "flood",
                format!(
                    "voice: {name} is over {rate} datagrams a second; dropping (frame {refused})"
                ),
            );
            return;
        }

        match packet.body {
            // A client's ping: the session was touched above, which is all a
            // ping means. Java answers nothing —
            // `NettyUdpServerConnection.handle(PingPacket)` only records the
            // time — and that is not laziness: both clients answer a ping they
            // receive, so an answer to an answer would ping-pong until the
            // datagram rate limit started dropping real audio.
            UdpBody::Ping { .. } => {
                let Some(session) = self.sessions.get(&player) else {
                    return;
                };
                let configured = session.configured;
                if !configured {
                    self.configure(player);
                }
            }
            UdpBody::PlayerAudio {
                sequence_number,
                data,
                distance,
                activation_id,
                ..
            } => self.audio(player, sequence_number, &data, distance, activation_id),
            // Only a server sends these; from a client they are noise.
            UdpBody::SourceAudio { .. } | UdpBody::SelfAudio { .. } | UdpBody::Custom { .. } => {}
        }
    }

    /// `VoiceTcpServerConnectionManager.sendConfigInfo`, once the client's
    /// socket is known to work.
    fn configure(&mut self, player: Uuid) {
        let Some(session) = self.sessions.get(&player) else {
            return;
        };
        let Some(config) = self.config_for(session) else {
            return;
        };
        let name = session.name.clone();
        self.send_control(player, &TcpPacket::Config(Box::new(config)));
        // The list of who is talking, which the mod's menu shows. It goes in a
        // payload of its own: `ConfigPacket`'s reader treats anything after it
        // as the optional `playerIconConfig` (2.1.7+), so a `PlayerListPacket`
        // appended to the same payload would be read as an icon config and the
        // packet would fail.
        let players: Vec<VoicePlayerInfo> = self.sessions.values().map(|s| self.info(s)).collect();
        self.send_control(player, &TcpPacket::PlayerList { players });
        if let Some(session) = self.sessions.get_mut(&player) {
            session.configured = true;
        }

        // `VoiceServerPlayerSource`: a listener learns a speaker's record
        // before the first frame. The Java client drops `SourceAudioPacket`
        // whose id it has no source for, so without this a Java client hears
        // nobody, however loud the relay is.
        let peers: Vec<SourceInfo> = self
            .sessions
            .values()
            .filter(|other| other.player != player)
            .map(|other| self.player_source(other))
            .collect();
        for record in peers {
            self.send_control(player, &TcpPacket::SourceInfo { source: record });
        }
        if let Some(mine) = self.sessions.get(&player).map(|s| self.player_source(s)) {
            for other in self.sessions.values() {
                if other.player != player && other.configured {
                    self.send_control(
                        other.player,
                        &TcpPacket::SourceInfo {
                            source: mine.clone(),
                        },
                    );
                }
            }
        }
        self.log(Level::Info, format!("voice: {name} is configured"));
    }

    /// The record a `PLAYER` source is described with: `PlayerSourceInfo`,
    /// which is the session itself plus the main line.
    fn player_source(&self, session: &Session) -> SourceInfo {
        SourceInfo {
            kind: "PLAYER".into(),
            addon_id: "plasmo:voice".into(),
            id: session.player,
            name: Some(session.name.clone()),
            // `BaseServerAudioSource.state` starts at 1 (created), and the
            // audio frames carry it as `source_state`.
            state: 1,
            decoder: Some(CodecInfo {
                name: "opus".into(),
                params: Vec::new(),
            }),
            stereo: false,
            line_id: source_line_id(PROXIMITY_NAME),
            icon_visible: true,
            angle: 0,
            player: Some(self.info(session)),
            extra: Vec::new(),
        }
    }

    /// `PlayerAudioPacket` to everyone close enough: the sealed payload is
    /// copied as it is and only the 16-byte secret is rewritten per listener.
    fn audio(
        &mut self,
        player: Uuid,
        sequence_number: i64,
        data: &[u8],
        distance: i16,
        activation_id: Uuid,
    ) {
        let Some(session) = self.sessions.get(&player) else {
            return;
        };
        // A server mute (`/vmute`) is the server's decision, so it comes first
        // and is checked against the player rather than the session: Java's
        // `VoiceServerProximitySource` drops the frame of a muted speaker.
        if session.muted || session.voice_disabled || !session.configured || self.muted(player) {
            return;
        }
        let secret = session.secret;

        // `SelfActivationHelper.sendAudioInfo`: the speaker is handed their own
        // frame (the payload only when the size changed) so their own source
        // knows the sequence number and the distance, and gets their record
        // again when they switch activation.
        let size_changed = session.sent_size != data.len();
        let record =
            (session.activation != Some(activation_id)).then(|| self.player_source(session));
        if let Some(session) = self.sessions.get_mut(&player) {
            session.sent_size = data.len();
            session.activation = Some(activation_id);
        }
        self.send_udp(
            secret,
            UdpPacket::now(
                secret,
                UdpBody::SelfAudio {
                    source_id: player,
                    sequence_number,
                    data: size_changed.then(|| data.to_vec()),
                    distance,
                },
            ),
        );
        if let Some(record) = record {
            self.send_control(
                player,
                &TcpPacket::SelfSourceInfo {
                    source: record,
                    player_id: player,
                    activation_id,
                    sequence_number,
                },
            );
        }

        let mut listeners = std::mem::take(&mut self.listeners);
        listeners.clear();
        if let Some(position) = self.positions.get(&player).copied() {
            self.fill_listeners(position.place(), player, distance, &mut listeners);
        }
        if listeners.is_empty() {
            self.listeners = listeners;
            if let Some(session) = self.sessions.get_mut(&player) {
                session.dropped += 1;
            }
            return;
        }

        let encoded = UdpPacket::now(
            secret,
            UdpBody::SourceAudio {
                sequence_number,
                data: data.to_vec(),
                source_id: player,
                source_state: 1,
                distance,
            },
        )
        .encode();

        self.datagram.clear();
        self.datagram.extend_from_slice(&encoded);
        for (address, listener) in &listeners {
            UdpPacket::replace_secret(&mut self.datagram, *listener);
            let _ = self.socket.send_to(&self.datagram, address);
        }
        self.listeners = listeners;
    }

    /// The sessions within an audio source's reach, in the same dimension,
    /// capped by `max_recipients`. `hears_self` is the player whose own
    /// microphone this is: they are not sent their own frame.
    ///
    /// `VoiceServerProximitySource.getListeners`: the reach is
    /// `min(distance + maxExtraAudioBroadcastDistance, distance * 2)`. A
    /// distance of 0 or less is a source that is not placed in the world (a
    /// direct one): every session hears it.
    fn fill_listeners(
        &self,
        place: Place,
        hears_self: Uuid,
        distance: i16,
        out: &mut Vec<(SocketAddr, Uuid)>,
    ) {
        let reach = Self::listener_reach(distance, self.config.extra_broadcast_distance);
        let limit2 = reach * reach;

        for session in self.sessions.values() {
            if session.player == hears_self || !session.configured {
                continue;
            }
            let (Some(address), Some(position)) = (
                session.address,
                self.positions.get(&session.player).copied(),
            ) else {
                continue;
            };
            let listener = position.place();
            if listener.dimension != place.dimension {
                continue;
            }
            if distance > 0 && place.distance2(&listener) > limit2 {
                continue;
            }
            out.push((address, session.secret));
            if out.len() >= self.config.max_recipients {
                return;
            }
        }
    }

    /// `clientModMinVersion`'s check: dot-separated numbers, anything after a
    /// `-` or `+` ignored as a pre-release or build tag. `None` when either
    /// side is not a version at all, which is why a client that announces
    /// something else is let through rather than refused.
    fn version_at_least(version: &str, minimum: &str) -> Option<bool> {
        let parts = |text: &str| -> Option<Vec<u32>> {
            let release = text.trim().split(['-', '+']).next().unwrap_or(text);
            release
                .split('.')
                .map(|part| part.trim().parse::<u32>().ok())
                .collect()
        };
        let mut version = parts(version)?;
        let mut minimum = parts(minimum)?;
        while version.len() < minimum.len() {
            version.push(0);
        }
        while minimum.len() < version.len() {
            minimum.push(0);
        }
        Some(version >= minimum)
    }

    /// `min(distance + extra, distance * 2)`, squared here because every
    /// comparison is against a squared distance.
    fn listener_reach(distance: i16, extra: i32) -> f64 {
        let distance = i32::from(distance.max(0));
        let reach = (distance + extra.max(0)).min(distance * 2);
        f64::from(reach.clamp(0, i32::from(i16::MAX)))
    }

    /// A frame for a source that is not a microphone (`Relay::source_audio`):
    /// sealed with the shared key and sent to the sessions near the source.
    fn source_audio(&mut self, source: Uuid, sequence_number: i64, frame: &[u8]) {
        // An empty frame is a source that stopped; a source nobody registered
        // is a producer that outlived its announcement.
        let Some(registered) = self.sources.get(&source).cloned() else {
            return;
        };
        if frame.is_empty() {
            return;
        }

        let mut listeners = std::mem::take(&mut self.listeners);
        listeners.clear();
        self.fill_listeners(
            registered.place,
            source,
            registered.distance,
            &mut listeners,
        );
        if listeners.is_empty() {
            self.listeners = listeners;
            return;
        }

        // The relay is the producer's only client: no one else holds the key
        // with the frame, so it is sealed here, once, and copied as it is.
        // The secret in it is a placeholder: `replace_secret` rewrites it per
        // listener before the datagram goes out.
        let encoded = UdpPacket::now(
            [0u8; 16],
            UdpBody::SourceAudio {
                sequence_number,
                data: self.cipher.seal(frame),
                source_id: source,
                source_state: 1,
                distance: registered.distance,
            },
        )
        .encode();

        self.datagram.clear();
        self.datagram.extend_from_slice(&encoded);
        for (address, listener) in &listeners {
            UdpPacket::replace_secret(&mut self.datagram, *listener);
            let _ = self.socket.send_to(&self.datagram, address);
        }
        self.listeners = listeners;
    }

    /// A new shared key: handed out again, and used for everything sealed
    /// after it. Sessions that have not answered yet get it with the config
    /// their first datagram asks for anyway.
    fn rotate(&mut self, key: [u8; 16]) {
        self.key = key;
        self.cipher = Cipher::new(key);
        // The config, not the connection: the secret and the address stay,
        // and only the wrapped AES key changes, which is what a client reads
        // a second `ConfigPacket` for (`pv-client`'s `state.rs`).
        let players: Vec<Uuid> = self
            .sessions
            .values()
            .filter(|session| session.key.is_some())
            .map(|session| session.player)
            .collect();
        for player in &players {
            let config = self
                .sessions
                .get(player)
                .and_then(|session| self.config_for(session));
            let Some(config) = config else {
                continue;
            };
            self.send_control(*player, &TcpPacket::Config(Box::new(config)));
            if let Some(session) = self.sessions.get_mut(player) {
                session.configured = true;
            }
        }
        self.log(
            Level::Info,
            format!(
                "voice: key rotated, {} session(s) were handed the new key",
                players.len()
            ),
        );
    }

    fn send_udp(&self, secret: Uuid, packet: UdpPacket) {
        let bytes = packet.encode();
        if let Some(address) = self.address_of(secret) {
            let _ = self.socket.send_to(&bytes, address);
        }
    }

    fn address_of(&self, secret: Uuid) -> Option<SocketAddr> {
        let player = self.by_secret.get(&secret)?;
        self.sessions.get(player).and_then(|s| s.address)
    }

    // ---------------------------------------------------------------- upkeep

    /// `NettyUdpKeepAlive`: a ping to every session whose turn it is.
    ///
    /// A Java client pings only until its socket is up and then waits for
    /// these: the ping is the only thing that tells it the socket still works,
    /// and after seven seconds without one it calls itself timed out. Without
    /// this every Java player is dropped and re-keyed every fifteen seconds.
    ///
    /// Run on every pass of the loop rather than once a second: Java checks
    /// its schedule every 100 ms, and a one-second granularity on a 1.5 s
    /// schedule would put the gaps close to the client's own timeout.
    fn keepalive(&mut self, now: Instant) {
        let due: Vec<(Uuid, Uuid)> = self
            .sessions
            .values()
            .filter(|s| s.wants_ping(now))
            .map(|s| (s.player, s.secret))
            .collect();
        if due.is_empty() {
            return;
        }
        let time = pv_proto::now_millis();
        for (player, secret) in due {
            let wait = PING_FIRST + ping_jitter();
            if let Some(session) = self.sessions.get_mut(&player) {
                session.pinged(now, wait);
            }
            self.send_udp(
                secret,
                UdpPacket::now(
                    secret,
                    UdpBody::Ping {
                        time,
                        server_ip: None,
                        server_port: None,
                    },
                ),
            );
        }
    }

    /// Retries the key request and drops the sessions that went quiet.
    fn sweep(&mut self, now: Instant) {
        self.last_sweep = now;

        let due: Vec<Uuid> = self
            .sessions
            .values()
            .filter(|s| s.wants_request(now))
            .map(|s| s.player)
            .collect();
        for player in due {
            if let Some(session) = self.sessions.get_mut(&player) {
                session.asked(now);
            }
            self.send_control(player, &TcpPacket::PlayerInfoRequest);
        }

        // `clientModRequired`: a player whose check ran out without a single
        // control packet has no mod. Java kicks for that; who is spared is the
        // game's call (`pv.bypass_mod_requirement` spares an operator), so this
        // only reports it.
        let missing: Vec<(Uuid, String)> = self
            .sessions
            .values()
            .filter(|s| s.overdue(now))
            .map(|s| (s.player, s.name.clone()))
            .collect();
        for (player, name) in missing {
            if let Some(session) = self.sessions.get_mut(&player) {
                session.settle_check();
            }
            self.log(
                Level::Warn,
                format!(
                    "voice: {name} sent no PlasmoVoice packet in {:?} (voice-client-mod-required)",
                    self.config.client_mod_required_check
                ),
            );
            self.events.push(Event::ModMissing { player, name });
        }

        // `VoiceMuteManager.tick`: a temporary mute whose time ran out is
        // lifted. Java checks every five seconds; this sweep runs every one.
        let expired: Vec<(Uuid, bool)> = self
            .mutes
            .iter()
            .filter(|(_, mute)| mute.until.is_some_and(|until| until <= now))
            .map(|(player, mute)| (*player, mute.silent))
            .collect();
        for (player, silent) in expired {
            // A mute that was silent stays silent when it runs out
            // (`VoiceMuteManager.tick`: `muteInfo.silent || …`).
            self.unmute(player, silent);
        }

        let gone: Vec<Uuid> = self
            .sessions
            .values()
            .filter(|s| s.gave_up() || s.last_seen.elapsed() > self.config.session_timeout)
            .map(|s| s.player)
            .collect();
        for player in gone {
            let name = self
                .sessions
                .get(&player)
                .map(|session| session.name.clone())
                .unwrap_or_default();
            let heard = self
                .sessions
                .get(&player)
                .is_some_and(|session| session.address.is_some());
            let why = if heard { "timed out" } else { "never answered" };
            self.log(Level::Info, format!("voice: {name} {why}"));
            self.leave(player);
        }
    }

    // ----------------------------------------------------------------- output

    fn send_control(&self, player: Uuid, packet: &TcpPacket) {
        self.send_payload(player, packet.encode());
    }

    fn send_payload(&self, player: Uuid, payload: Vec<u8>) {
        self.events.push(Event::Send { player, payload });
    }

    fn log(&self, level: Level, message: String) {
        self.events.push(Event::Log { level, message });
    }

    /// Reports a refusal once per kind, so a flood leaves one line rather than
    /// one per datagram.
    fn refuse(&mut self, kind: &'static str, message: String) {
        if self.warned.insert(kind) {
            self.log(Level::Warn, message);
        }
    }
}

/// The wait a ping is delayed by, as `NettyUdpKeepAlive` jitters its own:
/// a server with many sessions must not put them all on the same millisecond.
fn ping_jitter() -> Duration {
    use rsa::rand_core::RngCore;
    Duration::from_millis(u64::from(rsa::rand_core::OsRng.next_u32() % PING_JITTER))
}
