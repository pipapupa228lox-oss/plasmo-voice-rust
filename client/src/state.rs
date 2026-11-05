//! The session state machine: the plugin channel on one side, the UDP socket
//! on the other, in the order the server drives it.
//!
//! The game calls four things:
//!
//! * [`VoiceSession::handle_channel`] with each `plasmo:voice/v2` payload;
//! * [`VoiceSession::take_outgoing`] to know what to send back on that channel;
//! * [`VoiceSession::feed_microphone`] with each 20 ms frame of microphone;
//! * [`VoiceSession::poll_audio`] every frame, to get what to play.
//!
//! Everything the server sends that a player would hear or see is kept here:
//! the config, the players, the activations.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use pv_proto::{
    Config, TcpPacket, Uuid, VoiceActivation, VoicePlayerInfo, PROXIMITY_NAME,
};

use crate::codec::from_capture;
use crate::crypto::Aes;
use crate::identity::Identity;
use crate::session::{Incoming, Stats, VoiceClient};

/// `NettyUdpKeepAlive` closes a connection that goes quiet, so every client
/// pings; twice a second is what the Java client's tick amounts to.
const PING_EVERY: Duration = Duration::from_millis(500);

/// A server that has not been heard from for this long is gone: it answers
/// every ping, so six seconds of silence is twelve unanswered pings.
const SILENCE: Duration = Duration::from_secs(6);
/// The first wait before asking for a new session; it doubles from there.
const RECONNECT_FIRST: Duration = Duration::from_secs(1);
/// The longest wait between attempts, so a server that is down for an hour is
/// asked twice a minute instead of every second.
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// Attempts before the client stops asking and says why. A voice port that a
/// firewall blocks never answers, and a player should get one clear message
/// rather than a hidden retry loop forever.
const RECONNECT_LIMIT: u32 = 5;

pub struct VoiceSession {
    minecraft_version: String,
    identity: Option<Identity>,
    secret: Option<Uuid>,
    address: Option<SocketAddr>,
    config: Option<Config>,
    client: Option<VoiceClient>,
    players: Vec<VoicePlayerInfo>,
    /// The player behind each source id, from `SourceInfo`; the speaker icons
    /// go by it.
    sources: HashMap<Uuid, String>,
    /// The source line each source belongs to (`SourceInfo.lineId`): the line's
    /// icon is what the mod draws over the speaker's head.
    lines: HashMap<Uuid, Uuid>,
    /// Source ids we have already asked about.
    requested: HashSet<Uuid>,
    outgoing: Vec<TcpPacket>,
    muted: bool,
    voice_disabled: bool,
    /// A frame went out since the last `PlayerAudioEndPacket`.
    talking: bool,
    error: Option<String>,
    last_ping: Instant,
    /// The Minecraft server's address, for the `0.0.0.0` a server announces
    /// when it does not know its own public address (`hostPublic` unset).
    server_address: Option<String>,
    /// How long the server may be silent before the session is asked for
    /// again; [`SILENCE`] unless a test or a launcher says otherwise.
    silence: Duration,
    /// Reconnects since the last session that worked, and when the next try is
    /// due. The game never waits on either.
    reconnects: u32,
    next_attempt: Instant,
    /// The session was dropped for silence and a `PlayerInfo` is out: the wait
    /// for a new `ConnectionPacket`. A first join is not this — there the
    /// server asks, and the client does not retry on its own.
    awaiting: bool,
}

impl VoiceSession {
    pub fn new(minecraft_version: &str) -> Self {
        VoiceSession {
            minecraft_version: minecraft_version.to_string(),
            identity: None,
            secret: None,
            address: None,
            config: None,
            client: None,
            players: Vec::new(),
            sources: HashMap::new(),
            lines: HashMap::new(),
            requested: HashSet::new(),
            outgoing: Vec::new(),
            muted: false,
            voice_disabled: false,
            talking: false,
            error: None,
            last_ping: Instant::now(),
            server_address: None,
            silence: SILENCE,
            reconnects: 0,
            next_attempt: Instant::now(),
            awaiting: false,
        }
    }

    /// Changes how long silence is tolerated before a reconnect. The default
    /// is six seconds; a test uses a fraction of that instead of sleeping.
    pub fn with_reconnect_silence(mut self, silence: Duration) -> Self {
        self.silence = silence;
        self
    }

    /// The server this channel belongs to (`"host:port"`), used when the
    /// `ConnectionPacket` carries the wildcard address.
    pub fn set_server_address(&mut self, address: &str) {
        self.server_address = Some(address.to_owned());
    }

    /// Skips generating a key: for tests, and for a launcher that caches one.
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// One payload of the plugin channel: one packet, or several.
    ///
    /// A packet the server sends that cannot be used (a key that is not ours,
    /// a config before a connection) is kept in `error` and dropped: the game
    /// thread must not be handed a Result for every channel message.
    pub fn handle_channel(&mut self, payload: &[u8]) -> Result<(), String> {
        let packets = TcpPacket::decode_all(payload).map_err(|error| error.to_string())?;
        for packet in packets {
            if let Err(error) = self.handle_packet(packet) {
                self.error = Some(error);
            }
        }
        Ok(())
    }

    fn handle_packet(&mut self, packet: TcpPacket) -> Result<(), String> {
        match packet {
            // The server asks on join and retries until a key arrives; this is
            // the only thing that starts a session.
            TcpPacket::PlayerInfoRequest => {
                if self.identity.is_none() {
                    self.identity = Some(Identity::generate()?);
                }
                let public_key = self
                    .identity
                    .as_ref()
                    .map(|identity| identity.public_key().to_vec())
                    .unwrap_or_default();
                self.outgoing.push(crate::player_info(
                    &self.minecraft_version,
                    public_key,
                    self.muted,
                ));
            }
            TcpPacket::Connection { secret, ip, port } => {
                self.secret = Some(secret);
                let address: SocketAddr = if ip.is_empty() || ip == "0.0.0.0" {
                    // The same fallback as the Java client: the Minecraft
                    // server's host, with the voice server's port.
                    let host = self
                        .server_address
                        .as_deref()
                        .and_then(host_of)
                        .ok_or_else(|| {
                            format!(
                                "the voice address is {ip}:{port} and the server's host is unknown"
                            )
                        })?;
                    resolve(&host, port)?
                } else {
                    // An IPv6 literal needs its brackets back.
                    let shown = if ip.contains(':') {
                        format!("[{ip}]:{port}")
                    } else {
                        format!("{ip}:{port}")
                    };
                    shown
                        .parse()
                        .map_err(|_| format!("bad voice address {ip}:{port}"))?
                };
                self.address = Some(address);

                // A session that came up resets the retry count: the next
                // silence starts from one second again.
                self.awaiting = false;
                self.reconnects = 0;
                self.next_attempt = Instant::now();

                let activation = self
                    .config
                    .as_ref()
                    .and_then(crate::default_activation)
                    .cloned()
                    .unwrap_or_else(proximity_fallback);

                // The config only comes after the server has heard from this
                // secret, so the socket opens now and the codec arrives later.
                let client = VoiceClient::connect(
                    address,
                    secret,
                    activation.id,
                    activation.default_distance as i16,
                    false,
                    None,
                )
                .map_err(|error| format!("udp: {error}"))?;
                client
                    .ping()
                    .map_err(|error| format!("udp ping: {error}"))?;
                self.client = Some(client);
                self.last_ping = Instant::now();
            }
            TcpPacket::Config(config) => {
                let capture = &config.capture;
                let encoder = capture
                    .encoder
                    .as_ref()
                    .map(|codec| codec.name.as_str());
                let codec = from_capture(
                    encoder,
                    capture.sample_rate,
                    capture.mtu_size,
                    false,
                )?;

                // Every 2.1.17 server encrypts the audio payload: the key it
                // hands over is wrapped with the RSA key from our PlayerInfo.
                let encryption = match &config.encryption {
                    None => None,
                    Some(info) => {
                        let Some(identity) = &self.identity else {
                            return Err(format!(
                                "{} before our key was sent",
                                info.algorithm
                            ));
                        };
                        let raw = crate::crypto::unwrap_key(identity.private(), &info.data)?;
                        if info.algorithm != "AES/CBC/PKCS5Padding" {
                            return Err(format!(
                                "the server encrypts with {}, which this client does not speak",
                                info.algorithm
                            ));
                        }
                        Some(Aes::new(&raw)?)
                    }
                };

                let activation = config
                    .activations
                    .iter()
                    .find(|activation| activation.name == PROXIMITY_NAME)
                    .or_else(|| config.activations.first());

                let Some(activation) = activation else {
                    return Err("the config has no activation".into());
                };

                let Some(client) = &mut self.client else {
                    return Err("config before connection".into());
                };
                client.set_codec(codec);
                client.set_encryption(encryption);
                client.set_activation(
                    activation.id,
                    activation.default_distance as i16,
                );

                // Tell the server which distance we hear each activation at.
                let distances = config
                    .activations
                    .iter()
                    .map(|activation| (activation.id, activation.default_distance))
                    .collect();
                self.outgoing
                    .push(TcpPacket::PlayerActivationDistances { distances });

                self.config = Some(*config);
            }
            TcpPacket::PlayerList { players } => self.players = players,
            TcpPacket::SourceInfo { source } => {
                self.lines.insert(source.id, source.line_id);
                if let Some(player) = &source.player {
                    self.sources.insert(source.id, player.nick.clone());
                }
            }
            TcpPacket::SourceLineRegister { line } => {
                if let Some(config) = &mut self.config {
                    if !config.source_lines.iter().any(|known| known.id == line.id) {
                        config.source_lines.push(*line);
                    }
                }
            }
            TcpPacket::PlayerInfoUpdate { player } => {
                match self
                    .players
                    .iter_mut()
                    .find(|known| known.player_id == player.player_id)
                {
                    Some(known) => *known = player,
                    None => self.players.push(player),
                }
            }
            TcpPacket::PlayerDisconnect { player_id } => {
                self.players.retain(|player| player.player_id != player_id);
            }
            TcpPacket::ActivationRegister { activation } => {
                if let Some(config) = &mut self.config {
                    if !config.activations.iter().any(|a| a.id == activation.id) {
                        config.activations.push(*activation);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The packets the game has to send on `plasmo:voice/v2`.
    pub fn take_outgoing(&mut self) -> Vec<TcpPacket> {
        std::mem::take(&mut self.outgoing)
    }

    /// One frame of the microphone, in samples at the config's rate.
    pub fn feed_microphone(&mut self, samples: &[i16]) -> Result<Option<usize>, String> {
        if self.voice_disabled || self.muted {
            return Ok(None);
        }
        let Some(client) = &mut self.client else {
            return Ok(None);
        };
        let sent = client
            .send_frame(samples)
            .map_err(|error| format!("udp: {error}"))?;
        self.talking = true;
        Ok(Some(sent))
    }

    /// The microphone went quiet: tell the server the burst is over, which is
    /// what makes the speaker's icon fade and the packet stream stop.
    pub fn finish_talking(&mut self) {
        if !self.talking {
            return;
        }
        if let Some(client) = &self.client {
            if let Some(control) = client.audio_end() {
                self.outgoing.push(crate::control_packet(control));
            }
        }
        self.talking = false;
    }

    pub fn poll_audio(&mut self) -> Vec<Incoming> {
        self.client
            .as_mut()
            .and_then(|client| client.poll().ok())
            .unwrap_or_default()
    }

    pub fn set_muted(&mut self, muted: bool) {
        if self.muted == muted {
            return;
        }
        self.muted = muted;
        if muted {
            self.finish_talking();
        }
        self.outgoing.push(TcpPacket::PlayerState {
            voice_disabled: self.voice_disabled,
            microphone_muted: self.muted,
        });
    }

    pub fn set_voice_disabled(&mut self, disabled: bool) {
        self.voice_disabled = disabled;
        if disabled {
            self.finish_talking();
        }
        self.outgoing.push(TcpPacket::PlayerState {
            voice_disabled: self.voice_disabled,
            microphone_muted: self.muted,
        });
    }

    pub fn set_activation(&mut self, activation: Uuid, distance: i16) {
        if let Some(client) = &mut self.client {
            client.set_activation(activation, distance);
        }
    }

    pub fn frame_size(&self) -> Option<usize> {
        self.client.as_ref().and_then(VoiceClient::frame_size)
    }

    /// Keeps the UDP mapping alive and notices a session that died; the game
    /// calls it every frame.
    pub fn touch(&mut self) {
        self.reconnect_if_silent();
        if self.last_ping.elapsed() < PING_EVERY {
            return;
        }
        self.last_ping = Instant::now();
        if let Some(client) = &self.client {
            let _ = client.ping();
        }
    }

    /// The server has gone quiet for longer than [`SILENCE`]: drop the socket
    /// and ask for a new session.
    ///
    /// The ask is a `PlayerInfo` on the plugin channel — the same packet that
    /// joins — because the secret and the AES key belong to the server: a
    /// client cannot invent them. The server answers with a new
    /// `ConnectionPacket` and a new secret, and the config follows the first
    /// datagram, exactly as on a first join. That is also what makes this
    /// safe against the Java server, whose handler for a second `PlayerInfo`
    /// is a re-key rather than an error.
    fn reconnect_if_silent(&mut self) {
        let now = Instant::now();

        // Already waiting for a new session: ask again when the wait is up.
        if self.awaiting {
            if now < self.next_attempt {
                return;
            }
            if self.reconnects >= RECONNECT_LIMIT {
                self.error = Some(format!(
                    "voice: no answer after {RECONNECT_LIMIT} reconnects"
                ));
                self.awaiting = false;
                return;
            }
            self.reconnects += 1;
            self.next_attempt = now + reconnect_backoff(self.reconnects);
            self.ask_for_a_session();
            return;
        }

        let Some(client) = &self.client else {
            return;
        };
        if client.silent_for() < self.silence || now < self.next_attempt {
            return;
        }

        // The socket is dead: whatever the reason (a NAT mapping that expired,
        // a restarted server, a firewall that started dropping), nothing on it
        // is worth keeping.
        self.client = None;
        self.secret = None;
        self.address = None;
        self.talking = false;
        self.last_ping = now;
        self.awaiting = true;
        self.reconnects = 1;
        self.next_attempt = now + reconnect_backoff(1);
        self.ask_for_a_session();
    }

    /// The `PlayerInfo` that starts a session, with the identity we already
    /// hold: the server unwraps the shared key with the key it announced, and
    /// a new pair would only cost a second of key generation.
    fn ask_for_a_session(&mut self) {
        if self.identity.is_none() {
            self.identity = Identity::generate().ok();
        }
        let Some(identity) = &self.identity else {
            return;
        };
        self.outgoing.push(crate::player_info(
            &self.minecraft_version,
            identity.public_key().to_vec(),
            self.muted,
        ));
    }

    /// How many times the session was re-established or asked for again.
    pub fn reconnects(&self) -> u32 {
        self.reconnects
    }

    /// Whether the server's config has arrived, so audio can flow.
    pub fn has_config(&self) -> bool {
        self.client
            .as_ref()
            .is_some_and(|client| client.frame_size().is_some())
    }

    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    pub fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }

    pub fn players(&self) -> &[VoicePlayerInfo] {
        &self.players
    }

    /// The nickname behind a source id, while the server still knows it.
    pub fn source_nick(&self, source_id: Uuid) -> Option<&str> {
        self.sources.get(&source_id).map(String::as_str)
    }

    /// What the server said about a player: their own microphone mute, and
    /// whether they switched voice chat off. The icon over their head goes by
    /// it before the source line's own icon does.
    pub fn player_state(&self, nick: &str) -> Option<(bool, bool)> {
        self.players
            .iter()
            .find(|player| player.nick == nick)
            .map(|player| (player.microphone_muted, player.voice_disabled))
    }

    /// The source line a source belongs to, as its id.
    pub fn source_line(&self, source_id: Uuid) -> Option<Uuid> {
        self.lines.get(&source_id).copied()
    }

    /// The activation the server offers under `name` (`proximity`, `whisper`).
    pub fn activation_named(&self, name: &str) -> Option<&crate::proto::VoiceActivation> {
        self.config
            .as_ref()?
            .activations
            .iter()
            .find(|activation| activation.name == name)
    }

    /// The icon of the line a source belongs to, as the server wrote it
    /// (`plasmovoice:textures/icons/speaker.png`): `speaker`, `speaker_whisper`
    /// and the rest of the source lines.
    pub fn source_icon(&self, source_id: Uuid) -> Option<&str> {
        let line = *self.lines.get(&source_id)?;
        self.config
            .as_ref()?
            .source_lines
            .iter()
            .find(|known| known.id == line)
            .map(|line| line.icon.as_str())
    }

    /// Asks who is behind a source id (`SourceInfoRequestPacket`), which is
    /// what makes the server answer with the player's nickname and so what the
    /// speaker icon can hang on. Once per id.
    pub fn request_source_info(&mut self, source_id: Uuid) {
        if self.sources.contains_key(&source_id) || !self.requested.insert(source_id) {
            return;
        }
        self.outgoing
            .push(TcpPacket::SourceInfoRequest { source_id });
    }

    /// What the UDP socket has seen: how much audio arrived, and where the rest
    /// was dropped.
    pub fn stats(&self) -> Stats {
        self.client.as_ref().map(VoiceClient::stats).unwrap_or_default()
    }

    /// The first few distinct problems, each once.
    pub fn notes(&self) -> &[String] {
        self.client
            .as_ref()
            .map(VoiceClient::notes)
            .unwrap_or(&[])
    }

    pub fn activations(&self) -> &[VoiceActivation] {
        self.config
            .as_ref()
            .map(|config| config.activations.as_slice())
            .unwrap_or(&[])
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn is_muted(&self) -> bool {
        self.muted
    }
}

/// The wait before reconnect number `attempt` (1-based): 1, 2, 4, 8, 16 s,
/// then [`RECONNECT_MAX`].
fn reconnect_backoff(attempt: u32) -> Duration {
    let doublings = attempt.saturating_sub(1).min(4);
    (RECONNECT_FIRST * (1 << doublings)).min(RECONNECT_MAX)
}

/// The proximity activation every PlasmoVoice server has, for the moment
/// between `ConnectionPacket` and `ConfigPacket`: the socket needs an id to
/// open with, and the config only arrives after this client has spoken on it.
fn proximity_fallback() -> VoiceActivation {
    VoiceActivation {
        name: PROXIMITY_NAME.to_string(),
        translation: "pv.activation.proximity".to_string(),
        icon: "proximity".to_string(),
        id: VoiceActivation::proximity_id(),
        distances: vec![8, 16, 32],
        default_distance: 16,
        proximity: true,
        transitive: false,
        stereo_supported: true,
        encoder: None,
        weight: 10,
    }
}

/// The host part of a `"host:port"` (or `"host"`), bracketing IPv6 as the
/// launcher's server list writes it.
fn host_of(address: &str) -> Option<String> {
    let address = address.trim();
    if let Some(rest) = address.strip_prefix('[') {
        return rest.split(']').next().map(|host| host.to_owned());
    }
    match address.rsplit_once(':') {
        // A bare host has no port to strip; a lone `:` would leave nothing.
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            Some(host.to_owned())
        }
        Some(_) => None,
        None => Some(address.to_owned()),
    }
}

/// The voice port on the server's host. DNS is on the game thread here, once
/// per connection, which is what the Java client does too.
fn resolve(host: &str, port: i32) -> Result<SocketAddr, String> {
    let port = u16::try_from(port).map_err(|_| format!("voice port {port} is not a port"))?;
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve {host}: {error}"))?
        .collect();
    // `localhost` resolves to `::1` first on Windows, and a voice server that
    // announced no address is on the IPv4 host we connected to.
    Ok(addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.first())
        .copied()
        .ok_or_else(|| format!("{host} has no address"))?)
}

#[cfg(test)]
mod address_tests {
    use super::{host_of, resolve};

    #[test]
    fn a_host_is_taken_apart_the_way_the_server_list_writes_it() {
        assert_eq!(host_of("play.example.org:25565").as_deref(), Some("play.example.org"));
        assert_eq!(host_of("play.example.org").as_deref(), Some("play.example.org"));
        assert_eq!(host_of("1.2.3.4:25565").as_deref(), Some("1.2.3.4"));
        assert_eq!(host_of("[::1]:25565").as_deref(), Some("::1"));
    }

    #[test]
    fn the_voice_address_resolves() {
        let address = resolve("127.0.0.1", 25_565).unwrap();
        assert_eq!(address.port(), 25_565);
    }
}
