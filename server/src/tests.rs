//! The relay against a mock client over a real UDP socket: the handshake the
//! Java server drives, the config it hands out, and what gets forwarded.

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use pv_proto::{
    Pos3d, SourceInfo, TcpPacket, UdpBody, UdpPacket, Uuid, VoiceActivation, source_line_id,
};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::pkcs8::EncodePublicKey;

use super::{
    Catalogue, Config, Event, Level, MuteDuration, MuteUnit, Place, Position, Relay, Source,
    uuid_of,
};

/// How long a test waits for the relay before it fails: the thread wakes every
/// 20 ms and a sweep runs every second, so this is several times the worst
/// case, not a tuned number.
const PATIENCE: Duration = Duration::from_secs(5);

fn player(n: u128) -> Uuid {
    uuid_of(n)
}

/// Waits for the positions pushed a moment ago to reach the relay thread.
/// The thread wakes every 20 ms, and the two transports have no ordering
/// between them, so a test that sends audio right after `positions` would race.
fn settle() {
    std::thread::sleep(Duration::from_millis(150));
}

fn place(player: Uuid, dimension: u32, x: f64) -> Position {
    Position {
        player,
        dimension,
        x,
        y: 64.0,
        z: 0.0,
    }
}

/// The relay plus the events that were taken off it but not looked at yet, so
/// one test never loses another's config while it waits for its own.
struct Harness {
    relay: Relay,
    pending: VecDeque<Event>,
}

impl Harness {
    fn with(config: Config) -> Self {
        Harness {
            relay: Relay::start(config).expect("bind the relay"),
            pending: VecDeque::new(),
        }
    }

    fn new() -> Self {
        Harness::with(Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            ..Config::default()
        })
    }

    /// Every setting the server's config reaches, at a value other than the
    /// default, so a test can see each of them arrive.
    fn config_for_setting() -> Config {
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            sample_rate: 24_000,
            mtu: 1280,
            opus_mode: "AUDIO".into(),
            opus_bitrate: 64_000,
            distances: vec![8, 24],
            default_distance: 24,
            player_icon_visibility: vec!["HIDE_SERVER_MUTED".into()],
            player_icon_y_offset: 0.25,
            ..Config::default()
        }
    }

    /// The next event: one kept from an earlier look, or a fresh one.
    fn next(&mut self) -> Option<Event> {
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        self.relay.drain(1).into_iter().next()
    }

    /// Waits for an event `what` describes, dropping the others; `None` when
    /// `PATIENCE` runs out.
    fn wait(&mut self, mut what: impl FnMut(&Event) -> bool) -> Option<Event> {
        let start = Instant::now();
        while start.elapsed() < PATIENCE {
            match self.next() {
                Some(event) => {
                    if what(&event) {
                        return Some(event);
                    }
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        None
    }

    /// The control packets the relay sends `player` next. Whatever else was
    /// waiting is kept for the next call, and so are the `SourceInfo`
    /// announcements that follow a config: those have a test of their own.
    fn control_for(&mut self, player: Uuid, described: &str) -> Vec<TcpPacket> {
        let mut kept = VecDeque::new();
        let mut packets = None;
        let start = Instant::now();
        while start.elapsed() < PATIENCE && packets.is_none() {
            match self.pending.pop_front().or_else(|| self.next()) {
                Some(event @ Event::Send { player: to, .. }) if to == player => {
                    let Event::Send { payload, .. } = &event else {
                        unreachable!()
                    };
                    let decoded = TcpPacket::decode_all(payload).ok();
                    match decoded {
                        // A speaker's record, announced when someone is
                        // configured: not the packet this call waits for.
                        Some(ref packets)
                            if packets
                                .iter()
                                .all(|p| matches!(p, TcpPacket::SourceInfo { .. })) =>
                        {
                            kept.push_back(event);
                        }
                        other => packets = other,
                    }
                }
                Some(other) => kept.push_back(other),
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        kept.append(&mut self.pending);
        self.pending = kept;
        let packets = packets.unwrap_or_else(|| panic!("the relay never sent {described}"));
        packets
    }

    /// The next payload for `player`, `SourceInfo` records included: the
    /// answer to a `SourceInfoRequest` is one, so it cannot be filtered out.
    fn records_for(&mut self, player: Uuid, described: &str) -> Vec<TcpPacket> {
        let mut kept = VecDeque::new();
        let mut packets = None;
        let start = Instant::now();
        while start.elapsed() < PATIENCE && packets.is_none() {
            match self.pending.pop_front().or_else(|| self.next()) {
                Some(Event::Send {
                    player: to,
                    payload,
                }) if to == player => packets = TcpPacket::decode_all(&payload).ok(),
                Some(other) => kept.push_back(other),
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        kept.append(&mut self.pending);
        self.pending = kept;
        packets.unwrap_or_else(|| panic!("the relay never sent {described}"))
    }

    /// Every `SourceInfo` record the relay has announced to `player`, waiting
    /// for `want` of them.
    fn announcements(&mut self, player: Uuid, want: usize) -> Vec<SourceInfo> {
        let start = Instant::now();
        let mut kept = VecDeque::new();
        let mut records = Vec::new();
        while start.elapsed() < PATIENCE && records.len() < want {
            match self.pending.pop_front().or_else(|| self.next()) {
                Some(Event::Send {
                    player: to,
                    payload,
                }) if to == player => {
                    if let Ok(packets) = TcpPacket::decode_all(&payload) {
                        for packet in packets {
                            if let TcpPacket::SourceInfo { source } = packet {
                                records.push(source);
                            }
                        }
                    }
                }
                // Another player's events are kept: the next call wants them.
                Some(other) => kept.push_back(other),
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        kept.append(&mut self.pending);
        self.pending = kept;
        records
    }

    fn logs(&mut self, needle: &str) -> bool {
        self.wait(|event| matches!(event, Event::Log { message, .. } if message.contains(needle)))
            .is_some()
    }
}

/// A mock PlasmoVoice client: the secret it was given and the socket it sends
/// audio from.
struct Client {
    player: Uuid,
    secret: Uuid,
    socket: UdpSocket,
    /// The key it announced: the only thing that can unwrap a `ConfigPacket`'s
    /// AES key, which is how a rotation is checked.
    private: Arc<RsaPrivateKey>,
    /// `ConfigPacket.encryption.data` as the last one it was sent wrapped the
    /// key: what a fresh join starts on.
    wrapped: Vec<u8>,
    /// The `ConfigPacket` this client was configured with, as it decoded it:
    /// every server setting the client can see lives in there.
    config: Box<pv_proto::Config>,
}

impl Client {
    fn send_audio(&self, relay: &Relay, data: &[u8], distance: i16) {
        let packet = UdpPacket::now(
            self.secret,
            UdpBody::PlayerAudio {
                sequence_number: 7,
                data: data.to_vec(),
                activation_id: VoiceActivation::proximity_id(),
                distance,
                stereo: false,
            },
        );
        self.socket
            .send_to(&packet.encode(), relay.local_addr())
            .expect("send audio");
    }

    fn channel(&self, relay: &Relay, packet: TcpPacket) {
        relay.channel(self.player, &packet.encode());
    }

    /// The next datagram that is not the answer to our own ping, or `None` if
    /// the socket stayed quiet.
    fn receive(&self) -> Option<UdpPacket> {
        let mut buffer = [0u8; 2048];
        for _ in 0..4 {
            let Ok((size, _)) = self.socket.recv_from(&mut buffer) else {
                return None;
            };
            let Some(packet) = UdpPacket::decode(&buffer[..size]).ok() else {
                continue;
            };
            if !matches!(packet.body, UdpBody::Ping { .. }) {
                return Some(packet);
            }
        }
        None
    }

    /// The server's own keep-alive ping, waiting up to `limit` for it.
    fn wait_ping(&self, limit: Duration) -> Option<UdpPacket> {
        let start = Instant::now();
        let mut buffer = [0u8; 2048];
        while start.elapsed() < limit {
            let Ok((size, _)) = self.socket.recv_from(&mut buffer) else {
                continue;
            };
            let Some(packet) = UdpPacket::decode(&buffer[..size]).ok() else {
                continue;
            };
            if matches!(packet.body, UdpBody::Ping { .. }) {
                return Some(packet);
            }
        }
        None
    }

    /// Whether the relay answers a client's ping that carried `time` within
    /// `window`. Java never does, so this must be false.
    fn echoes_ping(&self, time: i64, window: Duration) -> bool {
        let start = Instant::now();
        let mut buffer = [0u8; 2048];
        while start.elapsed() < window {
            let Ok((size, _)) = self.socket.recv_from(&mut buffer) else {
                continue;
            };
            let Ok(packet) = UdpPacket::decode(&buffer[..size]) else {
                continue;
            };
            if matches!(packet.body, UdpBody::Ping { time: echoed, .. } if echoed == time) {
                return true;
            }
        }
        false
    }
}

/// Drives the handshake the Java server drives: request, info, connection,
/// a ping, then the config. Returns the client once it is configured.
fn join(harness: &mut Harness, player: Uuid, name: &str) -> Client {
    join_with(harness, player, name, "2.1.17")
}

/// The key `join_with` announces, generated once for the whole test binary.
///
/// 1024 bits keeps it quick, but a keygen in a debug build still takes about a
/// second, and a test with a short `session_timeout` would lose the session to
/// the sweep before the handshake finished if every join paid for one.
fn shared_key() -> Arc<RsaPrivateKey> {
    static KEY: OnceLock<Arc<RsaPrivateKey>> = OnceLock::new();
    Arc::clone(KEY.get_or_init(|| {
        Arc::new(RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).expect("generate a key"))
    }))
}

/// The same handshake, with the client reporting `version`: `clientModMinVersion`
/// is what an old client is refused for.
fn join_with(harness: &mut Harness, player: Uuid, name: &str, version: &str) -> Client {
    harness.relay.join(player, name);
    let packets = harness.control_for(player, "the key request");
    assert_eq!(
        packets,
        vec![TcpPacket::PlayerInfoRequest],
        "the server asks first"
    );

    // 1024 bits keeps the tests quick; the relay parses whatever X.509 RSA key
    // a client sends, and the Java client sends 2048.
    let private = shared_key();
    let public = rsa::RsaPublicKey::from(&*private);
    let der = public
        .to_public_key_der()
        .expect("export")
        .as_bytes()
        .to_vec();

    harness.relay.channel(
        player,
        &TcpPacket::PlayerInfo {
            voice_disabled: false,
            microphone_muted: false,
            minecraft_version: "26.3".into(),
            version: version.into(),
            public_key: der,
        }
        .encode(),
    );

    // A retried key request can interleave: the sweep asks again after two
    // seconds, and a slow machine can take that long to build a key.
    let mut packets = harness.control_for(player, "the connection");
    for _ in 0..3 {
        if packets
            .iter()
            .any(|p| matches!(p, TcpPacket::Connection { .. }))
        {
            break;
        }
        packets = harness.control_for(player, "the connection");
    }
    let Some(TcpPacket::Connection { secret, ip, port }) = packets
        .iter()
        .find(|p| matches!(p, TcpPacket::Connection { .. }))
    else {
        panic!("expected a ConnectionPacket, got {packets:?}");
    };
    let (secret, port) = (*secret, *port);
    assert_eq!(port, i32::from(harness.relay.local_addr().port()));
    // `ServerConfig.Host.ip` is "0.0.0.0" in Java, and the client swaps
    // exactly that for the Minecraft server's host. An empty string it would
    // resolve to its own loopback instead.
    assert_eq!(
        ip, "0.0.0.0",
        "the client is told to use the Minecraft host"
    );

    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind the client");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let ping = UdpPacket::now(
        secret,
        UdpBody::Ping {
            time: 42,
            server_ip: None,
            server_port: None,
        },
    );
    socket
        .send_to(&ping.encode(), harness.relay.local_addr())
        .expect("send the ping");

    let packets = harness.control_for(player, "the config");
    let Some(TcpPacket::Config(config)) =
        packets.iter().find(|p| matches!(p, TcpPacket::Config(_)))
    else {
        panic!("expected a ConfigPacket, got {packets:?}");
    };
    let encryption = config
        .encryption
        .as_ref()
        .expect("every 2.1.17 server encrypts the audio");
    assert_eq!(encryption.algorithm, "AES/CBC/PKCS5Padding");
    // Only the holder of the private key can unwrap the shared AES key.
    let key = private
        .decrypt(Pkcs1v15Encrypt, &encryption.data)
        .expect("the key is wrapped with our own RSA key");
    assert_eq!(key.len(), 16, "AES-128");
    let activation = config.proximity_activation().expect("proximity is offered");
    assert!(
        activation.distances.contains(&activation.default_distance),
        "`validateDefaultDistance` leaves a default the list holds: {:?} on {:?}",
        activation.default_distance,
        activation.distances
    );
    // `ProximityServerActivation.register`: the line the client draws player
    // icons with, and the icons Java names for it. A client takes the icon as
    // a resource location, so a short name is a missing texture.
    let line = config
        .source_lines
        .iter()
        .find(|line| line.name == "proximity")
        .expect("the proximity line the client draws");
    assert_eq!(line.id, source_line_id("proximity"));
    assert_eq!(line.icon, "plasmovoice:textures/icons/speaker.png");
    assert_eq!(line.translation, "pv.activation.proximity");
    assert_eq!(line.weight, 1);
    assert_eq!(
        activation.icon, "plasmovoice:textures/icons/microphone.png",
        "the microphone icon above the speaker's head"
    );
    assert!(
        activation.transitive,
        "the proximity activation is transitive"
    );
    assert_eq!(activation.weight, 1);

    // The player list follows in a payload of its own: `ConfigPacket`'s reader
    // would take anything appended to it for the optional icon config.
    let list = harness.control_for(player, "the player list");
    assert!(
        list.iter()
            .any(|p| matches!(p, TcpPacket::PlayerList { .. })),
        "the menu's player list comes with the config, got {list:?}"
    );

    let wrapped = encryption.data.clone();
    Client {
        player,
        secret,
        socket,
        private,
        wrapped,
        config: Box::new((**config).clone()),
    }
}

#[test]
fn a_join_reaches_a_config_wrapped_for_that_client() {
    let mut harness = Harness::new();
    let client = join(&mut harness, player(1), "Alice");

    // Java answers no ping — `NettyUdpServerConnection.handle(PingPacket)` only
    // records the time — and it must not: both clients answer a ping they
    // receive, so an answer to an answer would ping-pong until the datagram
    // rate limit started dropping audio.
    assert!(
        !client.echoes_ping(42, Duration::from_millis(600)),
        "the relay answered a client's ping, which the Java server never does"
    );

    // The relay pings on its own, as `NettyUdpKeepAlive` does. A Java client
    // pings only until its socket is up and then waits for this, and calls
    // itself timed out after seven seconds without one.
    let ping = client
        .wait_ping(PATIENCE)
        .expect("the relay's keep-alive ping");
    assert_eq!(ping.secret, client.secret);
    harness.relay.shutdown();
}

#[test]
fn a_quiet_session_that_answers_pings_survives_a_long_idle() {
    // Same as the six-second test below, only longer: something that breaks
    // after the first few pings would slip through a short window.
    let mut harness = Harness::with(Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        session_timeout: Duration::from_secs(4),
        ..Config::default()
    });
    let client = join(&mut harness, player(1), "Alice");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut answers = 0u32;
    let mut timed_out = false;
    while Instant::now() < deadline {
        let Some(ping) = client.wait_ping(Duration::from_millis(400)) else {
            continue;
        };
        let UdpBody::Ping { time, .. } = ping.body else {
            continue;
        };
        let answer = UdpPacket::now(
            client.secret,
            UdpBody::Ping {
                time,
                server_ip: None,
                server_port: None,
            },
        );
        client
            .socket
            .send_to(&answer.encode(), harness.relay.local_addr())
            .expect("answer the ping");
        answers += 1;
        while let Some(event) = harness.relay.drain(32).into_iter().next() {
            if let Event::Log { message, .. } = event {
                timed_out |= message.contains("timed out");
            }
        }
    }
    assert!(
        answers >= 5,
        "the relay pinged through the whole twenty seconds: {answers}"
    );
    assert!(!timed_out, "a client that answers pings is not dropped");
    harness.relay.shutdown();
}

#[test]
fn a_quiet_session_that_answers_pings_stays_configured() {
    // The timeout is short enough that only the answers can be what keeps the
    // session: pings go out every 1.5–3 s, so a client that answers each one
    // never leaves a four-second gap.
    let mut harness = Harness::with(Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        session_timeout: Duration::from_secs(4),
        ..Config::default()
    });
    let client = join(&mut harness, player(1), "Alice");

    // The Java client's half of the keep-alive: every ping it is sent, it
    // answers. A session that does that must never be dropped, however quiet
    // its microphone is. The log is drained as the loop runs, so a timeout
    // that landed during the six seconds cannot hide behind later one.
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut answers = 0u32;
    let mut timed_out = false;
    while Instant::now() < deadline {
        let Some(ping) = client.wait_ping(Duration::from_millis(400)) else {
            continue;
        };
        let UdpBody::Ping { time, .. } = ping.body else {
            continue;
        };
        let answer = UdpPacket::now(
            client.secret,
            UdpBody::Ping {
                time,
                server_ip: None,
                server_port: None,
            },
        );
        client
            .socket
            .send_to(&answer.encode(), harness.relay.local_addr())
            .expect("answer the ping");
        answers += 1;
        while let Some(event) = harness.relay.drain(32).into_iter().next() {
            if let Event::Log { message, .. } = event {
                timed_out |= message.contains("timed out");
            }
        }
    }
    assert!(
        answers >= 2,
        "the relay pinged through the whole six seconds"
    );
    assert!(!timed_out, "a client that answers pings is not dropped");
    harness.relay.shutdown();
}

#[test]
fn audio_reaches_a_listener_within_range_under_that_listeners_secret() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");

    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 5.0)]);
    settle();

    let frame = vec![0xAB; 64];
    alice.send_audio(&harness.relay, &frame, 16);

    let packet = bob.receive().expect("Bob hears Alice");
    assert_eq!(packet.secret, bob.secret, "the header holds Bob's secret");
    match packet.body {
        UdpBody::SourceAudio {
            data,
            source_id,
            source_state,
            distance,
            ..
        } => {
            assert_eq!(data, frame, "the sealed payload is copied byte for byte");
            assert_eq!(source_id, alice.player);
            assert_eq!(source_state, 1, "speaking");
            assert_eq!(distance, 16);
        }
        other => panic!("expected SourceAudio, got {other:?}"),
    }

    // Alice does not hear herself as a source, but she is handed her own frame
    // as `SelfAudioInfoPacket`, which is what the mod's own overlay reads.
    let own = alice.receive().expect("the speaker's own info");
    assert_eq!(own.secret, alice.secret);
    match own.body {
        UdpBody::SelfAudio {
            source_id,
            sequence_number,
            distance,
            ..
        } => {
            assert_eq!(source_id, alice.player);
            assert_eq!(sequence_number, 7);
            assert_eq!(distance, 16);
        }
        other => panic!("expected SelfAudio, not a frame for someone else: {other:?}"),
    }
    harness.relay.shutdown();
}

#[test]
fn the_config_carries_the_distances_and_the_icon_the_server_was_given() {
    // `proximity.distances`, `proximity.defaultDistance` and `[voice.playerIcon]`
    // reach the client exactly as `VoiceServerConfig` holds them.
    let mut harness = Harness::with(Harness::config_for_setting());
    let alice = join(&mut harness, player(1), "Alice");

    let config = &alice.config;
    let activation = config.proximity_activation().expect("proximity is offered");
    assert_eq!(
        activation.distances,
        vec![8, 24],
        "the list is the server's"
    );
    assert_eq!(
        activation.default_distance, 24,
        "and so is the one it starts on"
    );
    assert_eq!(config.capture.sample_rate, 24_000);
    assert_eq!(config.capture.mtu_size, 1280);
    let encoder = config
        .capture
        .encoder
        .as_ref()
        .expect("an encoder is negotiated");
    assert_eq!(encoder.param("mode"), Some("AUDIO"));
    assert_eq!(encoder.param("bitrate"), Some("64000"));
    let icon = config.player_icon.as_ref().expect("2.1.7+ always sends it");
    assert_eq!(icon.visibility, vec!["HIDE_SERVER_MUTED"]);
    assert!((icon.offset.y - 0.25).abs() < 1e-9);
    assert_eq!(icon.offset.x, 0.0);
    assert_eq!(icon.offset.z, 0.0);
    harness.relay.shutdown();
}

#[test]
fn a_client_older_than_the_minimum_is_not_configured() {
    // `clientModMinVersion`: the server says so in the log and never hands the
    // client a `ConnectionPacket`, which is what Java does instead of kicking.
    let mut harness = Harness::with(Config {
        client_mod_min_version: "2.1.0".into(),
        ..Harness::config_for_setting()
    });
    harness.relay.join(player(1), "Alice");
    harness.control_for(player(1), "the key request");

    let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).expect("generate a key");
    let der = rsa::RsaPublicKey::from(&private)
        .to_public_key_der()
        .expect("export")
        .as_bytes()
        .to_vec();
    harness.relay.channel(
        player(1),
        &TcpPacket::PlayerInfo {
            voice_disabled: false,
            microphone_muted: false,
            minecraft_version: "26.3".into(),
            version: "2.0.0".into(),
            public_key: der,
        }
        .encode(),
    );

    assert!(
        harness.logs("older than 2.1.0"),
        "the log names the version and the minimum"
    );
    // Whatever else arrives (a retried key request, the announcements), no
    // connection does: without it a client has no secret and no UDP address.
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        if let Some(Event::Send {
            player: to,
            payload,
        }) = harness.next()
        {
            let connected = to == player(1)
                && TcpPacket::decode_all(&payload)
                    .map(|packets| {
                        packets
                            .iter()
                            .any(|p| matches!(p, TcpPacket::Connection { .. }))
                    })
                    .unwrap_or(false);
            assert!(!connected, "an old client is never configured");
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    harness.relay.shutdown();
}

#[test]
fn a_configured_client_learns_the_players_around_it() {
    // The Java client drops `SourceAudioPacket` whose id it has no source for,
    // so every player's `PLAYER` record is announced before the first frame:
    // to the ones already configured, and theirs to the one just configured.
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");

    let for_alice = harness.announcements(alice.player, 1);
    assert_eq!(for_alice.len(), 1, "Alice learns about Bob");
    let bob_source = &for_alice[0];
    assert_eq!(bob_source.kind, "PLAYER");
    assert_eq!(bob_source.id, bob.player);
    assert_eq!(bob_source.name.as_deref(), Some("Bob"));
    assert_eq!(
        bob_source.player.as_ref().map(|p| p.nick.as_str()),
        Some("Bob"),
        "the tail `PlayerSourceInfo` adds is the player itself"
    );
    assert!(
        bob_source.icon_visible,
        "the speaker icon is drawn by default"
    );
    assert_eq!(bob_source.line_id, source_line_id("proximity"));

    let for_bob = harness.announcements(bob.player, 1);
    assert_eq!(for_bob.len(), 1, "Bob learns about Alice");
    assert_eq!(
        for_bob[0].player.as_ref().map(|p| p.nick.as_str()),
        Some("Alice")
    );
    harness.relay.shutdown();
}

#[test]
fn the_speaker_is_told_its_own_source_and_when_the_activation_changes() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 4.0)]);
    settle();

    alice.send_audio(&harness.relay, &[3; 48], 16);
    assert!(bob.receive().is_some(), "Bob hears the frame");

    let packets = harness.control_for(alice.player, "the speaker's own record");
    let TcpPacket::SelfSourceInfo {
        source,
        player_id,
        activation_id,
        sequence_number,
    } = packets[0].clone()
    else {
        panic!("expected a SelfSourceInfoPacket, got {packets:?}");
    };
    assert_eq!(player_id, alice.player);
    assert_eq!(activation_id, VoiceActivation::proximity_id());
    assert_eq!(sequence_number, 7);
    assert_eq!(source.kind, "PLAYER");
    assert_eq!(source.state, 1, "the state the audio frames carry");
    harness.relay.shutdown();
}

#[test]
fn a_proximity_activation_is_heard_past_its_distance_but_never_past_twice_it() {
    // `VoiceServerProximitySource.getListeners`: reach is
    // `min(distance + maxExtraAudioBroadcastDistance, distance * 2)`, and PV's
    // default extra is 16. A 16-block activation therefore reaches 32 blocks:
    // a listener a second's walk outside the circle still hears the tail of a
    // sentence instead of a hole in the middle of it.
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");

    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 20.0)]);
    settle();
    alice.send_audio(&harness.relay, &[7; 32], 16);
    assert!(
        bob.receive().is_some(),
        "20 blocks is inside 16 + 16 (capped at 32) and must be heard"
    );

    // 8 blocks plus 16 would be 24, but twice 8 is 16: the cap wins.
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 18.0)]);
    settle();
    alice.send_audio(&harness.relay, &[7; 32], 8);
    assert!(
        bob.receive().is_none(),
        "an 8-block activation reaches 16, not 24"
    );
    harness.relay.shutdown();
}

#[test]
fn a_direct_source_is_heard_everywhere_in_its_dimension() {
    // A source with no place in the world (`distance` 0) is a stream, not a
    // jukebox: every session in the same dimension hears it, however far.
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    let stream = pv_proto::name_uuid("stream");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 5_000.0)]);
    harness.relay.sources(vec![jukebox(stream, 0, 0.0, 0)]);
    settle();

    harness.relay.source_audio(stream, 1, &[9; 48]);
    assert!(bob.receive().is_some(), "a direct source ignores distance");
    assert!(alice.receive().is_some());

    // Another dimension is still silent: `Place.dimension` is compared first.
    harness.relay.sources(vec![jukebox(stream, 1, 0.0, 0)]);
    settle();
    harness.relay.source_audio(stream, 2, &[9; 48]);
    assert!(bob.receive().is_none());
    harness.relay.shutdown();
}

#[test]
fn audio_stops_at_the_activation_distance_and_at_a_dimension_border() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");

    // 40 blocks apart, 16-block activation: out of range.
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 40.0)]);
    settle();
    alice.send_audio(&harness.relay, &[1, 2, 3], 16);
    assert!(bob.receive().is_none(), "40 blocks away is silence");

    // Close enough, but in the Nether: still silence.
    harness.relay.positions(vec![
        place(player(1), 0, 0.0),
        place(player(2), (-1_i32) as u32, 1.0),
    ]);
    settle();
    alice.send_audio(&harness.relay, &[1, 2, 3], 16);
    assert!(bob.receive().is_none(), "another dimension is silence");
    harness.relay.shutdown();
}

#[test]
fn a_muted_client_is_not_relayed() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 1.0)]);
    settle();

    alice.channel(
        &harness.relay,
        TcpPacket::PlayerState {
            voice_disabled: false,
            microphone_muted: true,
        },
    );
    // Bob is told of the change, so the relay has applied it before the frame
    // below is sent: the two transports must not race.
    let update = harness.control_for(player(2), "the state update");
    // `PlayerStatePacket` carries the client's own microphone switch, which is
    // `microphoneMuted`; `muted` is the server's (`/vmute`) and stays false.
    assert!(
        update.iter().any(|packet| matches!(
            packet,
            TcpPacket::PlayerInfoUpdate { player }
                if player.microphone_muted && !player.muted
        )),
        "the others are told the player muted, got {update:?}"
    );

    alice.send_audio(&harness.relay, &[9; 32], 16);
    assert!(bob.receive().is_none(), "a muted microphone sends nothing");
    harness.relay.shutdown();
}

#[test]
fn a_silent_session_times_out() {
    let mut harness = Harness::with(Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        session_timeout: Duration::from_millis(1500),
        ..Config::default()
    });
    let _alice = join(&mut harness, player(1), "Alice");
    let _bob = join(&mut harness, player(2), "Bob");

    // Nobody pings: the sweep drops the sessions once the timeout passes.
    assert!(
        harness.logs("timed out"),
        "a session that goes quiet is dropped"
    );
    harness.relay.shutdown();
}

#[test]
fn a_datagram_with_an_unknown_secret_is_ignored() {
    let harness = Harness::new();
    let stranger = UdpSocket::bind("127.0.0.1:0").expect("bind");
    stranger
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");

    let packet = UdpPacket::now(
        [0x5A; 16],
        UdpBody::Ping {
            time: 1,
            server_ip: None,
            server_port: None,
        },
    );
    stranger
        .send_to(&packet.encode(), harness.relay.local_addr())
        .expect("send");

    let mut buffer = [0u8; 2048];
    assert!(
        stranger.recv_from(&mut buffer).is_err(),
        "a secret the relay never issued gets no answer"
    );
    harness.relay.shutdown();
}

#[test]
fn several_control_packets_in_one_payload_are_all_read() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let _bob = join(&mut harness, player(2), "Bob");

    // A `PlayerState` and a `PlayerAudioEnd` in a single channel payload, as
    // a client that batched two updates would send them.
    let mut payload = TcpPacket::PlayerState {
        voice_disabled: false,
        microphone_muted: false,
    }
    .encode();
    payload.extend(
        TcpPacket::PlayerAudioEnd {
            sequence_number: 3,
            activation_id: VoiceActivation::proximity_id(),
            distance: 16,
        }
        .encode(),
    );
    harness.relay.channel(alice.player, &payload);

    assert!(
        harness
            .wait(|event| matches!(
                event,
                Event::Send { player: to, payload }
                    if *to == player(2)
                        && TcpPacket::decode_all(payload).is_ok_and(|packets| packets
                            .iter()
                            .any(|p| matches!(p, TcpPacket::SourceAudioEnd { .. })))
            ))
            .is_some(),
        "Bob is told Alice stopped talking"
    );
    harness.relay.shutdown();
}

#[test]
fn a_junk_public_key_gets_no_config() {
    let mut harness = Harness::new();
    harness.relay.join(player(1), "Mallory");
    let _ = harness.control_for(player(1), "the key request");

    harness.relay.channel(
        player(1),
        &TcpPacket::PlayerInfo {
            voice_disabled: false,
            microphone_muted: false,
            minecraft_version: "26.3".into(),
            version: "2.1.17".into(),
            public_key: vec![0u8; 162],
        }
        .encode(),
    );

    assert!(
        harness.logs("not RSA/X.509"),
        "the refusal is logged with its reason"
    );
    harness.relay.shutdown();
}

#[test]
fn a_port_already_taken_is_an_error_not_a_panic() {
    // The server starts without voice and logs why.
    let taken = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let address = taken.local_addr().expect("address");
    let error = Relay::start(Config {
        bind: address,
        ..Config::default()
    })
    .err()
    .expect("the port is taken");
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
}

#[test]
fn a_reconnect_with_a_new_key_gets_a_new_secret_and_the_old_one_dies() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 1.0)]);
    settle();

    // Alice's client restarted: a new `PlayerInfo` on the same Minecraft
    // connection, with a new key, as a client that lost its config sends it.
    let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).expect("generate a key");
    let der = rsa::RsaPublicKey::from(&private)
        .to_public_key_der()
        .expect("export")
        .as_bytes()
        .to_vec();
    harness.relay.channel(
        alice.player,
        &TcpPacket::PlayerInfo {
            voice_disabled: false,
            microphone_muted: false,
            minecraft_version: "26.3".into(),
            version: "2.1.17".into(),
            public_key: der,
        }
        .encode(),
    );

    let packets = harness.control_for(alice.player, "the new connection");
    let Some(TcpPacket::Connection { secret, .. }) = packets
        .iter()
        .find(|p| matches!(p, TcpPacket::Connection { .. }))
    else {
        panic!("expected a ConnectionPacket, got {packets:?}");
    };
    let fresh = *secret;
    assert_ne!(fresh, alice.secret, "a re-key issues a new secret");

    // The old secret no longer resolves: a frame sealed with it is nobody's.
    alice.send_audio(&harness.relay, &[0x11; 16], 16);
    assert!(bob.receive().is_none(), "the old secret is dead");

    // The new secret has to earn its config: the first datagram on it is the
    // ping, and the relay answers with the key wrapped for the new RSA key.
    let ping = UdpPacket::now(
        fresh,
        UdpBody::Ping {
            time: 7,
            server_ip: None,
            server_port: None,
        },
    );
    alice
        .socket
        .send_to(&ping.encode(), harness.relay.local_addr())
        .expect("send the ping");
    let packets = harness.control_for(alice.player, "the new config");
    let Some(TcpPacket::Config(config)) =
        packets.iter().find(|p| matches!(p, TcpPacket::Config(_)))
    else {
        panic!("expected a ConfigPacket, got {packets:?}");
    };
    let encryption = config.encryption.as_ref().expect("the key came back");
    assert_eq!(
        private
            .decrypt(Pkcs1v15Encrypt, &encryption.data)
            .expect("the new key unwraps it")
            .len(),
        16
    );
    assert!(harness.logs("re-keyed"), "the reconnect is in the log");

    // Audio flows again, under the new secret.
    let packet = UdpPacket::now(
        fresh,
        UdpBody::PlayerAudio {
            sequence_number: 1,
            data: vec![0x22; 16],
            activation_id: VoiceActivation::proximity_id(),
            distance: 16,
            stereo: false,
        },
    );
    alice
        .socket
        .send_to(&packet.encode(), harness.relay.local_addr())
        .expect("send audio");
    let heard = bob.receive().expect("Bob hears Alice again");
    assert_eq!(heard.secret, bob.secret);
    harness.relay.shutdown();
}

#[test]
fn a_flood_is_cut_off_at_the_session_budget() {
    let mut harness = Harness::with(Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        datagrams_per_second: 10,
        ..Config::default()
    });
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 1.0)]);
    settle();

    // Forty frames in one burst at a budget of ten a second: the bucket holds
    // one datagram of credit, so the burst cannot all go through.
    for _ in 0..40 {
        alice.send_audio(&harness.relay, &[0x33; 16], 16);
    }
    let mut heard = 0;
    while bob.receive().is_some() {
        heard += 1;
    }
    assert!(heard >= 1, "the first frames are within the budget");
    assert!(
        heard < 20,
        "the burst is cut off, {heard} of 40 got through"
    );
    assert!(
        harness.logs("datagrams a second"),
        "the refusal is in the log"
    );
    harness.relay.shutdown();
}

#[test]
fn an_oversized_datagram_is_dropped_before_it_is_read() {
    let mut harness = Harness::with(Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        max_datagram_bytes: 64,
        ..Config::default()
    });
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 1.0)]);
    settle();

    // The join's own ping fits; a frame four times the cap does not.
    alice.send_audio(&harness.relay, &[0x44; 256], 16);
    assert!(bob.receive().is_none(), "an oversized frame goes nowhere");
    assert!(
        harness.logs("the cap is 64"),
        "the drop names the cap it broke"
    );
    harness.relay.shutdown();
}

#[test]
fn the_command_queue_coalesces_positions_and_drops_the_oldest() {
    use super::relay::{Command, Commands};

    // A hundred ticks of positions leave one snapshot, and nothing is lost.
    let queue = Commands::new(8);
    for _ in 0..100 {
        queue.push(Command::Positions(Vec::new()));
    }
    assert_eq!(
        queue.dropped(),
        0,
        "positions coalesce, they do not pile up"
    );
    let mut taken = 0;
    while queue.try_pop().is_some() {
        taken += 1;
    }
    assert_eq!(taken, 1, "one snapshot is what the relay reads");

    // Control packets are not coalesced: a full queue keeps the newest ones.
    let queue = Commands::new(8);
    for n in 0..8 {
        queue.push(Command::Leave { player: player(n) });
    }
    queue.push(Command::Join {
        player: player(99),
        name: "Nine".into(),
    });
    assert_eq!(queue.dropped(), 1, "one command made room for the join");
    let mut names = Vec::new();
    while let Some(command) = queue.try_pop() {
        if let Command::Join { name, .. } = command {
            names.push(name);
        }
    }
    assert_eq!(
        names,
        vec!["Nine".to_string()],
        "the newest command survived"
    );
}

#[test]
fn a_level_is_spelled_as_the_log_spells_it() {
    assert_eq!(Level::Info.as_str(), "INFO");
    assert_eq!(Level::Warn.as_str(), "WARN");
}

/// A `STATIC` source at `x` in `dimension`, heard `distance` blocks away.
fn jukebox(id: Uuid, dimension: u32, x: f64, distance: i16) -> Source {
    let place = Pos3d { x, y: 64.0, z: 0.0 };
    Source {
        info: SourceInfo::static_source(
            "plasmo:voice",
            id,
            source_line_id("proximity"),
            "Jukebox",
            place,
            Pos3d::default(),
        ),
        place: Place {
            dimension,
            x,
            y: 64.0,
            z: 0.0,
        },
        distance,
    }
}

#[test]
fn a_static_source_answers_a_source_info_request_with_its_place() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let box_id = pv_proto::name_uuid("jukebox");
    let source = jukebox(box_id, 0, 12.0, 16);
    harness.relay.sources(vec![source.clone()]);
    // Both commands go through one FIFO queue, so the source is registered
    // before the request is looked at.

    alice.channel(
        &harness.relay,
        TcpPacket::SourceInfoRequest { source_id: box_id },
    );
    let packets = harness.records_for(alice.player, "the source's record");
    let TcpPacket::SourceInfo { source: record } = &packets[0] else {
        panic!("expected a SourceInfoPacket, got {packets:?}");
    };
    assert_eq!(record, &source.info, "the record is the one registered");
    assert_eq!(record.kind, "STATIC");
    let (place, _) = record.static_place().expect("a place comes with it");
    assert_eq!(place.x, 12.0);
    assert_eq!(place.y, 64.0);
    harness.relay.shutdown();
}

#[test]
fn an_unknown_source_is_not_answered_at_all() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    alice.channel(
        &harness.relay,
        TcpPacket::SourceInfoRequest {
            source_id: pv_proto::name_uuid("nothing"),
        },
    );
    assert!(
        harness
            .wait(|event| matches!(event, Event::Send { player: to, .. } if *to == alice.player))
            .is_none(),
        "a request for a source nobody registered is dropped"
    );
    harness.relay.shutdown();
}

#[test]
fn a_static_sources_audio_is_sealed_and_heard_only_near_the_source() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    let box_id = pv_proto::name_uuid("jukebox");
    // Alice stands 60 blocks from the jukebox, Bob 5: only Bob hears it, and
    // the source's own distance is what decides, not Alice's.
    harness
        .relay
        .positions(vec![place(player(1), 0, 60.0), place(player(2), 0, 5.0)]);
    harness.relay.sources(vec![jukebox(box_id, 0, 0.0, 8)]);
    settle();

    let frame = vec![0x5a; 96];
    harness.relay.source_audio(box_id, 3, &frame);

    let packet = bob.receive().expect("Bob is next to the jukebox");
    assert_eq!(packet.secret, bob.secret);
    match packet.body {
        UdpBody::SourceAudio {
            data,
            source_id,
            distance,
            sequence_number,
            ..
        } => {
            assert_eq!(source_id, box_id, "the frame names the source, not Bob");
            assert_eq!(distance, 8, "the source's own reach");
            assert_eq!(sequence_number, 3);
            // The relay is the producer here, so the frame is sealed with the
            // shared key: whole blocks, an IV in front, and not the plain wire.
            assert_ne!(data, frame, "the frame was sealed, not copied");
            assert_eq!(data.len() % 16, 0);
            assert!(data.len() >= 32);
        }
        other => panic!("expected SourceAudio, got {other:?}"),
    }
    assert!(alice.receive().is_none(), "60 blocks away is silence");

    // A source in another dimension is silence for everyone in this one.
    harness.relay.sources(vec![jukebox(box_id, 1, 0.0, 32)]);
    settle();
    harness.relay.source_audio(box_id, 4, &frame);
    assert!(bob.receive().is_none());
    harness.relay.shutdown();
}

#[test]
fn a_key_rotation_reaches_every_session_that_answered() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");

    let new_key = *b"rotation-key-01!";
    harness.relay.rotate_key(new_key);

    for client in [&alice, &bob] {
        let packets = harness.control_for(client.player, "the rotated config");
        let Some(TcpPacket::Config(config)) =
            packets.iter().find(|p| matches!(p, TcpPacket::Config(_)))
        else {
            panic!("expected a ConfigPacket, got {packets:?}");
        };
        let encryption = config.encryption.as_ref().expect("the new key rides here");
        let wrapped = client
            .private
            .decrypt(Pkcs1v15Encrypt, &encryption.data)
            .expect("wrapped with that client's own RSA key");
        assert_eq!(
            wrapped.as_slice(),
            new_key.as_slice(),
            "every session is handed the same new key"
        );
    }
    assert!(harness.logs("key rotated"));

    // A client that joins after the rotation starts on the new key: the config
    // its own handshake carried is the rotated one.
    let carol = join(&mut harness, player(3), "Carol");
    let wrapped = carol
        .private
        .decrypt(Pkcs1v15Encrypt, &carol.wrapped)
        .expect("unwrapped");
    assert_eq!(wrapped.as_slice(), new_key.as_slice());
    harness.relay.shutdown();
}

#[test]
fn a_client_that_never_answers_the_mod_check_is_reported() {
    let mut harness = Harness::with(Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        client_mod_required: true,
        client_mod_required_check: Duration::from_millis(500),
        ..Config::default()
    });

    // The mock client's key is generated before the clock starts: this check
    // is wall-clock, and a keygen inside the handshake would eat it, exactly
    // as a real client's slow start would (Java has the same 3 s and the same
    // property). Bob then does the whole handshake — his `PlayerInfo` settles
    // his check — and Alice joins and never says a word.
    let _ = shared_key();
    let _bob = join(&mut harness, player(2), "Bob");
    harness.relay.join(player(1), "Alice");

    // The log line comes first and the event after it, so one pass over the
    // events sees both: `wait` drops what it walks over.
    let mut logged = false;
    let event = harness
        .wait(|event| {
            if let Event::Log { message, .. } = event {
                if message.contains("voice-client-mod-required") {
                    logged = true;
                }
            }
            matches!(event, Event::ModMissing { .. })
        })
        .expect("the player without the mod is reported");
    let Event::ModMissing {
        player: reported,
        name,
    } = event
    else {
        unreachable!()
    };
    assert_eq!(reported, player(1), "the one who never answered");
    assert_eq!(name, "Alice", "the game needs the name for its log line");
    assert!(logged, "the log says which setting did it");

    // The check is spent: one join is kicked at most once, and Bob — whose
    // `PlayerInfo` settled his — is never reported.
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(1_300) {
        if let Some(Event::ModMissing { .. }) = harness.next() {
            panic!("the check must fire once per join");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    harness.relay.shutdown();
}

#[test]
fn the_mod_check_is_off_unless_it_is_asked_for() {
    let mut harness = Harness::new();
    harness.relay.join(player(1), "Alice");
    assert!(
        harness
            .wait(|event| matches!(event, Event::ModMissing { .. }))
            .is_none(),
        "clientModRequired is false in Java's own config"
    );
    harness.relay.shutdown();
}

#[test]
fn a_language_request_is_answered_with_the_forced_language() {
    let mut harness = Harness::with(Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        forced_language: Some("ja_jp".into()),
        ..Config::default()
    });
    let alice = join(&mut harness, player(1), "Alice");

    alice.channel(
        &harness.relay,
        TcpPacket::LanguageRequest {
            language: "ru_ru".into(),
        },
    );
    let packets = harness.control_for(alice.player, "the language");
    assert_eq!(
        packets,
        vec![TcpPacket::Language {
            // The name is the one the client asked for, not the forced one:
            // `PlayerChannelHandler.sendLanguage` sends `requestedLanguage`
            // and lets `getClientLanguage` resolve the strings.
            name: "ru_ru".into(),
            // `ja_jp` is a language this relay does not ship, and Java answers
            // a forced language it does not know with no strings at all
            // (`languages[forced] ?: ImmutableMap.of()`).
            language: Vec::new(),
        }],
        "forcedLanguage changes the strings, not the name"
    );
    harness.relay.shutdown();
}

#[test]
fn without_a_forced_language_the_client_keeps_its_own() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");

    alice.channel(
        &harness.relay,
        TcpPacket::LanguageRequest {
            language: "ru_ru".into(),
        },
    );
    let packets = harness.control_for(alice.player, "the language");
    assert_eq!(
        packets,
        vec![TcpPacket::Language {
            name: "ru_ru".into(),
            // The `[client]` scope of `languages/ru_ru.toml`, flattened the
            // way `VoiceServerLanguages.languageToMapOfStrings` does it.
            language: vec![(
                "pv.activation.proximity".to_string(),
                "Близость".to_string()
            )],
        }]
    );

    // A request that names no language at all gets the server's default.
    alice.channel(
        &harness.relay,
        TcpPacket::LanguageRequest {
            language: String::new(),
        },
    );
    let packets = harness.control_for(alice.player, "the default language");
    assert_eq!(
        packets,
        vec![TcpPacket::Language {
            name: "en_us".into(),
            // Java's own `languages/en_us.toml`, compiled in.
            language: vec![(
                "pv.activation.proximity".to_string(),
                "Proximity".to_string()
            )],
        }],
        "`default_language` answers an empty request"
    );

    // A language neither the relay nor the client has is answered with the
    // default one's strings (Java's `getLanguage(null, …)`), under the name the
    // client asked for.
    alice.channel(
        &harness.relay,
        TcpPacket::LanguageRequest {
            language: "de_de".into(),
        },
    );
    let packets = harness.control_for(alice.player, "an unknown language");
    assert_eq!(
        packets,
        vec![TcpPacket::Language {
            name: "de_de".into(),
            language: vec![(
                "pv.activation.proximity".to_string(),
                "Proximity".to_string()
            )],
        }],
        "an unknown language falls back to the default"
    );
    harness.relay.shutdown();
}

#[test]
fn an_owners_language_file_wins_over_the_compiled_in_strings() {
    let dir = std::env::temp_dir().join(format!("pv-languages-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a folder for the languages");
    // One key, reworded; everything else is left to the file the relay ships.
    std::fs::write(
        dir.join("ru_ru.toml"),
        "[client.pv.activation]\nproximity = \"Вплотную\"\n",
    )
    .expect("the owner's file");

    let (catalogue, warnings) = Catalogue::load(Some(&dir));
    assert_eq!(warnings, Vec::<String>::new(), "a good file is no warning");
    let strings = catalogue.client("ru_ru", "en_us", None);
    assert_eq!(
        strings,
        vec![(
            "pv.activation.proximity".to_string(),
            "Вплотную".to_string()
        )],
        "the owner's word"
    );
    // `languages/en_us.toml` is seeded on the first start, so the owner has a
    // file to edit; the one they wrote is left exactly as it was.
    assert!(dir.join("en_us.toml").exists(), "the folder is seeded");
    assert_eq!(
        std::fs::read_to_string(dir.join("ru_ru.toml")).expect("the owner's file"),
        "[client.pv.activation]\nproximity = \"Вплотную\"\n",
        "an existing file is never overwritten"
    );
    // Java's `fillMissing`: a key the owner's file does not name keeps the
    // word from the file compiled in.
    assert!(
        catalogue
            .server("ru_ru", "en_us", None)
            .iter()
            .any(|(key, value)| {
                key == "pv.mutes.unmuted" && value == "С вас снят мут"
            })
    );

    // A file that is not a language file is a warning, and the rest still run.
    std::fs::write(dir.join("broken.toml"), "[client\nproximity = 1\n").expect("a broken file");
    let (_, warnings) = Catalogue::load(Some(&dir));
    assert_eq!(warnings.len(), 1, "one warning: {warnings:?}");
    assert!(warnings[0].contains("broken.toml"), "{}", warnings[0]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_relay_answers_from_the_languages_folder_it_was_given() {
    let dir = std::env::temp_dir().join(format!("pv-languages-relay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a folder for the languages");
    std::fs::write(
        dir.join("ru_ru.toml"),
        "[client.pv.activation]\nproximity = \"Вплотную\"\n",
    )
    .expect("the owner's file");

    let mut harness = Harness::with(Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        languages_dir: Some(dir.clone()),
        ..Config::default()
    });
    let alice = join(&mut harness, player(1), "Alice");
    alice.channel(
        &harness.relay,
        TcpPacket::LanguageRequest {
            language: "ru_ru".into(),
        },
    );
    let packets = harness.control_for(alice.player, "the language");
    assert_eq!(
        packets,
        vec![TcpPacket::Language {
            name: "ru_ru".into(),
            language: vec![(
                "pv.activation.proximity".to_string(),
                "Вплотную".to_string()
            )],
        }],
        "the folder is read before the first request"
    );
    // The folder was seeded by the start itself, not by the test.
    assert!(dir.join("en_us.toml").exists());
    harness.relay.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn java_s_language_files_parse_as_they_are_written() {
    // Both scopes, a nested table and Java's multi-line string, exactly as
    // `languages/en_us.toml` in the plugin has them.
    let catalogue = Catalogue::builtin();
    let server = catalogue.server("en_us", "en_us", None);
    let kick = server
        .iter()
        .find(|(key, _)| key == "pv.error.mod_missing_kick_message")
        .map(|(_, value)| value.clone())
        .expect("the kick message");
    assert_eq!(
        kick,
        "Sorry, you need to install the Plasmo Voice mod to play on this server.\n\
         Download here: https://modrinth.com/plugin/plasmo-voice",
        "the newline after the opening `\"\"\"` is dropped, as TOML says"
    );
    assert!(
        server
            .iter()
            .any(|(key, value)| key == "pv.mutes.durations.minutes" && value == "for %s min")
    );
    // The client scope is the packet's map, and only that scope: a `[server]`
    // key never travels to a client.
    assert_eq!(
        catalogue.client("en_us", "en_us", None),
        vec![(
            "pv.activation.proximity".to_string(),
            "Proximity".to_string()
        )]
    );
}

/// `VoiceServerLanguages.getLanguage(name, SERVER)`: the `[server]` scope is
/// resolved by the same rule as the client one — a forced language wins, and a
/// name no file has is answered with `default_language` — and the two scopes
/// never mix.
#[test]
fn the_server_scope_is_resolved_like_the_client_one() {
    let catalogue = Catalogue::builtin();
    let russian = catalogue.server("ru_ru", "en_us", None);
    assert!(
        russian.iter().any(|(key, value)| {
            key == "pv.mutes.permanently_muted"
                && value == "Вам запрещено говорить навсегда. Причина: %s"
        }),
        "the game renders its own messages from this scope"
    );
    // Java re-asks for `null` when the name is unknown, which is the default
    // language's map.
    assert_eq!(
        catalogue.server("de_de", "en_us", None),
        catalogue.server("en_us", "en_us", None),
        "an unknown name falls back to the default language"
    );
    // `forcedLanguage` is the platform translator's too: it reaches the scope
    // the server speaks in, not only the one it sends to clients.
    assert_eq!(catalogue.server("en_us", "en_us", Some("ru_ru")), russian);
    // A forced name the catalogue does not have leaves nothing to render, and
    // the game keeps the component for the client — Java's `ImmutableMap.of()`.
    assert!(catalogue.server("en_us", "en_us", Some("de_de")).is_empty());
    // A `[client]` key is not in the server's scope: a client's own strings
    // never become a message the server says.
    assert!(
        !russian
            .iter()
            .any(|(key, _)| key == "pv.activation.proximity")
    );
}

#[test]
fn a_server_muted_player_is_silent_and_marked_muted() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 1.0)]);
    settle();

    // `/vmute Alice` with no duration: permanent, as `permanent` is in Java.
    harness
        .relay
        .mute(player(1), None, Some("being loud"), false);
    let update = harness.control_for(player(2), "the muted record");
    assert!(
        update.iter().any(|packet| matches!(
            packet,
            TcpPacket::PlayerInfoUpdate { player: info }
                if info.player_id == player(1) && info.muted
        )),
        "Bob is told Alice is muted, got {update:?}"
    );
    alice.send_audio(&harness.relay, &[7; 32], 16);
    assert!(
        bob.receive().is_none(),
        "a muted player's audio is not relayed"
    );

    // `/vunmute Alice`: the record says so, and the audio comes back.
    harness.relay.unmute(player(1));
    let update = harness.control_for(player(2), "the unmuted record");
    assert!(
        update.iter().any(|packet| matches!(
            packet,
            TcpPacket::PlayerInfoUpdate { player: info }
                if info.player_id == player(1) && !info.muted
        )),
        "Bob is told the mute is lifted, got {update:?}"
    );
    alice.send_audio(&harness.relay, &[7; 32], 16);
    assert!(bob.receive().is_some(), "an unmuted player is heard again");
    harness.relay.shutdown();
}

#[test]
fn a_mute_event_carries_what_the_player_is_told() {
    let mut harness = Harness::new();
    let _alice = join(&mut harness, player(1), "Alice");

    harness.relay.mute(
        player(1),
        Some(MuteDuration {
            unit: MuteUnit::Minutes,
            amount: 5,
        }),
        Some("being loud"),
        false,
    );
    let event = harness
        .wait(|event| matches!(event, Event::Mute { .. }))
        .expect("the game is told to notify the player");
    let Event::Mute {
        player: muted,
        name,
        muted: on,
        duration,
        reason,
        ..
    } = event
    else {
        unreachable!()
    };
    assert_eq!(muted, player(1));
    assert_eq!(name, "Alice");
    assert!(on);
    assert_eq!(
        duration,
        Some(MuteDuration {
            unit: MuteUnit::Minutes,
            amount: 5
        }),
        "the unit the admin typed, for `pv.mutes.temporarily_muted`"
    );
    assert_eq!(reason.as_deref(), Some("being loud"));
    harness.relay.shutdown();
}

#[test]
fn a_temporary_mute_lifts_itself() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 1.0)]);
    settle();

    harness.relay.mute(
        player(1),
        Some(MuteDuration {
            unit: MuteUnit::Seconds,
            amount: 1,
        }),
        None,
        false,
    );
    harness.control_for(player(2), "the muted record");
    alice.send_audio(&harness.relay, &[7; 32], 16);
    assert!(bob.receive().is_none(), "muted for the second it lasts");

    // `VoiceMuteManager.tick` lifts it when the time is up, and everyone is
    // told; the sweep runs every second, so give it two.
    let event = harness
        .wait(|event| matches!(event, Event::Mute { muted: false, .. }))
        .expect("the mute runs out");
    let Event::Mute { player: lifted, .. } = event else {
        unreachable!()
    };
    assert_eq!(lifted, player(1));
    // The listeners are told in the same breath; that broadcast has a test of
    // its own just above, so this one only checks the lift reached the relay.
    alice.send_audio(&harness.relay, &[7; 32], 16);
    assert!(bob.receive().is_some(), "and the player is heard again");
    harness.relay.shutdown();
}

#[test]
fn a_mute_belongs_to_the_player_not_the_session() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let bob = join(&mut harness, player(2), "Bob");
    harness
        .relay
        .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 1.0)]);
    settle();
    harness.relay.mute(player(1), None, None, false);
    harness.control_for(player(2), "the muted record");
    // The muted player is told as well (`broadcastPlayerInfoUpdate` reaches
    // everyone configured), so that record is drained before the reconnect.
    harness.control_for(player(1), "her own muted record");

    // A reconnect is a new session and a new secret, but the same punishment
    // (`MuteStorage` is per player in Java).
    let _ = alice;
    harness.relay.leave(player(1));
    let alice = join(&mut harness, player(1), "Alice");
    alice.send_audio(&harness.relay, &[7; 32], 16);
    assert!(
        bob.receive().is_none(),
        "a muted player who reconnects stays muted"
    );
    harness.relay.shutdown();
}

#[test]
fn the_muted_flag_is_the_servers_and_the_microphone_is_the_players() {
    let mut harness = Harness::new();
    let alice = join(&mut harness, player(1), "Alice");
    let _bob = join(&mut harness, player(2), "Bob");

    // Alice mutes her own microphone: Java's `microphoneMuted`, not `muted` —
    // a client draws a different icon for each (`HIDE_CLIENT_MUTED`).
    alice.channel(
        &harness.relay,
        TcpPacket::PlayerState {
            voice_disabled: false,
            microphone_muted: true,
        },
    );
    let update = harness.control_for(player(2), "the microphone record");
    let info = update
        .iter()
        .find_map(|packet| match packet {
            TcpPacket::PlayerInfoUpdate { player: info } if info.player_id == player(1) => {
                Some(info.clone())
            }
            _ => None,
        })
        .expect("Bob is told about Alice's microphone");
    assert!(info.microphone_muted, "the microphone switch is her own");
    assert!(!info.muted, "and it is not a server mute");

    // The server mutes her: the same update says `muted`, and the microphone
    // flag is still hers.
    harness.relay.mute(player(1), None, None, false);
    let update = harness.control_for(player(2), "the muted record");
    let info = update
        .iter()
        .find_map(|packet| match packet {
            TcpPacket::PlayerInfoUpdate { player: info } if info.player_id == player(1) => {
                Some(info.clone())
            }
            _ => None,
        })
        .expect("Bob is told about the server mute");
    assert!(info.muted, "a server mute is `muted`");
    assert!(info.microphone_muted, "her own switch is untouched");
    harness.relay.shutdown();
}

#[test]
fn a_mute_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("pv-mutes-restart-{}", std::process::id()));
    let path = dir.join("voice_mutes.json");
    let config = || Config {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mute_file: Some(path.clone()),
        ..Config::default()
    };
    // Waits for the writer thread, which runs beside the relay.
    fn written(path: &std::path::Path, what: impl Fn(&str) -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < PATIENCE {
            if let Ok(text) = std::fs::read_to_string(path) {
                if what(&text) {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }
    let alice_uuid = "00000000-0000-0000-0000-000000000001";

    {
        let mut harness = Harness::with(config());
        let _alice = join(&mut harness, player(1), "Alice");
        harness
            .relay
            .mute(player(1), None, Some("being loud"), false);
        assert!(
            written(&path, |text| text.contains(alice_uuid)),
            "the mute is written to {} while the server runs",
            path.display()
        );
        harness.relay.shutdown();
    }

    // A new relay, as after a restart: the file is read before the thread
    // starts, and the game is told what is in it.
    {
        let mut harness = Harness::with(config());
        let event = harness
            .wait(|event| matches!(event, Event::Mute { muted: true, .. }))
            .expect("the restored mute is announced");
        let Event::Mute {
            player: muted,
            muted: on,
            reason,
            ..
        } = event
        else {
            unreachable!()
        };
        assert_eq!(muted, player(1));
        assert!(on);
        assert_eq!(reason.as_deref(), Some("being loud"));

        let alice = join(&mut harness, player(1), "Alice");
        let bob = join(&mut harness, player(2), "Bob");
        harness
            .relay
            .positions(vec![place(player(1), 0, 0.0), place(player(2), 0, 1.0)]);
        settle();
        alice.send_audio(&harness.relay, &[7; 32], 16);
        assert!(
            bob.receive().is_none(),
            "a mute read from the file still silences the player"
        );

        // `/vunmute` takes it out of the file too.
        harness.relay.unmute(player(1));
        assert!(
            written(&path, |text| !text.contains(alice_uuid)),
            "the lifted mute leaves the file"
        );
        harness.relay.shutdown();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
