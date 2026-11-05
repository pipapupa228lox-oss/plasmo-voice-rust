//! The handshake, end to end: the packets a real 2.1.17 server sends, over a
//! real UDP socket, with the client's own state machine on the other side.
//!
//! The order matters and is the server's: `PlayerInfoRequest` (it asks on
//! join, `PlayerInfoRequestScheduler`), then `Connection`, then — only once a
//! datagram from our secret arrives — `Config` with the AES key.

use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use pv_proto::{
    name_uuid, CaptureInfo, CodecInfo, TcpPacket, UdpBody, UdpPacket, VoiceActivation,
    VoiceSourceLine, PROXIMITY_NAME,
};

use crate::identity::Identity;
use crate::state::VoiceSession;

const SECRET: [u8; 16] = *b"secretsecretsecr";

fn config_packet(encryption: Option<pv_proto::EncryptionInfo>) -> TcpPacket {
    TcpPacket::Config(Box::new(pv_proto::Config {
        server_id: name_uuid("server"),
        capture: CaptureInfo {
            sample_rate: 48_000,
            mtu_size: 1024,
            encoder: Some(CodecInfo {
                name: "opus".into(),
                params: vec![("bitrate".into(), "32000".into())],
            }),
        },
        encryption,
        source_lines: vec![VoiceSourceLine {
            name: "main".into(),
            translation: "pv.line.main".into(),
            icon: "main".into(),
            default_volume: 1.0,
            weight: 10,
            id: pv_proto::source_line_id("main"),
            players: None,
        }],
        activations: vec![VoiceActivation {
            name: PROXIMITY_NAME.into(),
            translation: "pv.activation.proximity".into(),
            icon: "proximity".into(),
            id: VoiceActivation::proximity_id(),
            distances: vec![8, 16, 32],
            default_distance: 16,
            proximity: true,
            transitive: false,
            stereo_supported: true,
            encoder: None,
            weight: 10,
        }],
        permissions: vec![("pv.activate".into(), true)],
        player_icon: None,
    }))
}

/// The server's UDP side: eats the keep-alive ping, then echoes one frame
/// back as another player's voice. `same_data` is what a real server does
/// with an encrypted payload: it never opens it, it forwards the bytes.
fn echo_server(socket: UdpSocket) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        loop {
            let (read, from) = socket.recv_from(&mut buffer).expect("a datagram");
            let packet = UdpPacket::decode(&buffer[..read]).expect("a voice packet");
            match packet.body {
                UdpBody::Ping { .. } => continue,
                UdpBody::PlayerAudio {
                    sequence_number,
                    data,
                    distance,
                    ..
                } => {
                    let reply = UdpPacket::now(
                        SECRET,
                        UdpBody::SourceAudio {
                            sequence_number,
                            data,
                            source_id: *b"another-player00",
                            source_state: 1,
                            distance,
                        },
                    );
                    socket.send_to(&reply.encode(), from).expect("a reply");
                    return;
                }
                _ => continue,
            }
        }
    })
}

/// Calls `touch` until the session says something on the channel, which after
/// a silence is the `PlayerInfo` that asks for a new one.
fn wait_for_an_ask(session: &mut VoiceSession) -> Vec<TcpPacket> {
    for _ in 0..200 {
        session.touch();
        let outgoing = session.take_outgoing();
        if !outgoing.is_empty() {
            return outgoing;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("the client never asked for a new session");
}

fn open_session(address: std::net::SocketAddr) -> VoiceSession {
    let mut session = VoiceSession::new("1.21.5").with_identity(Identity::generate().unwrap());

    // 1. The server asks who we are; the answer carries the RSA key it will
    //    wrap the voice key with.
    session
        .handle_channel(&TcpPacket::PlayerInfoRequest.encode())
        .unwrap();
    let outgoing = session.take_outgoing();
    match outgoing.as_slice() {
        [TcpPacket::PlayerInfo {
            version, public_key, ..
        }] => {
            assert_eq!(version, "2.1.17", "the server compares the major version");
            assert!(crate::identity::parses_as_x509(public_key));
        }
        other => panic!("expected one PlayerInfo, got {other:?}"),
    }

    // 2. ConnectionPacket: the secret and where the audio goes. The socket
    //    opens and pings; nothing goes back on the channel.
    session
        .handle_channel(
            &TcpPacket::Connection {
                secret: SECRET,
                ip: "127.0.0.1".into(),
                port: address.port() as i32,
            }
            .encode(),
        )
        .unwrap();
    assert!(session.take_outgoing().is_empty());
    assert!(session.is_connected(), "the UDP socket is open");
    assert!(!session.has_config(), "no codec before the config");

    session
}

#[test]
fn a_server_drives_the_session_from_request_to_audio() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let voice_addr = udp.local_addr().unwrap();
    let server = echo_server(udp);

    let mut session = open_session(voice_addr);

    // 3. ConfigPacket: the codec, the activations, the rate.
    session
        .handle_channel(&config_packet(None).encode())
        .unwrap();
    assert!(session.has_config());
    assert_eq!(session.frame_size(), Some(960), "20 ms at 48 kHz");
    assert_eq!(session.activations().len(), 1);
    assert!(matches!(
        session.take_outgoing().as_slice(),
        [TcpPacket::PlayerActivationDistances { .. }]
    ));

    // 4. A microphone frame goes to the server and comes back as a source.
    let samples: Vec<i16> = (0..960)
        .map(|i| {
            let phase = 2.0 * std::f32::consts::PI * 300.0 * i as f32 / 48_000.0;
            (phase.sin() * 9_000.0) as i16
        })
        .collect();
    assert!(session.feed_microphone(&samples).unwrap().is_some());

    let mut heard = Vec::new();
    for _ in 0..200 {
        heard = session.poll_audio();
        if !heard.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].samples.len(), samples.len());
    assert_eq!(heard[0].source_id, *b"another-player00");

    // 5. Going quiet ends the burst, which the game sends as a control packet.
    session.finish_talking();
    assert!(matches!(
        session.take_outgoing().as_slice(),
        [TcpPacket::PlayerAudioEnd { distance: 16, .. }]
    ));

    server.join().unwrap();
}

#[test]
fn the_audio_payload_is_sealed_with_the_key_from_the_config() {
    use rsa::pkcs1v15::Pkcs1v15Encrypt;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::RsaPublicKey;

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let voice_addr = udp.local_addr().unwrap();
    let server = echo_server(udp);

    let identity = Identity::generate().unwrap();
    let public = RsaPublicKey::from_public_key_der(identity.public_key()).unwrap();
    let key = b"0123456789abcdef";
    let wrapped = public
        .encrypt(&mut rsa::rand_core::OsRng, Pkcs1v15Encrypt, key)
        .unwrap();

    let mut session = VoiceSession::new("1.21.5").with_identity(identity);
    session
        .handle_channel(&TcpPacket::PlayerInfoRequest.encode())
        .unwrap();
    session.take_outgoing();
    session
        .handle_channel(
            &TcpPacket::Connection {
                secret: SECRET,
                ip: "127.0.0.1".into(),
                port: voice_addr.port() as i32,
            }
            .encode(),
        )
        .unwrap();

    session
        .handle_channel(
            &config_packet(Some(pv_proto::EncryptionInfo {
                algorithm: "AES/CBC/PKCS5Padding".into(),
                data: wrapped,
            }))
            .encode(),
        )
        .unwrap();
    assert!(session.error().is_none(), "{:?}", session.error());
    assert!(session.has_config());

    // Out: encrypted, so not the Opus bytes verbatim; back in: decrypted with
    // the same key, because the server forwards the payload untouched.
    let samples: Vec<i16> = (0..960).map(|i| (i as i16) * 7).collect();
    assert!(session.feed_microphone(&samples).unwrap().is_some());

    let mut heard = Vec::new();
    for _ in 0..200 {
        heard = session.poll_audio();
        if !heard.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].samples.len(), samples.len());

    server.join().unwrap();
}

#[test]
fn a_silent_server_is_asked_for_a_new_session() {
    // Nothing listens on the voice port: every ping is unanswered, which is
    // what a lost UDP mapping or a restarted server looks like to a client.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let voice_addr = udp.local_addr().unwrap();
    drop(udp);

    let mut session = VoiceSession::new("1.21.5")
        .with_identity(Identity::generate().unwrap())
        .with_reconnect_silence(Duration::from_millis(100));

    session
        .handle_channel(&TcpPacket::PlayerInfoRequest.encode())
        .unwrap();
    session.take_outgoing();
    session
        .handle_channel(
            &TcpPacket::Connection {
                secret: SECRET,
                ip: "127.0.0.1".into(),
                port: voice_addr.port() as i32,
            }
            .encode(),
        )
        .unwrap();
    assert!(session.is_connected());

    let asked = wait_for_an_ask(&mut session);
    assert!(
        matches!(asked.as_slice(), [TcpPacket::PlayerInfo { .. }]),
        "a new session is asked for with `PlayerInfo`, got {asked:?}"
    );
    assert!(!session.is_connected(), "the dead socket is gone");
    assert_eq!(session.reconnects(), 1);
    assert!(session.error().is_none(), "one silence is not an error");
}

#[test]
fn a_new_connection_ends_the_wait_and_resets_the_retries() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let voice_addr = udp.local_addr().unwrap();
    drop(udp);

    let mut session = VoiceSession::new("1.21.5")
        .with_identity(Identity::generate().unwrap())
        .with_reconnect_silence(Duration::from_millis(100));
    session
        .handle_channel(&TcpPacket::PlayerInfoRequest.encode())
        .unwrap();
    session.take_outgoing();
    let connect = |secret: [u8; 16]| {
        TcpPacket::Connection {
            secret,
            ip: "127.0.0.1".into(),
            port: voice_addr.port() as i32,
        }
        .encode()
    };
    session.handle_channel(&connect(SECRET)).unwrap();
    assert_eq!(session.reconnects(), 0);

    wait_for_an_ask(&mut session);

    // The server answers with a new secret, the way the relay's re-key does.
    session
        .handle_channel(&connect(*b"another-secret!!"))
        .unwrap();
    assert!(session.is_connected(), "the session is back");
    assert_eq!(session.reconnects(), 0, "a working session resets the count");
    assert!(session.take_outgoing().is_empty());
}

#[test]
fn muting_stops_the_microphone_and_tells_the_server() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let voice_addr = udp.local_addr().unwrap();

    let mut session = open_session(voice_addr);
    session
        .handle_channel(&config_packet(None).encode())
        .unwrap();
    session.take_outgoing();

    session.set_muted(true);
    assert!(session.feed_microphone(&[0i16; 960]).unwrap().is_none());

    assert!(matches!(
        session.take_outgoing().as_slice(),
        [TcpPacket::PlayerState {
            microphone_muted: true,
            ..
        }]
    ));
}

#[test]
fn a_key_that_is_not_ours_leaves_the_session_unopened() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let voice_addr = udp.local_addr().unwrap();
    let mut session = open_session(voice_addr);

    session
        .handle_channel(
            &config_packet(Some(pv_proto::EncryptionInfo {
                algorithm: "AES/CBC/PKCS5Padding".into(),
                data: vec![1; 256],
            }))
            .encode(),
        )
        .unwrap();

    assert!(session.error().is_some(), "junk must not be taken as a key");
    assert!(!session.has_config());
}
