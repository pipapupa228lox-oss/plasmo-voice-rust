//! The PlasmoVoice client, ported to Rust for Horizon.
//!
//! What a session needs, and what is here:
//!
//! 1. `ConnectionPacket` from the server, arriving in the plugin channel
//!    `plasmo:voice/v2`: a secret and the UDP address. Then `ConfigPacket`
//!    with the sample rate, the MTU and the activations.
//! 2. A [`VoiceClient`] on that address: microphone frames in
//!    (`send_frame`), other players' frames out (`poll`).
//! 3. The control packets back: `PlayerInfoPacket` to join,
//!    `PlayerStatePacket` when muting, `PlayerAudioEndPacket` when a burst
//!    ends.
//!
//! The game side — reading the channel, feeding the microphone, mixing the
//! result — is the native Horizon mod's job; this crate is the protocol.

pub mod audio;
pub mod codec;
pub mod crypto;
#[cfg(feature = "device")]
pub mod device;
pub mod identity;
pub mod state;
pub mod session;

#[cfg(test)]
mod state_tests;

pub use codec::{from_capture, AudioCodec, RawCodec};
#[cfg(feature = "opus")]
pub use codec::OpusCodec;
pub use pv_proto as proto;
pub use session::{Control, Incoming, VoiceClient};

use proto::{TcpPacket, VoiceActivation};

/// The version reported in `PlayerInfoPacket`. It cannot be our own: the
/// server compares the major version with its own and drops clients below
/// `clientModMinVersion` (2.0.0 by default), so this is the Java version whose
/// protocol this crate implements, 2.1.17.
pub const CLIENT_VERSION: &str = "2.1.17";

/// What the Java client answers to `PlayerInfoRequestPacket`.
pub fn player_info(
    minecraft_version: &str,
    public_key: Vec<u8>,
    microphone_muted: bool,
) -> TcpPacket {
    TcpPacket::PlayerInfo {
        voice_disabled: false,
        microphone_muted,
        minecraft_version: minecraft_version.to_string(),
        version: CLIENT_VERSION.to_string(),
        public_key,
    }
}

/// The packet that tells the server we went quiet.
pub fn control_packet(control: Control) -> TcpPacket {
    match control {
        Control::PlayerInfo {
            voice_disabled,
            microphone_muted,
        } => TcpPacket::PlayerState {
            voice_disabled,
            microphone_muted,
        },
        Control::AudioEnd {
            sequence_number,
            activation_id,
            distance,
        } => TcpPacket::PlayerAudioEnd {
            sequence_number,
            activation_id,
            distance,
        },
    }
}

/// The activation a session starts on: proximity, when the server offers it.
pub fn default_activation(config: &proto::Config) -> Option<&VoiceActivation> {
    config.proximity_activation()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::{UdpBody, UdpPacket, Uuid};
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;

    const SECRET: Uuid = *b"secretsecretsecr";

    /// Plays the server: takes one `PlayerAudioPacket` and sends it back as
    /// `SourceAudioPacket`, which is what a server does for everyone in range.
    fn echo_server(socket: UdpSocket, secret: Uuid) -> thread::JoinHandle<(Uuid, i16, bool)> {
        thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            let (read, from) = socket.recv_from(&mut buffer).expect("a datagram");
            let packet = UdpPacket::decode(&buffer[..read]).expect("a voice packet");

            match packet.body {
                UdpBody::PlayerAudio {
                    sequence_number,
                    data,
                    activation_id,
                    distance,
                    stereo,
                } => {
                    let reply = UdpPacket::now(
                        secret,
                        UdpBody::SourceAudio {
                            sequence_number,
                            data,
                            source_id: *b"another-player00",
                            source_state: 1,
                            distance,
                        },
                    );
                    socket.send_to(&reply.encode(), from).expect("a reply");
                    (activation_id, distance, stereo)
                }
                other => panic!("expected player audio, got {other:?}"),
            }
        })
    }

    fn collect(client: &mut VoiceClient) -> Vec<Incoming> {
        for _ in 0..200 {
            let incoming = client.poll().expect("poll");
            if !incoming.is_empty() {
                return incoming;
            }
            thread::sleep(Duration::from_millis(5));
        }
        Vec::new()
    }

    #[test]
    fn a_frame_goes_out_and_comes_back_as_a_source() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let server_thread = echo_server(server, SECRET);

        let mut client = VoiceClient::connect(
            addr,
            SECRET,
            VoiceActivation::proximity_id(),
            16,
            false,
            Some(Box::new(RawCodec::new(960))),
        )
        .unwrap();

        let samples: Vec<i16> = (0..960).map(|i| (i as i16).wrapping_mul(37)).collect();
        client.send_frame(&samples).unwrap();

        let incoming = collect(&mut client);
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].samples, samples);
        assert_eq!(incoming[0].source_id, *b"another-player00");
        assert_eq!(incoming[0].state, 1);

        let (activation, distance, stereo) = server_thread.join().unwrap();
        assert_eq!(activation, VoiceActivation::proximity_id());
        assert_eq!(distance, 16);
        assert!(!stereo);
    }

    #[cfg(feature = "opus")]
    #[test]
    fn the_same_path_carries_real_opus() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let server_thread = echo_server(server, SECRET);

        let codec = OpusCodec::new(48_000, 1024, false).unwrap();
        let mut client = VoiceClient::connect(
            addr,
            SECRET,
            VoiceActivation::proximity_id(),
            8,
            false,
            Some(Box::new(codec)),
        )
        .unwrap();

        let samples: Vec<i16> = (0..960)
            .map(|i| {
                let phase = 2.0 * std::f32::consts::PI * 220.0 * i as f32 / 48_000.0;
                (phase.sin() * 10_000.0) as i16
            })
            .collect();
        client.send_frame(&samples).unwrap();

        let incoming = collect(&mut client);
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].samples.len(), samples.len());
        server_thread.join().unwrap();
    }

    #[test]
    fn the_control_packets_match_the_java_layout() {
        let end = control_packet(Control::AudioEnd {
            sequence_number: 12,
            activation_id: VoiceActivation::proximity_id(),
            distance: 16,
        });
        let bytes = end.encode();
        assert_eq!(bytes[0], 0x0c, "PlayerAudioEndPacket is id 12");
        assert_eq!(&bytes[1..9], &12_i64.to_be_bytes());
        assert_eq!(&bytes[9..25], &VoiceActivation::proximity_id());
        assert_eq!(&bytes[25..27], &16_i16.to_be_bytes());

        let info = player_info("1.21.5", vec![1, 2, 3], false);
        let bytes = info.encode();
        assert_eq!(bytes[0], 0x0a, "PlayerInfoPacket is id 10");
    }
}
