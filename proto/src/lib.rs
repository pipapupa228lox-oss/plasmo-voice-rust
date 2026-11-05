//! A Rust implementation of the PlasmoVoice 2.1.x wire protocol, ported from
//! `protocol/` of plasmo-voice 2.1.17 (LGPL-3.0).
//!
//! Two packet sets travel over two transports:
//!
//! * control packets (`TcpPacket`) go inside the Minecraft plugin channel
//!   [`CHANNEL`], in both directions. The name is historical: they are not
//!   sent over a socket by the client.
//! * audio packets (`UdpPacket`) go to the voice server's own UDP port, and
//!   every datagram starts with [`UDP_MAGIC`].
//!
//! Nothing here touches the network: it turns bytes into packets and back.

pub mod bytes;
pub mod data;
pub mod packets;

pub use bytes::{name_uuid, Error, Reader, Result, Uuid, Writer};
pub use data::{
    CaptureInfo, CodecInfo, GameProfile, PlayerIconConfig, Pos3d, VoiceActivation, VoicePlayerInfo,
    VoiceSourceLine, PROXIMITY_NAME,
};
pub use packets::{
    source_line_id, Config, EncryptionInfo, SourceInfo, TcpPacket, UdpBody, UdpPacket, CHANNEL,
    FLAG_CHANNEL, SERVICE_CHANNEL, UDP_MAGIC,
};

/// The clock the Java codec stamps packets with, in milliseconds.
pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Uuid {
        *b"0123456789abcdef"
    }

    #[test]
    fn activation_ids_are_java_name_uuids() {
        // UUID.nameUUIDFromBytes("proximity_activation".getBytes(UTF_8)) in Java.
        assert_eq!(
            bytes::uuid_to_string(VoiceActivation::proximity_id()),
            "4aec07ba-d109-3345-9a0a-92022a116cd0"
        );
    }

    #[test]
    fn udp_header_is_magic_then_id_then_secret_then_time() {
        let packet = UdpPacket {
            secret: secret(),
            timestamp: 0x0102_0304_0506_0708,
            body: UdpBody::Ping {
                time: 42,
                server_ip: None,
                server_port: None,
            },
        };
        let bytes = packet.encode();

        assert_eq!(&bytes[0..4], &[0x4e, 0x90, 0x04, 0xe9]);
        assert_eq!(bytes[4], 0x01, "ping is packet id 1");
        assert_eq!(&bytes[5..21], &secret());
        assert_eq!(&bytes[21..29], &0x0102_0304_0506_0708_i64.to_be_bytes());
        assert_eq!(&bytes[29..37], &42_i64.to_be_bytes());
    }

    #[test]
    fn player_audio_round_trips() {
        let packet = UdpPacket {
            secret: secret(),
            timestamp: 7,
            body: UdpBody::PlayerAudio {
                sequence_number: 1234,
                data: vec![1, 2, 3, 4, 5],
                activation_id: VoiceActivation::proximity_id(),
                distance: 16,
                stereo: false,
            },
        };
        let decoded = UdpPacket::decode(&packet.encode()).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn source_audio_round_trips() {
        let packet = UdpPacket {
            secret: secret(),
            timestamp: 9,
            body: UdpBody::SourceAudio {
                sequence_number: 88,
                data: vec![9; 120],
                source_id: name_uuid("player"),
                source_state: 1,
                distance: 8,
            },
        };
        assert_eq!(UdpPacket::decode(&packet.encode()).unwrap(), packet);
    }

    #[test]
    fn a_datagram_without_the_magic_number_is_refused() {
        let mut bytes = UdpPacket {
            secret: secret(),
            timestamp: 0,
            body: UdpBody::Ping {
                time: 0,
                server_ip: None,
                server_port: None,
            },
        }
        .encode();
        bytes[0] = 0x00;
        assert!(matches!(
            UdpPacket::decode(&bytes),
            Err(Error::BadMagic(_))
        ));
    }

    #[test]
    fn connection_packet_round_trips() {
        let packet = TcpPacket::Connection {
            secret: secret(),
            ip: "127.0.0.1".into(),
            port: 25566,
        };
        assert_eq!(TcpPacket::decode(&packet.encode()).unwrap(), packet);
    }

    #[test]
    fn player_info_carries_the_public_key() {
        let packet = TcpPacket::PlayerInfo {
            voice_disabled: false,
            microphone_muted: true,
            minecraft_version: "1.21.5".into(),
            version: "0.1.0".into(),
            public_key: vec![7; 32],
        };
        assert_eq!(TcpPacket::decode(&packet.encode()).unwrap(), packet);
    }

    #[test]
    fn config_round_trips_with_a_line_and_an_activation() {
        let activation = VoiceActivation {
            name: PROXIMITY_NAME.into(),
            translation: "pv.activation.proximity".into(),
            icon: "proximity".into(),
            id: VoiceActivation::proximity_id(),
            distances: vec![8, 16, 32],
            default_distance: 16,
            proximity: true,
            transitive: false,
            stereo_supported: true,
            encoder: Some(CodecInfo {
                name: "opus".into(),
                params: vec![("mtuSize".into(), "1024".into())],
            }),
            weight: 10,
        };
        let config = Config {
            server_id: name_uuid("server"),
            capture: CaptureInfo {
                sample_rate: 48000,
                mtu_size: 1024,
                encoder: Some(CodecInfo {
                    name: "opus".into(),
                    params: vec![("bitrate".into(), "32000".into())],
                }),
            },
            encryption: None,
            source_lines: vec![VoiceSourceLine {
                name: "main".into(),
                translation: "pv.line.main".into(),
                icon: "main".into(),
                default_volume: 1.0,
                weight: 10,
                id: source_line_id("main"),
                players: None,
            }],
            activations: vec![activation],
            permissions: vec![("pv.activate".into(), true)],
            player_icon: Some(PlayerIconConfig {
                visibility: vec!["ALWAYS".into()],
                offset: Pos3d {
                    x: 0.0,
                    y: 0.5,
                    z: 0.0,
                },
            }),
        };

        let packet = TcpPacket::Config(Box::new(config));
        let decoded = TcpPacket::decode(&packet.encode()).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn a_source_info_request_round_trips() {
        // 0x0f, client to server: the relay only answers a source it parsed,
        // so a missing arm here would silently turn every ask into `Unknown`.
        let packet = TcpPacket::SourceInfoRequest {
            source_id: name_uuid("jukebox"),
        };
        let bytes = packet.encode();
        assert_eq!(bytes[0], 0x0f);
        assert_eq!(TcpPacket::decode(&bytes).unwrap(), packet);
    }

    #[test]
    fn a_static_source_carries_its_place() {
        let id = name_uuid("jukebox");
        let source = SourceInfo::static_source(
            "plasmo:voice",
            id,
            source_line_id("main"),
            "Jukebox",
            Pos3d {
                x: 12.5,
                y: 64.0,
                z: -3.25,
            },
            Pos3d::default(),
        );
        assert_eq!(source.kind, "STATIC");
        let packet = TcpPacket::SourceInfo {
            source: source.clone(),
        };
        let decoded = TcpPacket::decode(&packet.encode()).unwrap();
        assert_eq!(decoded, packet, "the STATIC tail is kept as written");
        let (place, look) = source.static_place().expect("a static source has a place");
        assert_eq!(place, Pos3d { x: 12.5, y: 64.0, z: -3.25 });
        assert_eq!(look, Pos3d::default());
        // A player source has no place in its record: the field is not there.
        assert!(SourceInfo::static_source("a", id, id, "n", Pos3d::default(), Pos3d::default())
            .static_place()
            .is_some());
        let player = SourceInfo {
            kind: "PLAYER".into(),
            ..source
        };
        assert_eq!(player.static_place(), None);
    }

    #[test]
    fn a_2_1_6_config_without_a_player_icon_still_decodes() {
        let config = Config {
            server_id: name_uuid("server"),
            capture: CaptureInfo {
                sample_rate: 48000,
                mtu_size: 1024,
                encoder: None,
            },
            encryption: None,
            source_lines: Vec::new(),
            activations: Vec::new(),
            permissions: Vec::new(),
            player_icon: None,
        };
        let bytes = TcpPacket::Config(Box::new(config)).encode();

        match TcpPacket::decode(&bytes).unwrap() {
            TcpPacket::Config(decoded) => {
                assert_eq!(decoded.player_icon, None);
                assert_eq!(decoded.capture.sample_rate, 48000);
                assert!(decoded.activations.is_empty());
            }
            other => panic!("expected config, got {other:?}"),
        }
    }

    #[test]
    fn several_packets_in_one_channel_payload() {
        let first = TcpPacket::PlayerState {
            voice_disabled: false,
            microphone_muted: true,
        };
        let second = TcpPacket::PlayerAudioEnd {
            sequence_number: 5,
            activation_id: VoiceActivation::proximity_id(),
            distance: 16,
        };
        let mut payload = first.encode();
        payload.extend(second.encode());

        let decoded = TcpPacket::decode_all(&payload).unwrap();
        assert_eq!(decoded, vec![first, second]);
    }

    #[test]
    fn an_unknown_packet_keeps_its_bytes() {
        let bytes = vec![0x7f, 1, 2, 3];
        assert_eq!(
            TcpPacket::decode(&bytes).unwrap(),
            TcpPacket::Unknown {
                id: 0x7f,
                payload: vec![1, 2, 3],
            }
        );
    }
}
