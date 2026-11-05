//! The client half of a voice session: one UDP socket, the secret the server
//! handed out, and the frames going each way.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use pv_proto::{UdpBody, UdpPacket, Uuid};

use crate::codec::AudioCodec;
use crate::crypto::Aes;

/// One frame of someone else's voice, already decoded.
#[derive(Debug, Clone)]
pub struct Incoming {
    pub source_id: Uuid,
    /// Samples at the session's rate; the mixer decides the volume.
    pub samples: Vec<i16>,
    /// The distance the speaker's activation uses, in blocks.
    pub distance: i16,
    /// `SourceInfo.state`: 0 is idle, 1 speaking.
    pub state: u8,
}

/// What the control channel has to carry back to the server.
#[derive(Debug, Clone, PartialEq)]
pub enum Control {
    PlayerInfo {
        voice_disabled: bool,
        microphone_muted: bool,
    },
    AudioEnd {
        sequence_number: i64,
        activation_id: Uuid,
        distance: i16,
    },
}

/// What the datagrams did, for the log: how many arrived, where the ones that
/// went nowhere were dropped, and how much audio went out. A silent session
/// looks the same whether the server sends nothing or the key is wrong; these
/// numbers tell them apart.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Datagrams read from the socket, of any kind.
    pub datagrams: u64,
    /// Datagrams sealed with another secret: not ours to read.
    pub other_secret: u64,
    /// Audio the AES key could not open.
    pub decrypt_failed: u64,
    /// Audio the codec could not decode.
    pub decode_failed: u64,
    /// Frames that reached the mixer.
    pub frames_played: u64,
    /// Frames the microphone sent.
    pub frames_sent: u64,
    /// Bytes of Opus (sealed) sent.
    pub bytes_sent: u64,
    pub send_failed: u64,
}

pub struct VoiceClient {
    socket: UdpSocket,
    server: SocketAddr,
    secret: Uuid,
    /// Set by the `ConfigPacket` that follows our first UDP packet.
    codec: Option<Box<dyn AudioCodec>>,
    /// The server's AES key, once the config carried one.
    encryption: Option<Aes>,
    activation: Uuid,
    distance: i16,
    stereo: bool,
    sequence: i64,
    /// The last frame sent, so `Control::AudioEnd` can describe it.
    last_frame: Option<(i64, i16)>,
    /// The last datagram that carried our secret: the only proof the server is
    /// still there, because UDP has no close of its own.
    last_rx: Instant,
    stats: Stats,
    /// The first few distinct problems, each once, for the log.
    notes: Vec<String>,
}

impl VoiceClient {
    /// Opens the socket and points it at the voice server. The address is
    /// the one from `ConnectionPacket`. The socket is non-blocking, so the
    /// game thread never waits on audio.
    ///
    /// The codec and the AES key come later, with the `ConfigPacket`: the
    /// server sends it only after it has seen a packet from this secret.
    pub fn connect(
        server: SocketAddr,
        secret: Uuid,
        activation: Uuid,
        distance: i16,
        stereo: bool,
        codec: Option<Box<dyn AudioCodec>>,
    ) -> io::Result<Self> {
        // The wildcard has to be the same family as the server's address:
        // an IPv4 socket cannot send to an IPv6 address (`WSAEAFNOSUPPORT`,
        // what `localhost` → `::1` gave us).
        let wildcard = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(wildcard)?;
        socket.connect(server)?;
        socket.set_nonblocking(true)?;

        Ok(VoiceClient {
            socket,
            server,
            secret,
            codec,
            encryption: None,
            activation,
            distance,
            stereo,
            sequence: 0,
            last_frame: None,
            last_rx: Instant::now(),
            stats: Stats::default(),
            notes: Vec::new(),
        })
    }

    /// How long the server has been quiet. The client pings twice a second and
    /// the server answers every ping, so this staying above a few seconds
    /// means the session is gone — a lost UDP mapping, a restarted server, a
    /// firewall that started dropping.
    pub fn silent_for(&self) -> Duration {
        self.last_rx.elapsed()
    }

    /// What the socket has seen so far.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The first few distinct problems, each once.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Keeps one line per distinct problem: a broken packet arrives 50 times a
    /// second, and the log has to stay readable.
    fn note(&mut self, text: String) {
        if self.notes.len() < 8 && !self.notes.iter().any(|known| known == &text) {
            self.notes.push(text);
        }
    }

    /// The codec the config announced, or `None` until it arrives.
    pub fn set_codec(&mut self, codec: Box<dyn AudioCodec>) {
        self.codec = Some(codec);
    }

    /// The AES key from the config, unpinned by RSA. Every packet's audio
    /// payload is encrypted with it, in both directions.
    pub fn set_encryption(&mut self, encryption: Option<Aes>) {
        self.encryption = encryption;
    }

    pub fn encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    /// For tests and for servers behind a proxy, which announce another port.
    pub fn retarget(&mut self, server: SocketAddr) -> io::Result<()> {
        self.socket.connect(server)?;
        self.server = server;
        self.last_rx = Instant::now();
        Ok(())
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn activation(&self) -> Uuid {
        self.activation
    }

    pub fn distance(&self) -> i16 {
        self.distance
    }

    pub fn set_activation(&mut self, activation: Uuid, distance: i16) {
        self.activation = activation;
        self.distance = distance;
    }

    pub fn frame_size(&self) -> Option<usize> {
        self.codec.as_ref().map(|codec| codec.frame_size())
    }

    pub fn codec_name(&self) -> Option<&'static str> {
        self.codec.as_ref().map(|codec| codec.name())
    }

    /// Encodes one frame and sends it as `PlayerAudioPacket`. The server
    /// forwards it to everyone in range with the secret rewritten.
    pub fn send_frame(&mut self, samples: &[i16]) -> io::Result<usize> {
        let Some(codec) = &mut self.codec else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the server has not sent its config yet",
            ));
        };
        let encoded = codec
            .encode(samples)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let data = match &self.encryption {
            Some(encryption) => encryption.encrypt(&encoded),
            None => encoded,
        };

        self.sequence += 1;
        let packet = UdpPacket::now(
            self.secret,
            UdpBody::PlayerAudio {
                sequence_number: self.sequence,
                data: data.clone(),
                activation_id: self.activation,
                distance: self.distance,
                stereo: self.stereo,
            },
        );
        let bytes = packet.encode();
        self.stats.frames_sent += 1;
        self.stats.bytes_sent += data.len() as u64;
        if let Err(error) = self.socket.send(&bytes) {
            self.stats.send_failed += 1;
            return Err(error);
        }
        self.last_frame = Some((self.sequence, self.distance));
        Ok(data.len())
    }

    /// Keeps the server's NAT mapping open and measures latency.
    pub fn ping(&self) -> io::Result<()> {
        let packet = UdpPacket::now(
            self.secret,
            UdpBody::Ping {
                time: pv_proto::now_millis(),
                server_ip: None,
                server_port: None,
            },
        );
        self.socket.send(&packet.encode())?;
        Ok(())
    }

    /// The control packet that ends the current burst, once the microphone
    /// goes quiet. `None` before anything was sent.
    pub fn audio_end(&self) -> Option<Control> {
        self.last_frame.map(|(sequence_number, distance)| Control::AudioEnd {
            sequence_number,
            activation_id: self.activation,
            distance,
        })
    }

    /// Reads what has arrived, without blocking. Frames from sources the game
    /// has not described yet still decode: the packet carries the id.
    pub fn poll(&mut self) -> io::Result<Vec<Incoming>> {
        let mut buffer = [0u8; 2048];
        let mut incoming = Vec::new();

        loop {
            let read = match self.socket.recv(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                    // Windows reports an ICMP port unreachable this way; the
                    // server is not listening yet, which is not fatal.
                    break;
                }
                Err(error) => return Err(error),
            };

            let packet = match UdpPacket::decode(&buffer[..read]) {
                Ok(packet) => packet,
                // Someone else's traffic on the port, or a version mismatch.
                Err(_) => continue,
            };
            self.stats.datagrams += 1;
            if packet.secret != self.secret {
                self.stats.other_secret += 1;
                continue;
            }
            // Anything sealed with our own secret means the server is alive,
            // whether or not this build can use the body.
            self.last_rx = Instant::now();

            match packet.body {
                UdpBody::SourceAudio {
                    data,
                    source_id,
                    source_state,
                    distance,
                    ..
                } => {
                    // The server never decrypts: every listener holds the same
                    // key from its own config, so the payload is sealed here.
                    let sealed = data.len();
                    let plain = match &self.encryption {
                        Some(encryption) => match encryption.decrypt(&data) {
                            Some(plain) => plain,
                            None => {
                                self.stats.decrypt_failed += 1;
                                self.note("incoming audio: the AES key does not open it".into());
                                continue;
                            }
                        },
                        None => data,
                    };
                    if self.stats.frames_played < 3 {
                        // The header of the first frames, so a stream that the
                        // decoder accepts but that is not speech is visible.
                        self.note(format!(
                            "frame: {} sealed bytes, {} plain, {:02x?}…",
                            sealed,
                            plain.len(),
                            &plain[..plain.len().min(6)]
                        ));
                    }
                    let decoded = match &mut self.codec {
                        Some(codec) => codec.decode(&plain),
                        None => continue,
                    };
                    match decoded {
                        Ok(samples) => {
                            if self.stats.frames_played < 3 {
                                self.note(format!("frame: opus decoded {} samples", samples.len()));
                            }
                            self.stats.frames_played += 1;
                            incoming.push(Incoming {
                                source_id,
                                samples,
                                distance,
                                state: source_state,
                            })
                        }
                        Err(error) => {
                            self.stats.decode_failed += 1;
                            self.note(format!("incoming audio: opus decode failed: {error}"));
                            continue;
                        }
                    }
                }
                UdpBody::Ping { time, .. } => {
                    // The server probes us; answer with its own timestamp.
                    let reply = UdpPacket::now(
                        self.secret,
                        UdpBody::Ping {
                            time,
                            server_ip: None,
                            server_port: None,
                        },
                    );
                    let _ = self.socket.send(&reply.encode());
                }
                _ => {}
            }
        }

        Ok(incoming)
    }
}
