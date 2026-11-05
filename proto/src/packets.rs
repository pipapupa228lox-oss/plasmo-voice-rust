//! The packet sets: `PacketTcpCodec` (control, carried in the Minecraft
//! plugin channel `plasmo:voice/v2`) and `PacketUdpCodec` (audio, on its own
//! UDP port).

use crate::bytes::{name_uuid, Error, Reader, Result, Uuid, Writer};
use crate::data::{
    CaptureInfo, CodecInfo, GameProfile, PlayerIconConfig, Pos3d, VoiceActivation,
    VoicePlayerInfo, VoiceSourceLine,
};

/// `PacketUdpCodec.MAGIC_NUMBER`: filters datagrams that are not ours, since
/// the voice port shares nothing with Minecraft's own traffic.
pub const UDP_MAGIC: u32 = 0x4e90_04e9;

/// The plugin channel the control packets travel in.
pub const CHANNEL: &str = "plasmo:voice/v2";
/// The channel the server uses only to say it is installed.
pub const FLAG_CHANNEL: &str = "plasmo:voice/v2/installed";
/// The channel a proxy uses to hand the client its AES key.
pub const SERVICE_CHANNEL: &str = "plasmo:voice/v2/service";

// ---------------------------------------------------------------------------
// Control packets (TCP codec)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum TcpPacket {
    /// 0x01, server to client: the UDP secret and where to send audio.
    Connection {
        secret: Uuid,
        ip: String,
        port: i32,
    },
    /// 0x02, server to client: who are you. `PlayerInfoRequestScheduler` sends
    /// it on join and retries five times until the key arrives.
    PlayerInfoRequest,
    /// 0x03, server to client: the full voice configuration.
    Config(Box<Config>),
    /// 0x04, server to client: this player's permissions on their own, as
    /// `ConfigPlayerInfoPacket` (a `Config` carries the same map).
    ConfigPlayerInfo { permissions: Vec<(String, bool)> },
    /// 0x05, client to server: the language to translate the config into.
    /// The Java client sends it right after the config.
    LanguageRequest { language: String },
    /// 0x06, server to client: the translation keys the server's activations
    /// and source lines use.
    Language {
        name: String,
        language: Vec<(String, String)>,
    },
    /// 0x0e, server to client: draw the radius of an activation in the world.
    DistanceVisualize {
        radius: i32,
        color: i32,
        position: Option<Pos3d>,
    },
    /// 0x07, server to client: everyone on the voice server.
    PlayerList { players: Vec<VoicePlayerInfo> },
    /// 0x08, server to client: one player changed.
    PlayerInfoUpdate { player: VoicePlayerInfo },
    /// 0x09, server to client: a player left the voice server.
    PlayerDisconnect { player_id: Uuid },
    /// 0x0a, client to server: who we are and what client we run.
    PlayerInfo {
        voice_disabled: bool,
        microphone_muted: bool,
        minecraft_version: String,
        version: String,
        public_key: Vec<u8>,
    },
    /// 0x0b, client to server: muted, or voice off entirely.
    PlayerState {
        voice_disabled: bool,
        microphone_muted: bool,
    },
    /// 0x0c, client to server: this activation's audio has ended.
    PlayerAudioEnd {
        sequence_number: i64,
        activation_id: Uuid,
        distance: i16,
    },
    /// 0x0d, client to server: the distances we hear each activation at.
    PlayerActivationDistances { distances: Vec<(Uuid, i32)> },
    /// 0x0f, client to server: tell me about this source.
    SourceInfoRequest { source_id: Uuid },
    /// 0x10, server to client: a source appeared or changed.
    SourceInfo { source: SourceInfo },
    /// 0x11, server to client: our own source as the listeners see it
    /// (`SelfSourceInfoPacket`): who we are, on which activation, at which
    /// sequence number.
    SelfSourceInfo {
        source: SourceInfo,
        player_id: Uuid,
        activation_id: Uuid,
        sequence_number: i64,
    },
    /// 0x12, server to client: this source's audio has ended.
    SourceAudioEnd { source_id: Uuid, sequence_number: i64 },
    /// 0x13, server to client: an activation exists.
    ActivationRegister { activation: Box<VoiceActivation> },
    /// 0x14, server to client: an activation is gone.
    ActivationUnregister { activation_id: Uuid },
    /// 0x15, server to client: a source line exists.
    SourceLineRegister { line: Box<VoiceSourceLine> },
    /// 0x16, server to client: a source line is gone.
    SourceLineUnregister { line_id: Uuid },
    /// 0x17, server to client: a player joined a source line.
    SourceLinePlayerAdd {
        line_id: Uuid,
        player: GameProfile,
    },
    /// 0x18, server to client: a player left one.
    SourceLinePlayerRemove { line_id: Uuid, player_id: Uuid },
    /// 0x19, server to client: everyone on a source line.
    SourceLinePlayersList {
        line_id: Uuid,
        players: Vec<GameProfile>,
    },
    /// 0x1a, server to client: an action-bar message, as a JSON text
    /// component.
    AnimatedActionBar { json: String },
    /// A packet this build does not model; its payload is kept as is.
    Unknown { id: u8, payload: Vec<u8> },
}

/// `ConfigPacket`: what the server expects from the client.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub server_id: Uuid,
    pub capture: CaptureInfo,
    /// Set when a proxy encrypts the audio; this client speaks plaintext only.
    pub encryption: Option<EncryptionInfo>,
    pub source_lines: Vec<VoiceSourceLine>,
    pub activations: Vec<VoiceActivation>,
    pub permissions: Vec<(String, bool)>,
    pub player_icon: Option<PlayerIconConfig>,
}

/// `EncryptionInfo`: the AES algorithm name and a key blob the Java client
/// RSA-decrypts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionInfo {
    pub algorithm: String,
    pub data: Vec<u8>,
}

/// `SourceInfo`: the base record plus the fields its concrete type adds.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceInfo {
    pub kind: String,
    pub addon_id: String,
    pub id: Uuid,
    pub name: Option<String>,
    pub state: i8,
    pub decoder: Option<CodecInfo>,
    pub stereo: bool,
    pub line_id: Uuid,
    /// Whether a client draws this source's icon over the speaker's head.
    pub icon_visible: bool,
    /// Which way a directional source faces, in degrees.
    pub angle: i32,
    /// `PlayerSourceInfo`'s own tail: who is behind the microphone. The
    /// nickname is what the speaker icon over that player's head goes by.
    pub player: Option<VoicePlayerInfo>,
    /// The rest of the record, as the concrete type wrote it: `ENTITY`,
    /// `STATIC` and `DIRECT` sources, kept opaque.
    pub extra: Vec<u8>,
}

impl TcpPacket {
    /// `PacketTcpCodec.encode`: the id byte, then the body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::new();
        match self {
            TcpPacket::Connection { secret, ip, port } => {
                out.write_u8(0x01);
                out.write_uuid(*secret);
                out.write_utf(ip);
                out.write_i32(*port);
            }
            TcpPacket::PlayerInfoRequest => out.write_u8(0x02),
            TcpPacket::Config(config) => {
                out.write_u8(0x03);
                config.write(&mut out);
            }
            TcpPacket::ConfigPlayerInfo { permissions } => {
                out.write_u8(0x04);
                write_permissions(permissions, &mut out);
            }
            TcpPacket::LanguageRequest { language } => {
                out.write_u8(0x05);
                out.write_utf(language);
            }
            TcpPacket::Language { name, language } => {
                out.write_u8(0x06);
                out.write_utf(name);
                out.write_i32(language.len() as i32);
                for (key, value) in language {
                    out.write_utf(key);
                    out.write_utf(value);
                }
            }
            TcpPacket::PlayerList { players } => {
                out.write_u8(0x07);
                out.write_i32(players.len() as i32);
                for player in players {
                    player.write(&mut out);
                }
            }
            TcpPacket::PlayerInfoUpdate { player } => {
                out.write_u8(0x08);
                player.write(&mut out);
            }
            TcpPacket::PlayerDisconnect { player_id } => {
                out.write_u8(0x09);
                out.write_uuid(*player_id);
            }
            TcpPacket::PlayerInfo {
                voice_disabled,
                microphone_muted,
                minecraft_version,
                version,
                public_key,
            } => {
                out.write_u8(0x0a);
                out.write_bool(*voice_disabled);
                out.write_bool(*microphone_muted);
                out.write_utf(minecraft_version);
                out.write_utf(version);
                out.write_i32(public_key.len() as i32);
                out.write_raw(public_key);
            }
            TcpPacket::PlayerState {
                voice_disabled,
                microphone_muted,
            } => {
                out.write_u8(0x0b);
                out.write_bool(*voice_disabled);
                out.write_bool(*microphone_muted);
            }
            TcpPacket::PlayerAudioEnd {
                sequence_number,
                activation_id,
                distance,
            } => {
                out.write_u8(0x0c);
                out.write_i64(*sequence_number);
                out.write_uuid(*activation_id);
                out.write_i16(*distance);
            }
            TcpPacket::PlayerActivationDistances { distances } => {
                out.write_u8(0x0d);
                out.write_i32(distances.len() as i32);
                for (id, distance) in distances {
                    out.write_uuid(*id);
                    out.write_i32(*distance);
                }
            }
            TcpPacket::DistanceVisualize {
                radius,
                color,
                position,
            } => {
                out.write_u8(0x0e);
                out.write_i32(*radius);
                out.write_i32(*color);
                match position {
                    Some(position) => {
                        out.write_bool(true);
                        position.write(&mut out);
                    }
                    None => out.write_bool(false),
                }
            }
            TcpPacket::SourceInfoRequest { source_id } => {
                out.write_u8(0x0f);
                out.write_uuid(*source_id);
            }
            TcpPacket::SourceInfo { source } => {
                out.write_u8(0x10);
                source.write(&mut out);
            }
            TcpPacket::SelfSourceInfo {
                source,
                player_id,
                activation_id,
                sequence_number,
            } => {
                out.write_u8(0x11);
                source.write(&mut out);
                out.write_uuid(*player_id);
                out.write_uuid(*activation_id);
                out.write_i64(*sequence_number);
            }
            TcpPacket::SourceAudioEnd {
                source_id,
                sequence_number,
            } => {
                out.write_u8(0x12);
                out.write_uuid(*source_id);
                out.write_i64(*sequence_number);
            }
            TcpPacket::ActivationRegister { activation } => {
                out.write_u8(0x13);
                activation.write(&mut out);
            }
            TcpPacket::ActivationUnregister { activation_id } => {
                out.write_u8(0x14);
                out.write_uuid(*activation_id);
            }
            TcpPacket::SourceLineRegister { line } => {
                out.write_u8(0x15);
                line.write(&mut out);
            }
            TcpPacket::SourceLineUnregister { line_id } => {
                out.write_u8(0x16);
                out.write_uuid(*line_id);
            }
            TcpPacket::SourceLinePlayerAdd { line_id, player } => {
                out.write_u8(0x17);
                out.write_uuid(*line_id);
                player.write(&mut out);
            }
            TcpPacket::SourceLinePlayerRemove { line_id, player_id } => {
                out.write_u8(0x18);
                out.write_uuid(*line_id);
                out.write_uuid(*player_id);
            }
            TcpPacket::SourceLinePlayersList { line_id, players } => {
                out.write_u8(0x19);
                out.write_uuid(*line_id);
                out.write_i32(players.len() as i32);
                for player in players {
                    player.write(&mut out);
                }
            }
            TcpPacket::AnimatedActionBar { json } => {
                out.write_u8(0x1a);
                out.write_utf(json);
            }
            TcpPacket::Unknown { id, payload } => {
                out.write_u8(*id);
                out.write_raw(payload);
            }
        }
        out.into_bytes()
    }

    /// Decodes one packet; the whole slice must be that packet.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut input = Reader::new(buf);
        Self::read(&mut input)
    }

    /// Decodes packets until the buffer runs out: a plugin channel payload may
    /// hold more than one, the way the Java client polls it.
    pub fn decode_all(buf: &[u8]) -> Result<Vec<Self>> {
        let mut input = Reader::new(buf);
        let mut packets = Vec::new();
        while !input.is_empty() {
            packets.push(Self::read(&mut input)?);
        }
        Ok(packets)
    }

    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let id = input.read_u8()?;
        let packet = match id {
            0x01 => TcpPacket::Connection {
                secret: input.read_uuid()?,
                // `ConnectionPacket.read` uses a plain `readUTF`.
                ip: input.read_utf(u16::MAX as usize)?,
                port: input.read_i32()?,
            },
            0x02 => TcpPacket::PlayerInfoRequest,
            0x03 => TcpPacket::Config(Box::new(Config::read(input)?)),
            0x04 => TcpPacket::ConfigPlayerInfo {
                permissions: read_permissions(input)?,
            },
            0x05 => TcpPacket::LanguageRequest {
                language: input.read_utf(32)?,
            },
            0x06 => {
                let name = input.read_utf(u16::MAX as usize)?;
                let size = input.read_safe_int(0, i16::MAX as i32, "language entries")?;
                let mut language = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    let key = input.read_utf(u16::MAX as usize)?;
                    let value = input.read_utf(u16::MAX as usize)?;
                    language.push((key, value));
                }
                TcpPacket::Language { name, language }
            }
            0x07 => {
                let size = input.read_safe_int(0, i16::MAX as i32, "player list")?;
                let mut players = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    players.push(VoicePlayerInfo::read(input)?);
                }
                TcpPacket::PlayerList { players }
            }
            0x08 => TcpPacket::PlayerInfoUpdate {
                player: VoicePlayerInfo::read(input)?,
            },
            0x09 => TcpPacket::PlayerDisconnect {
                player_id: input.read_uuid()?,
            },
            0x0a => {
                let voice_disabled = input.read_bool()?;
                let microphone_muted = input.read_bool()?;
                TcpPacket::PlayerInfo {
                    voice_disabled,
                    microphone_muted,
                    minecraft_version: input.read_utf(64)?,
                    version: input.read_utf(64)?,
                    public_key: input.read_bytes(2048, "public key")?,
                }
            }
            0x0b => TcpPacket::PlayerState {
                voice_disabled: input.read_bool()?,
                microphone_muted: input.read_bool()?,
            },
            0x0c => TcpPacket::PlayerAudioEnd {
                sequence_number: input.read_i64()?,
                activation_id: input.read_uuid()?,
                distance: input.read_i16()?,
            },
            0x0d => {
                let size = input.read_safe_int(0, i8::MAX as i32, "activation distances")?;
                let mut distances = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    distances.push((input.read_uuid()?, input.read_i32()?));
                }
                TcpPacket::PlayerActivationDistances { distances }
            }
            0x0e => TcpPacket::DistanceVisualize {
                radius: input.read_i32()?,
                color: input.read_i32()?,
                position: if input.read_bool()? {
                    Some(Pos3d::read(input)?)
                } else {
                    None
                },
            },
            0x0f => TcpPacket::SourceInfoRequest {
                source_id: input.read_uuid()?,
            },
            0x10 => TcpPacket::SourceInfo {
                source: SourceInfo::read(input)?,
            },
            0x11 => TcpPacket::SelfSourceInfo {
                source: SourceInfo::read(input)?,
                player_id: input.read_uuid()?,
                activation_id: input.read_uuid()?,
                sequence_number: input.read_i64()?,
            },
            0x12 => TcpPacket::SourceAudioEnd {
                source_id: input.read_uuid()?,
                sequence_number: input.read_i64()?,
            },
            0x13 => TcpPacket::ActivationRegister {
                activation: Box::new(VoiceActivation::read(input)?),
            },
            0x14 => TcpPacket::ActivationUnregister {
                activation_id: input.read_uuid()?,
            },
            0x15 => TcpPacket::SourceLineRegister {
                line: Box::new(VoiceSourceLine::read(input)?),
            },
            0x16 => TcpPacket::SourceLineUnregister {
                line_id: input.read_uuid()?,
            },
            0x17 => TcpPacket::SourceLinePlayerAdd {
                line_id: input.read_uuid()?,
                player: GameProfile::read(input)?,
            },
            0x18 => TcpPacket::SourceLinePlayerRemove {
                line_id: input.read_uuid()?,
                player_id: input.read_uuid()?,
            },
            0x19 => {
                let line_id = input.read_uuid()?;
                let size = input.read_safe_int(0, i16::MAX as i32, "line players")?;
                let mut players = Vec::with_capacity(size as usize);
                for _ in 0..size {
                    players.push(GameProfile::read(input)?);
                }
                TcpPacket::SourceLinePlayersList { line_id, players }
            }
            0x1a => TcpPacket::AnimatedActionBar {
                json: input.read_utf(u16::MAX as usize)?,
            },
            other => TcpPacket::Unknown {
                id: other,
                payload: input.rest().to_vec(),
            },
        };
        Ok(packet)
    }
}

impl Config {
    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let server_id = input.read_uuid()?;
        let capture = CaptureInfo::read(input)?;

        let encryption = if input.read_bool()? {
            let algorithm = input.read_utf(u16::MAX as usize)?;
            let data = input.read_bytes(2048, "encryption key")?;
            Some(EncryptionInfo { algorithm, data })
        } else {
            None
        };

        let line_count = input.read_safe_int(0, i8::MAX as i32, "source lines")?;
        let mut source_lines = Vec::with_capacity(line_count as usize);
        for _ in 0..line_count {
            source_lines.push(VoiceSourceLine::read(input)?);
        }

        let activation_count = input.read_safe_int(0, i8::MAX as i32, "activations")?;
        let mut activations = Vec::with_capacity(activation_count as usize);
        for _ in 0..activation_count {
            activations.push(VoiceActivation::read(input)?);
        }

        // ConfigPlayerInfoPacket: the permission map.
        let permissions = read_permissions(input)?;

        // Since 2.1.7, and optional: a 2.1.6 server sends nothing here.
        let player_icon = if input.is_empty() {
            None
        } else {
            PlayerIconConfig::read(input).ok()
        };

        Ok(Config {
            server_id,
            capture,
            encryption,
            source_lines,
            activations,
            permissions,
            player_icon,
        })
    }

    fn write(&self, out: &mut Writer) {
        out.write_uuid(self.server_id);
        self.capture.write(out);

        out.write_bool(self.encryption.is_some());
        if let Some(encryption) = &self.encryption {
            out.write_utf(&encryption.algorithm);
            out.write_bytes(&encryption.data);
        }

        out.write_i32(self.source_lines.len() as i32);
        for line in &self.source_lines {
            line.write(out);
        }

        out.write_i32(self.activations.len() as i32);
        for activation in &self.activations {
            activation.write(out);
        }

        write_permissions(&self.permissions, out);

        if let Some(icon) = &self.player_icon {
            icon.write(out);
        }
    }

    /// The activation the client talks on by default: the proximity one.
    pub fn proximity_activation(&self) -> Option<&VoiceActivation> {
        self.activations
            .iter()
            .find(|activation| activation.name == crate::data::PROXIMITY_NAME)
    }

    pub fn activation(&self, id: Uuid) -> Option<&VoiceActivation> {
        self.activations.iter().find(|a| a.id == id)
    }

    /// The line a player's microphone belongs to: the proximity one, which is
    /// the only line a server without addons registers.
    pub fn proximity_line(&self) -> Option<&VoiceSourceLine> {
        self.source_lines
            .iter()
            .find(|line| line.name == crate::data::PROXIMITY_NAME)
            .or_else(|| self.source_lines.first())
    }
}

impl SourceInfo {
    /// A `STATIC` source: audio that comes from a place in the world — a
    /// jukebox, a speaker an addon drives — rather than from a player's
    /// microphone. The tail `StaticSourceInfo` writes is the place and the
    /// direction it faces, which is what a client draws its icon at.
    pub fn static_source(
        addon_id: &str,
        id: Uuid,
        line_id: Uuid,
        name: &str,
        position: Pos3d,
        look: Pos3d,
    ) -> Self {
        let mut extra = Writer::new();
        position.write(&mut extra);
        look.write(&mut extra);
        SourceInfo {
            kind: "STATIC".into(),
            addon_id: addon_id.into(),
            id,
            name: Some(name.into()),
            // `SourceInfo.State`: created, and no addon sends a change here.
            state: 0,
            decoder: Some(CodecInfo {
                name: "opus".into(),
                params: Vec::new(),
            }),
            stereo: false,
            line_id,
            icon_visible: true,
            angle: 0,
            player: None,
            extra: extra.into_bytes(),
        }
    }

    /// Where a `STATIC` source is, as [`SourceInfo::static_source`] wrote it:
    /// the place and the look direction. `None` for any other kind.
    pub fn static_place(&self) -> Option<(Pos3d, Pos3d)> {
        if self.kind != "STATIC" {
            return None;
        }
        let mut input = Reader::new(&self.extra);
        let position = Pos3d::read(&mut input).ok()?;
        let look = Pos3d::read(&mut input).ok()?;
        Some((position, look))
    }

    fn read(input: &mut Reader<'_>) -> Result<Self> {
        let kind = input.read_utf(u16::MAX as usize)?;
        let addon_id = input.read_utf(u16::MAX as usize)?;
        let id = input.read_uuid()?;
        let name = input.read_nullable_string(u16::MAX as usize)?;
        let state = input.read_u8()? as i8;
        let decoder = if input.read_bool()? {
            Some(CodecInfo::read(input)?)
        } else {
            None
        };
        let stereo = input.read_bool()?;
        let line_id = input.read_uuid()?;
        let icon_visible = input.read_bool()?;
        let angle = input.read_i32()?;

        // `PlayerSourceInfo.deserialize` reads a `VoicePlayerInfo` after the
        // base record; the other source types put their own fields there.
        let (player, extra) = if kind == "PLAYER" && !input.is_empty() {
            (VoicePlayerInfo::read(input).ok(), Vec::new())
        } else if kind == "PLAYER" {
            (None, Vec::new())
        } else {
            (None, input.rest().to_vec())
        };

        Ok(SourceInfo {
            kind,
            addon_id,
            id,
            name,
            state,
            decoder,
            stereo,
            line_id,
            icon_visible,
            angle,
            player,
            extra,
        })
    }

    fn write(&self, out: &mut Writer) {
        out.write_utf(&self.kind);
        out.write_utf(&self.addon_id);
        out.write_uuid(self.id);
        match &self.name {
            Some(name) => {
                out.write_bool(true);
                out.write_utf(name);
            }
            None => out.write_bool(false),
        }
        out.write_u8(self.state as u8);
        out.write_bool(self.decoder.is_some());
        if let Some(decoder) = &self.decoder {
            decoder.write(out);
        }
        out.write_bool(self.stereo);
        out.write_uuid(self.line_id);
        out.write_bool(self.icon_visible);
        out.write_i32(self.angle);
        if let Some(player) = &self.player {
            player.write(out);
        }
        out.write_raw(&self.extra);
    }
}

// ---------------------------------------------------------------------------
// Audio packets (UDP codec)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct UdpPacket {
    pub secret: Uuid,
    pub timestamp: i64,
    pub body: UdpBody,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UdpBody {
    /// 0x01. `server_ip`/`server_port` are optional and only sent by a client.
    Ping {
        time: i64,
        server_ip: Option<String>,
        server_port: Option<u16>,
    },
    /// 0x02, client to server: one Opus frame of the player's microphone.
    PlayerAudio {
        sequence_number: i64,
        data: Vec<u8>,
        activation_id: Uuid,
        distance: i16,
        stereo: bool,
    },
    /// 0x03, server to client: one Opus frame of someone else.
    SourceAudio {
        sequence_number: i64,
        data: Vec<u8>,
        source_id: Uuid,
        source_state: u8,
        distance: i16,
    },
    /// 0x04, server to client: what our own audio looks like to others.
    SelfAudio {
        source_id: Uuid,
        sequence_number: i64,
        data: Option<Vec<u8>>,
        distance: i16,
    },
    /// Registered as 0x100, sent as 0x00; payload kept opaque.
    Custom { id: u8, payload: Vec<u8> },
}

impl UdpPacket {
    /// `PacketUdpCodec.encode`: magic, id, secret, timestamp, body.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Writer::new();
        UdpBody::write(&self.body, &mut body);

        let mut out = Writer::new();
        out.write_i32(UDP_MAGIC as i32);
        out.write_u8(UdpBody::id(&self.body));
        out.write_uuid(self.secret);
        out.write_i64(self.timestamp);
        out.write_raw(body.as_slice());
        out.into_bytes()
    }

    /// The same, at the current time, the way the Java codec stamps packets.
    pub fn now(secret: Uuid, body: UdpBody) -> Self {
        UdpPacket {
            secret,
            timestamp: crate::now_millis(),
            body,
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut input = Reader::new(buf);
        let magic = input.read_i32()? as u32;
        if magic != UDP_MAGIC {
            return Err(Error::BadMagic(magic));
        }
        let id = input.read_u8()?;
        let secret = input.read_uuid()?;
        let timestamp = input.read_i64()?;
        let body = match id {
            0x01 => {
                let time = input.read_i64()?;
                let server_ip = input.read_utf(255).ok();
                let server_port = input.read_u16().ok();
                UdpBody::Ping {
                    time,
                    server_ip,
                    server_port: server_port.filter(|port| *port > 0),
                }
            }
            0x02 => UdpBody::PlayerAudio {
                sequence_number: input.read_i64()?,
                data: input.read_audio()?,
                activation_id: input.read_uuid()?,
                distance: input.read_i16()?,
                stereo: input.read_bool()?,
            },
            0x03 => UdpBody::SourceAudio {
                sequence_number: input.read_i64()?,
                data: input.read_audio()?,
                source_id: input.read_uuid()?,
                source_state: input.read_u8()?,
                distance: input.read_i16()?,
            },
            0x04 => {
                let source_id = input.read_uuid()?;
                let sequence_number = input.read_i64()?;
                let data = if input.read_bool()? {
                    Some(input.read_audio()?)
                } else {
                    None
                };
                UdpBody::SelfAudio {
                    source_id,
                    sequence_number,
                    data,
                    distance: input.read_i16()?,
                }
            }
            // `PacketUdpCodec` registers the custom packet as 0x100 but
            // writes it with `writeByte`, which keeps the low 8 bits: it goes
            // out as id 0 and the Java side cannot decode it back either. We
            // mirror that so the bytes match.
            0x00 => UdpBody::Custom {
                id: 0x00,
                payload: input.rest().to_vec(),
            },
            other => return Err(Error::UnknownPacket(other)),
        };
        Ok(UdpPacket {
            secret,
            timestamp,
            body,
        })
    }

    /// The 16 bytes at offset 5: the secret, which the server rewrites into
    /// forwarded packets (`replaceSecret`).
    pub fn replace_secret(buf: &mut [u8], secret: Uuid) {
        if buf.len() >= 21 {
            buf[5..21].copy_from_slice(&secret);
        }
    }
}

impl UdpBody {
    fn id(&self) -> u8 {
        match self {
            UdpBody::Ping { .. } => 0x01,
            UdpBody::PlayerAudio { .. } => 0x02,
            UdpBody::SourceAudio { .. } => 0x03,
            UdpBody::SelfAudio { .. } => 0x04,
            UdpBody::Custom { id, .. } => *id,
        }
    }

    fn write(&self, out: &mut Writer) {
        match self {
            UdpBody::Ping {
                time,
                server_ip,
                server_port,
            } => {
                out.write_i64(*time);
                if let (Some(ip), Some(port)) = (server_ip, server_port) {
                    out.write_utf(ip);
                    out.write_u16(*port);
                }
            }
            UdpBody::PlayerAudio {
                sequence_number,
                data,
                activation_id,
                distance,
                stereo,
            } => {
                out.write_i64(*sequence_number);
                out.write_i32(data.len() as i32);
                out.write_raw(data);
                out.write_uuid(*activation_id);
                out.write_i16(*distance);
                out.write_bool(*stereo);
            }
            UdpBody::SourceAudio {
                sequence_number,
                data,
                source_id,
                source_state,
                distance,
            } => {
                out.write_i64(*sequence_number);
                out.write_i32(data.len() as i32);
                out.write_raw(data);
                out.write_uuid(*source_id);
                out.write_u8(*source_state);
                out.write_i16(*distance);
            }
            UdpBody::SelfAudio {
                source_id,
                sequence_number,
                data,
                distance,
            } => {
                out.write_uuid(*source_id);
                out.write_i64(*sequence_number);
                out.write_bool(data.is_some());
                if let Some(data) = data {
                    out.write_i32(data.len() as i32);
                    out.write_raw(data);
                }
                out.write_i16(*distance);
            }
            UdpBody::Custom { payload, .. } => out.write_raw(payload),
        }
    }
}

/// `ConfigPlayerInfoPacket`'s map: a count, then a key and a value each.
fn read_permissions(input: &mut Reader<'_>) -> Result<Vec<(String, bool)>> {
    let count = input.read_safe_int(0, i8::MAX as i32, "permissions")?;
    let mut permissions = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let key = input.read_utf(u16::MAX as usize)?;
        permissions.push((key, input.read_bool()?));
    }
    Ok(permissions)
}

fn write_permissions(permissions: &[(String, bool)], out: &mut Writer) {
    out.write_i32(permissions.len() as i32);
    for (key, value) in permissions {
        out.write_utf(key);
        out.write_bool(*value);
    }
}

/// A source line id, from its name; `VoiceSourceLine.generateId`.
pub fn source_line_id(name: &str) -> Uuid {
    name_uuid(&format!("{name}_line"))
}

/// A game profile with no properties, for tests and for the client's own.
pub fn empty_profile(id: Uuid, name: &str) -> GameProfile {
    GameProfile {
        id,
        name: name.to_string(),
        properties: Vec::new(),
    }
}
