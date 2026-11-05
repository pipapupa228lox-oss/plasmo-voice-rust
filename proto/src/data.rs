//! The records carried inside packets (`su.plo.voice.proto.data`).

use crate::bytes::{name_uuid, Reader, Result, Uuid, Writer};

/// `CodecInfo`: a codec's name and its string parameters (mtu size, bitrate...).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodecInfo {
    pub name: String,
    pub params: Vec<(String, String)>,
}

impl CodecInfo {
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        // `readUTF` bounds nothing but the two-byte length; the Java codec
        // leaves codec names and parameters unbounded.
        let name = input.read_utf(u16::MAX as usize)?;
        let size = input.read_safe_int(0, 128, "codec params")?;
        let mut params = Vec::with_capacity(size as usize);
        for _ in 0..size {
            let key = input.read_utf(u16::MAX as usize)?;
            let value = input.read_utf(u16::MAX as usize)?;
            params.push((key, value));
        }
        Ok(CodecInfo { name, params })
    }

    pub fn write(&self, out: &mut Writer) {
        out.write_utf(&self.name);
        out.write_i32(self.params.len() as i32);
        for (key, value) in &self.params {
            out.write_utf(key);
            out.write_utf(value);
        }
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// `CaptureInfo`: what the server expects from the upload: sample rate, the
/// largest packet the encoder may produce, and the encoder's settings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaptureInfo {
    pub sample_rate: i32,
    pub mtu_size: i32,
    pub encoder: Option<CodecInfo>,
}

impl CaptureInfo {
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let sample_rate = input.read_i32()?;
        let mtu_size = input.read_i32()?;
        let encoder = if input.read_bool()? {
            Some(CodecInfo::read(input)?)
        } else {
            None
        };
        Ok(CaptureInfo {
            sample_rate,
            mtu_size,
            encoder,
        })
    }

    pub fn write(&self, out: &mut Writer) {
        out.write_i32(self.sample_rate);
        out.write_i32(self.mtu_size);
        out.write_bool(self.encoder.is_some());
        if let Some(encoder) = &self.encoder {
            encoder.write(out);
        }
    }
}

/// `VoiceActivation`: a key the server offers ("proximity", "whisper"...).
/// Its id is `UUID.nameUUIDFromBytes(name + "_activation")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceActivation {
    pub name: String,
    pub translation: String,
    pub icon: String,
    pub id: Uuid,
    pub distances: Vec<i32>,
    pub default_distance: i32,
    pub proximity: bool,
    pub transitive: bool,
    pub stereo_supported: bool,
    pub encoder: Option<CodecInfo>,
    pub weight: i32,
}

/// `VoiceActivation.PROXIMITY_NAME`.
pub const PROXIMITY_NAME: &str = "proximity";

impl VoiceActivation {
    pub fn id_for(name: &str) -> Uuid {
        name_uuid(&format!("{name}_activation"))
    }

    pub fn proximity_id() -> Uuid {
        Self::id_for(PROXIMITY_NAME)
    }

    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let name = input.read_utf(u16::MAX as usize)?;
        let translation = input.read_utf(u16::MAX as usize)?;
        let icon = input.read_utf(u16::MAX as usize)?;
        let id = Self::id_for(&name);
        let distances = input.read_int_list(64)?;
        // `VoiceActivation.deserialize` passes the wire value through
        // `validateDefaultDistance`, so a default the distances do not hold
        // becomes one they do.
        let default_distance = Self::validated_default_distance(&distances, input.read_i32()?);
        let proximity = input.read_bool()?;
        let transitive = input.read_bool()?;
        let stereo_supported = input.read_bool()?;
        let encoder = if input.read_bool()? {
            Some(CodecInfo::read(input)?)
        } else {
            None
        };
        let weight = input.read_i32()?;

        Ok(VoiceActivation {
            name,
            translation,
            icon,
            id,
            distances,
            default_distance,
            proximity,
            transitive,
            stereo_supported,
            encoder,
            weight,
        })
    }

    pub fn write(&self, out: &mut Writer) {
        out.write_utf(&self.name);
        out.write_utf(&self.translation);
        out.write_utf(&self.icon);
        out.write_i32(self.distances.len() as i32);
        for distance in &self.distances {
            out.write_i32(*distance);
        }
        out.write_i32(self.default_distance);
        out.write_bool(self.proximity);
        out.write_bool(self.transitive);
        out.write_bool(self.stereo_supported);
        out.write_bool(self.encoder.is_some());
        if let Some(encoder) = &self.encoder {
            encoder.write(out);
        }
        out.write_i32(self.weight);
    }

    /// The distances a client may pick from, in the order the server sent them.
    pub fn distance_options(&self) -> &[i32] {
        &self.distances
    }

    /// `VoiceActivation.validateDefaultDistance`: no distances at all means 0;
    /// a dynamic list (`[-1, max]`) keeps a value inside it or halves the max;
    /// otherwise the default is one of the distances, else the middle one.
    pub fn validated_default_distance(distances: &[i32], default_distance: i32) -> i32 {
        let Some(first) = distances.first() else {
            return 0;
        };
        if distances.len() == 2 && *first == -1 {
            let max = distances[1];
            return if (1..=max).contains(&default_distance) {
                default_distance
            } else {
                max / 2
            };
        }
        if distances.contains(&default_distance) {
            default_distance
        } else {
            distances[distances.len() / 2]
        }
    }

    /// `Activation.checkDistance`: whether a client may use that distance. A
    /// list that holds only `[-1, max]` accepts anything inside it.
    pub fn check_distance(&self, distance: i32) -> bool {
        if self.distances.is_empty() {
            return true;
        }
        if self.distances.len() == 2 && self.distances[0] == -1 {
            return distance >= 1 && distance <= self.distances[1];
        }
        self.distances.contains(&distance)
    }

    /// `Activation.calculateAllowedDistance`: the distance asked for, or the
    /// activation's own default when the list does not hold it.
    pub fn allowed_distance(&self, distance: i32) -> i32 {
        if self.check_distance(distance) {
            distance
        } else {
            self.default_distance
        }
    }
}

/// `McGameProfile` as `McGameProfileSerializer` reads it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GameProfile {
    pub id: Uuid,
    pub name: String,
    pub properties: Vec<(String, String, String)>,
}

impl GameProfile {
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let id = input.read_uuid()?;
        let name = input.read_utf(256)?;
        let size = input.read_safe_int(0, 100, "profile properties")?;
        let mut properties = Vec::with_capacity(size as usize);
        for _ in 0..size {
            properties.push((input.read_utf(1024)?, input.read_utf(8192)?, input.read_utf(2048)?));
        }
        Ok(GameProfile {
            id,
            name,
            properties,
        })
    }

    pub fn write(&self, out: &mut Writer) {
        out.write_uuid(self.id);
        out.write_utf(&self.name);
        out.write_i32(self.properties.len() as i32);
        for (name, value, signature) in &self.properties {
            out.write_utf(name);
            out.write_utf(value);
            out.write_utf(signature);
        }
    }
}

/// `VoiceSourceLine` ("main", "music"...). Its id is
/// `UUID.nameUUIDFromBytes(name + "_line")`.
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceSourceLine {
    pub name: String,
    pub translation: String,
    pub icon: String,
    pub default_volume: f64,
    pub weight: i32,
    pub id: Uuid,
    pub players: Option<Vec<GameProfile>>,
}

impl VoiceSourceLine {
    pub fn id_for(name: &str) -> Uuid {
        name_uuid(&format!("{name}_line"))
    }

    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let name = input.read_utf(u16::MAX as usize)?;
        let id = Self::id_for(&name);
        let translation = input.read_utf(u16::MAX as usize)?;
        let icon = input.read_utf(u16::MAX as usize)?;
        let default_volume = input.read_f64()?;
        let weight = input.read_i32()?;
        let players = if input.read_bool()? {
            let size = input.read_safe_int(0, i16::MAX as i32, "line players")?;
            let mut players = Vec::with_capacity(size as usize);
            for _ in 0..size {
                players.push(GameProfile::read(input)?);
            }
            Some(players)
        } else {
            None
        };

        Ok(VoiceSourceLine {
            name,
            translation,
            icon,
            default_volume,
            weight,
            id,
            players,
        })
    }

    pub fn write(&self, out: &mut Writer) {
        out.write_utf(&self.name);
        out.write_utf(&self.translation);
        out.write_utf(&self.icon);
        out.write_f64(self.default_volume);
        out.write_i32(self.weight);
        out.write_bool(self.players.is_some());
        if let Some(players) = &self.players {
            out.write_i32(players.len() as i32);
            for player in players {
                player.write(out);
            }
        }
    }
}

/// `VoicePlayerInfo`: who is on the voice server and whether they can talk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VoicePlayerInfo {
    pub player_id: Uuid,
    pub nick: String,
    pub muted: bool,
    pub voice_disabled: bool,
    pub microphone_muted: bool,
}

impl VoicePlayerInfo {
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let player_id = input.read_uuid()?;
        // `readUTF` has no length policy of its own: a nickname is bounded by
        // the two-byte length prefix and nothing else.
        let nick = input.read_utf(u16::MAX as usize)?;
        Ok(VoicePlayerInfo {
            player_id,
            nick,
            muted: input.read_bool()?,
            voice_disabled: input.read_bool()?,
            microphone_muted: input.read_bool()?,
        })
    }

    pub fn write(&self, out: &mut Writer) {
        out.write_uuid(self.player_id);
        out.write_utf(&self.nick);
        out.write_bool(self.muted);
        out.write_bool(self.voice_disabled);
        out.write_bool(self.microphone_muted);
    }
}

/// `Pos3d` as `Pos3dSerializer` writes it.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Pos3d {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Pos3d {
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        Ok(Pos3d {
            x: input.read_f64()?,
            y: input.read_f64()?,
            z: input.read_f64()?,
        })
    }

    pub fn write(&self, out: &mut Writer) {
        out.write_f64(self.x);
        out.write_f64(self.y);
        out.write_f64(self.z);
    }
}

/// `PlayerIconConfig`: where above the head the voice icon sits. Only read to
/// get past it; the client draws no icons yet.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PlayerIconConfig {
    pub visibility: Vec<String>,
    pub offset: Pos3d,
}

impl PlayerIconConfig {
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let size = input.read_safe_int(0, 8, "icon visibility")?;
        let mut visibility = Vec::with_capacity(size as usize);
        for _ in 0..size {
            visibility.push(input.read_utf(u16::MAX as usize)?);
        }
        let offset = Pos3d::read(input)?;
        Ok(PlayerIconConfig { visibility, offset })
    }

    pub fn write(&self, out: &mut Writer) {
        out.write_i32(self.visibility.len() as i32);
        for entry in &self.visibility {
            out.write_utf(entry);
        }
        self.offset.write(out);
    }
}
