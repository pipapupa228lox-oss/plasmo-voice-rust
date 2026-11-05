//! Audio codecs: what turns microphone samples into the bytes of a voice
//! packet, and back.
//!
//! PlasmoVoice negotiates this in `CaptureInfo`: the rate both sides use, the
//! largest frame the server accepts, and the encoder's settings. Opus at 48 kHz
//! in 20 ms frames is what the Java client sends and what this one sends too.

/// One codec, either direction. `frame_size` is in samples at `sample_rate`.
pub trait AudioCodec: Send {
    fn encode(&mut self, samples: &[i16]) -> Result<Vec<u8>, String>;
    fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, String>;
    fn frame_size(&self) -> usize;
    fn name(&self) -> &'static str;
}

/// Opus, with the settings the Java client uses: 48 kHz, mono for proximity,
/// 20 ms frames, a bitrate from the server's `CodecInfo`.
#[cfg(feature = "opus")]
pub struct OpusCodec {
    encoder: audiopus::coder::Encoder,
    decoder: audiopus::coder::Decoder,
    frame_size: usize,
    channels: usize,
    mtu: usize,
}

#[cfg(feature = "opus")]
impl OpusCodec {
    /// `sample_rate` from `CaptureInfo`, `mtu` from `CaptureInfo.mtu_size`.
    pub fn new(sample_rate: i32, mtu: i32, stereo: bool) -> Result<Self, String> {
        use audiopus::{Application, Channels, SampleRate};

        let rate = match sample_rate {
            8000 => SampleRate::Hz8000,
            12000 => SampleRate::Hz12000,
            16000 => SampleRate::Hz16000,
            24000 => SampleRate::Hz24000,
            48000 => SampleRate::Hz48000,
            other => return Err(format!("unsupported sample rate {other}")),
        };
        let channels = if stereo {
            Channels::Stereo
        } else {
            Channels::Mono
        };

        let mut encoder = audiopus::coder::Encoder::new(rate, channels, Application::Voip)
            .map_err(|error| format!("opus encoder: {error}"))?;
        let bitrate = if stereo { 64_000 } else { 32_000 };
        encoder
            .set_bitrate(audiopus::Bitrate::BitsPerSecond(bitrate))
            .map_err(|error| format!("opus bitrate: {error}"))?;

        let decoder = audiopus::coder::Decoder::new(rate, channels)
            .map_err(|error| format!("opus decoder: {error}"))?;

        // Opus frames are 2.5, 5, 10, 20, 40 or 60 ms; the Java client sends 20.
        let frame_size = (sample_rate as usize / 1000) * 20 * if stereo { 2 } else { 1 };

        Ok(OpusCodec {
            encoder,
            decoder,
            frame_size,
            channels: if stereo { 2 } else { 1 },
            mtu: (mtu as usize).clamp(64, 2048),
        })
    }
}

#[cfg(feature = "opus")]
impl AudioCodec for OpusCodec {
    fn encode(&mut self, samples: &[i16]) -> Result<Vec<u8>, String> {
        if samples.len() != self.frame_size {
            return Err(format!(
                "expected {} samples, got {}",
                self.frame_size,
                samples.len()
            ));
        }
        let mut out = vec![0u8; self.mtu];
        let len = self
            .encoder
            .encode(samples, &mut out)
            .map_err(|error| format!("opus encode: {error}"))?;
        out.truncate(len);
        Ok(out)
    }

    fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, String> {
        use audiopus::MutSignals;

        let packet = audiopus::packet::Packet::try_from(data)
            .map_err(|error| format!("opus packet: {error}"))?;
        let mut out = vec![0i16; self.frame_size];
        let signals = MutSignals::try_from(&mut out[..])
            .map_err(|error| format!("opus buffer: {error}"))?;
        let read = self
            .decoder
            .decode(Some(packet), signals, false)
            .map_err(|error| format!("opus decode: {error}"))?;
        out.truncate(read * self.channels);
        Ok(out)
    }

    fn frame_size(&self) -> usize {
        self.frame_size
    }

    fn name(&self) -> &'static str {
        "opus"
    }
}

/// No compression: the packet carries the samples as little-endian i16.
///
/// Not what a PlasmoVoice server accepts; it exists so the transport, the
/// header and the session can be tested without pulling in libopus.
pub struct RawCodec {
    frame_size: usize,
}

impl RawCodec {
    pub fn new(frame_size: usize) -> Self {
        RawCodec { frame_size }
    }
}

impl AudioCodec for RawCodec {
    fn encode(&mut self, samples: &[i16]) -> Result<Vec<u8>, String> {
        if samples.len() != self.frame_size {
            return Err(format!(
                "expected {} samples, got {}",
                self.frame_size,
                samples.len()
            ));
        }
        Ok(samples.iter().flat_map(|sample| sample.to_le_bytes()).collect())
    }

    fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, String> {
        if data.len() % 2 != 0 {
            return Err("odd byte count".into());
        }
        Ok(data
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect())
    }

    fn frame_size(&self) -> usize {
        self.frame_size
    }

    fn name(&self) -> &'static str {
        "raw"
    }
}

/// Picks a codec for what the server's `CaptureInfo` announced.
pub fn from_capture(
    encoder_name: Option<&str>,
    sample_rate: i32,
    mtu: i32,
    stereo: bool,
) -> Result<Box<dyn AudioCodec>, String> {
    match encoder_name.unwrap_or("opus") {
        "opus" => {
            #[cfg(feature = "opus")]
            {
                Ok(Box::new(OpusCodec::new(sample_rate, mtu, stereo)?))
            }
            #[cfg(not(feature = "opus"))]
            {
                Err("built without the opus feature".into())
            }
        }
        other => Err(format!("unsupported codec {other}")),
    }
}

#[cfg(all(test, feature = "opus"))]
mod tests {
    use super::*;

    fn sine(frequency: f32, sample_rate: f32, len: usize) -> Vec<i16> {
        (0..len)
            .map(|i| {
                let phase = 2.0 * std::f32::consts::PI * frequency * i as f32 / sample_rate;
                (phase.sin() * 12_000.0) as i16
            })
            .collect()
    }

    /// Loudness of a run of samples, in full-scale units.
    fn rms(samples: &[i16]) -> f32 {
        if samples.is_empty() {
            return 0.0;
        }
        let sum: f32 = samples.iter().map(|s| (*s as f32).powi(2)).sum();
        (sum / samples.len() as f32).sqrt() / 32_768.0
    }

    #[test]
    fn opus_round_trip_keeps_the_sound() {
        let mut codec = OpusCodec::new(48_000, 1024, false).unwrap();
        let original = sine(440.0, 48_000.0, codec.frame_size());

        let encoded = codec.encode(&original).unwrap();
        assert!(
            encoded.len() < original.len() * 2,
            "opus should compress: {} bytes for {} samples",
            encoded.len(),
            original.len()
        );
        assert!(encoded.len() <= 1024);

        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), original.len());

        // Opus has a lookahead, so the first milliseconds of a decoded frame
        // are still silence: compare loudness over the part that carries the
        // signal rather than over the whole frame.
        let from = codec.frame_size() / 2;
        let before = rms(&original[from..]);
        let after = rms(&decoded[from..]);
        assert!(
            (before - after).abs() / before < 0.2,
            "loudness changed from {before} to {after}"
        );
        assert!(after > 0.05, "the decoded frame is silent: {after}");
    }

    #[test]
    fn opus_refuses_a_frame_it_cannot_encode() {
        let mut codec = OpusCodec::new(48_000, 1024, false).unwrap();
        assert!(codec.encode(&[0i16; 100]).is_err());
    }

    #[test]
    fn capture_info_chooses_opus() {
        let codec = from_capture(Some("opus"), 48_000, 1024, false).unwrap();
        assert_eq!(codec.name(), "opus");
        assert_eq!(codec.frame_size(), 960);
    }
}
