//! Turning decoded frames into what the speakers play.
//!
//! Three pieces:
//!
//! * [`Mixer`] holds one buffer per speaker and sums them, attenuating by
//!   distance the way the plugin's client does: linear falloff to the
//!   activation's distance, nothing past it.
//! * [`resample`] moves a device's rate to the server's 48 kHz and back, since
//!   a headset rarely runs at exactly the codec's rate.
//! * [`frame`] is the microphone side: whatever the device gives is cut into
//!   frames of the size the codec wants.

use std::collections::HashMap;

use pv_proto::Uuid;

/// Linear falloff: full volume at the speaker, silent at `distance` blocks.
/// Two players standing on each other are not boosted, and a speaker beyond
/// the activation's distance is not heard at all.
pub fn gain(distance_in_blocks: f32, activation_distance: f32) -> f32 {
    if activation_distance <= 0.0 {
        return 1.0;
    }
    (1.0 - distance_in_blocks / activation_distance).clamp(0.0, 1.0)
}

/// `HRTF`-lite: how far the far ear trails the near one, in samples. A head is
/// about 0.2 m wide, which is 0.6 ms of sound, 32 samples at 48 kHz.
const MAX_DELAY: usize = 32;
/// One-pole low-pass on the far ear: about 2 kHz at 48 kHz, so the far side of
/// a voice is duller as well as quieter, as a head shadow does it.
const FAR_ALPHA: f32 = 0.25;

/// One buffer of samples per player, mixed into the device's buffer.
#[derive(Default)]
pub struct Mixer {
    voices: HashMap<Uuid, Vec<i16>>,
    /// Distances from the last `SourceInfo`, per source.
    distances: HashMap<Uuid, f32>,
    /// How far each source is heard, per source: a line's own distance when it
    /// has one, the mixer's activation distance otherwise.
    ranges: HashMap<Uuid, f32>,
    /// The menu's per-player volume, 0..2, as a factor; missing is 1.
    volumes: HashMap<Uuid, f32>,
    /// Where each source is, left to right: -1 is hard left, 1 hard right.
    pans: HashMap<Uuid, f32>,
    /// The last samples of each source, so the far ear can be delayed across
    /// the edge of a block.
    tails: HashMap<Uuid, Vec<i16>>,
    /// The far ear's low-pass state, per source.
    dulling: HashMap<Uuid, f32>,
    /// `Sound Occlusion`: the gain a wall leaves, per source, and the value
    /// actually applied as it slides there.
    occlusions: HashMap<Uuid, f32>,
    occluded: HashMap<Uuid, f32>,
    /// How far this client hears, in blocks; set from the activation config.
    pub activation_distance: f32,
    /// `Stereo Positioning`: pan each source by where it is, as the mod does
    /// with OpenAL. Off, every source is centred.
    pub panning: bool,
    pub master_volume: f32,
    /// `Adaptive Jitter Buffer`: a second of queue when on (the mod's default),
    /// 60 ms when off — a fixed, low-latency buffer that cuts sooner.
    pub adaptive: bool,
    /// `Exponential Distance Gain`: the linear falloff squared, as the mod's
    /// option bends it, instead of the straight line.
    pub exponential: bool,
}

impl Mixer {
    pub fn new(activation_distance: f32) -> Self {
        Mixer {
            voices: HashMap::new(),
            distances: HashMap::new(),
            ranges: HashMap::new(),
            volumes: HashMap::new(),
            pans: HashMap::new(),
            tails: HashMap::new(),
            dulling: HashMap::new(),
            occlusions: HashMap::new(),
            occluded: HashMap::new(),
            activation_distance,
            panning: true,
            master_volume: 1.0,
            adaptive: true,
            exponential: true,
        }
    }

    /// Queues a decoded frame for a speaker. Frames are appended, so a jittery
    /// network plays them in order instead of dropping them.
    pub fn push(&mut self, source: Uuid, samples: Vec<i16>) {
        self.voices.entry(source).or_default().extend(samples);
    }

    /// The distance the server last reported for this source.
    pub fn set_distance(&mut self, source: Uuid, distance: f32) {
        self.distances.insert(source, distance);
    }

    /// How far this source is heard, when its line says something other than
    /// the mixer's default.
    pub fn set_range(&mut self, source: Uuid, range: f32) {
        self.ranges.insert(source, range.max(0.0));
    }

    /// Where the source is, from the listener's point of view: -1 left,
    /// 0 in front or behind, 1 right.
    pub fn set_pan(&mut self, source: Uuid, pan: f32) {
        self.pans.insert(source, pan.clamp(-1.0, 1.0));
    }

    /// What a wall leaves of the source: 1.0 in the open, less behind blocks.
    /// The mixer slides towards it instead of stepping, so a doorway is not a
    /// click.
    pub fn set_occlusion(&mut self, source: Uuid, factor: f32) {
        self.occlusions.insert(source, factor.clamp(0.0, 1.0));
    }

    /// The Volume tab's slider for one speaker, as a factor (1.0 is 100 %).
    pub fn set_volume(&mut self, source: Uuid, volume: f32) {
        self.volumes.insert(source, volume.clamp(0.0, 2.0));
    }

    /// How many samples are queued for everyone, in total.
    pub fn queued(&self) -> usize {
        self.voices.values().map(Vec::len).sum()
    }

    /// Sums the queues into `out`, which the device plays. Samples are
    /// interleaved at the device's channel count; mono game audio is copied to
    /// every channel. Returns the number of samples written.
    ///
    /// A buffer that runs dry is silence, and a buffer that grows past a second
    /// is cut: latency must not accumulate when the network stalls.
    pub fn mix(&mut self, out: &mut [f32], channels: usize) -> usize {
        for samples in out.iter_mut() {
            *samples = 0.0;
        }
        let max_queued = if self.adaptive { 48_000 } else { 2_880 };

        for (source, queue) in self.voices.iter_mut() {
            if queue.len() > max_queued {
                let drop = queue.len() - max_queued;
                queue.drain(..drop);
            }
            let distance = self.distances.get(source).copied().unwrap_or(0.0);
            let range = self
                .ranges
                .get(source)
                .copied()
                .unwrap_or(self.activation_distance);
            let linear = gain(distance, range);
            // `BaseClientAudioSource.calculateDistanceGain`: the linear falloff
            // raised to the cube when `exponentialDistanceGain` is on, which it
            // is by default. A speaker halfway to the edge is at 12.5 %, not
            // the 25 % a square would give.
            let falloff = if self.exponential {
                linear * linear * linear
            } else {
                linear
            };
            let target = self.occlusions.get(source).copied().unwrap_or(1.0);
            let sliding = self.occluded.entry(*source).or_insert(1.0);
            // The same asymmetry the mod has: a wall that appears is heard at
            // once, and the ear opens again in 0.05 steps once it is gone.
            if target < *sliding {
                *sliding = target;
            } else {
                *sliding = (*sliding + 0.05).min(target);
            }
            let level = falloff
                * self.master_volume
                * self.volumes.get(source).copied().unwrap_or(1.0)
                * *sliding;
            if level <= 0.0 {
                queue.clear();
                continue;
            }
            // Equal power: a source in the middle is 3 dB down in each ear, not
            // 6 dB summed, and hard left loses nothing on the left.
            let (left, right) = if self.panning {
                let pan = self.pans.get(source).copied().unwrap_or(0.0);
                let angle = (pan + 1.0) * std::f32::consts::FRAC_PI_4;
                (angle.cos(), angle.sin())
            } else {
                (1.0, 1.0)
            };
            let channels = channels.max(1);
            let take = queue.len().min(out.len() / channels);
            // The far ear hears the source a little later and duller: the head
            // is in the way. Samples from the previous block are kept so the
            // delay does not click at every edge.
            let mut buf = self.tails.remove(source).unwrap_or_default();
            buf.extend(queue.drain(..take));
            let pan = if self.panning {
                self.pans.get(source).copied().unwrap_or(0.0)
            } else {
                0.0
            };
            let delay = (pan.abs() * MAX_DELAY as f32).round() as usize;
            let state = self.dulling.entry(*source).or_insert(0.0);
            let start = buf.len().saturating_sub(take);
            for index in 0..take {
                let near = buf[start + index];
                // Before the delay has passed there is nothing to hear yet:
                // `saturating_sub` would otherwise read the attack itself.
                let far = (start + index)
                    .checked_sub(delay)
                    .and_then(|at| buf.get(at).copied())
                    .unwrap_or(0);
                let near_value = near as f32 / 32_768.0 * level;
                let far_raw = far as f32 / 32_768.0 * level;
                let far_value = if delay == 0 {
                    // Straight ahead or behind: both ears get the same signal,
                    // not a dulled copy of it.
                    *state = near_value;
                    near_value
                } else {
                    *state += (far_raw - *state) * FAR_ALPHA;
                    *state
                };
                let base = index * channels;
                if channels == 1 {
                    out[base] += near_value;
                    continue;
                }
                // The right pan puts the source on the right: that ear is the
                // near one.
                let (left_value, right_value) = if pan >= 0.0 {
                    (far_value, near_value)
                } else {
                    (near_value, far_value)
                };
                out[base] += left_value * left;
                out[base + 1] += right_value * right;
                // Surround layouts: the rear channels get the centre.
                let centre = (left + right) * 0.5;
                for channel in 2..channels {
                    out[base + channel] += (left_value + right_value) * 0.5 * centre;
                }
            }
            let keep = buf.len().saturating_sub(MAX_DELAY);
            self.tails.insert(*source, buf[keep..].to_vec());
        }

        // Summing can clip; the device wants -1..1.
        for samples in out.iter_mut() {
            *samples = samples.clamp(-1.0, 1.0);
        }
        out.len()
    }

    /// Drops everything queued: on disconnect, or when switching server.
    pub fn clear(&mut self) {
        self.voices.clear();
        self.distances.clear();
        self.ranges.clear();
        self.volumes.clear();
        self.pans.clear();
        self.tails.clear();
        self.dulling.clear();
        self.occlusions.clear();
        self.occluded.clear();
    }
}

/// Linear resampling between two rates. Good enough for voice: the codec is
/// 48 kHz mono and the devices are 44.1 or 48, a few percent apart.
pub fn resample(input: &[i16], from: u32, to: u32) -> Vec<i16> {
    if from == to || input.is_empty() {
        return input.to_vec();
    }
    let ratio = from as f64 / to as f64;
    let length = (input.len() as f64 / ratio).round() as usize;
    let mut out = Vec::with_capacity(length);

    for index in 0..length {
        let position = index as f64 * ratio;
        let left = position.floor() as usize;
        let right = (left + 1).min(input.len() - 1);
        let fraction = position - left as f64;
        let value = input[left] as f64 * (1.0 - fraction) + input[right] as f64 * fraction;
        out.push(value.round() as i16);
    }
    out
}

/// Cuts samples into frames of `frame_size`, padding the last one with
/// silence. The codec only takes whole frames.
pub fn frame(samples: &[i16], frame_size: usize) -> Vec<Vec<i16>> {
    if frame_size == 0 {
        return Vec::new();
    }
    let mut frames: Vec<Vec<i16>> = samples
        .chunks(frame_size)
        .map(|chunk| chunk.to_vec())
        .collect();
    if let Some(last) = frames.last_mut() {
        if last.len() < frame_size {
            last.resize(frame_size, 0);
        }
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gain_falls_to_nothing_at_the_activation_distance() {
        assert_eq!(gain(0.0, 16.0), 1.0);
        assert!((gain(8.0, 16.0) - 0.5).abs() < 1e-6);
        assert_eq!(gain(16.0, 16.0), 0.0);
        assert_eq!(gain(64.0, 16.0), 0.0);
    }

    #[test]
    fn two_speakers_sum_and_clip() {
        let mut mixer = Mixer::new(16.0);
        let a = *b"player-a00000000";
        let b = *b"player-b00000000";
        mixer.push(a, vec![20_000; 4]);
        mixer.push(b, vec![20_000; 4]);

        let mut out = [0f32; 4];
        mixer.mix(&mut out, 1);
        assert!(out.iter().all(|sample| *sample <= 1.0 && *sample > 0.9));
        assert_eq!(mixer.queued(), 0);
    }

    #[test]
    fn a_distant_speaker_is_silent_and_dropped() {
        let mut mixer = Mixer::new(16.0);
        let a = *b"player-a00000000";
        mixer.set_distance(a, 40.0);
        mixer.push(a, vec![10_000; 8]);

        let mut out = [0f32; 8];
        mixer.mix(&mut out, 1);
        assert!(out.iter().all(|sample| *sample == 0.0));
        assert_eq!(mixer.queued(), 0);
    }

    #[test]
    fn stereo_output_gets_the_same_mono_sample_in_both_ears() {
        let mut mixer = Mixer::new(16.0);
        let a = *b"player-a00000000";
        mixer.push(a, vec![10_000, -10_000]);

        let mut out = [0f32; 4];
        mixer.mix(&mut out, 2);
        assert!((out[0] - out[1]).abs() < 1e-6);
        assert!((out[2] - out[3]).abs() < 1e-6);
        assert!(out[0] > 0.0 && out[2] < 0.0);
    }

    #[test]
    fn a_right_hand_speaker_is_louder_in_the_right_ear() {
        let mut mixer = Mixer::new(16.0);
        let a = *b"player-a00000000";
        mixer.set_pan(a, 1.0);
        mixer.push(a, vec![10_000; 2]);

        let mut out = [0f32; 4];
        mixer.mix(&mut out, 2);
        assert!(out[0].abs() < 1e-6, "left ear is silent: {out:?}");
        assert!(out[1] > 0.2);
        assert!(out[3] > 0.2);
    }

    #[test]
    fn the_far_ear_hears_the_source_later() {
        let mut mixer = Mixer::new(16.0);
        let a = *b"player-a00000000";
        // Halfway to the right: the left ear is the far one, 16 samples late.
        mixer.set_pan(a, 0.5);
        let mut samples = vec![0i16; 64];
        samples[0] = 20_000;
        mixer.push(a, samples);

        let mut out = [0f32; 128];
        mixer.mix(&mut out, 2);
        assert_eq!(out[0], 0.0, "the far ear is still silent at the attack");
        assert!(out[1] > 0.2, "the near ear hears it at once: {out:?}");
        assert!(out[16 * 2] > 0.0, "the far ear hears it 16 samples later");
    }

    #[test]
    fn a_wall_mutes_at_once_and_the_ear_recovers_in_steps() {
        // `BaseClientAudioSource`: the occlusion percent jumps when it grows
        // and shrinks by 0.05 a frame when it does not.
        let mut mixer = Mixer::new(16.0);
        mixer.panning = false;
        let a = *b"player-a00000000";
        mixer.set_occlusion(a, 0.3);
        mixer.push(a, vec![10_000; 2]);
        let mut blocked = [0f32; 2];
        mixer.mix(&mut blocked, 2);

        // The wall is gone: four frames later a quarter of the way back, not the
        // whole volume at once.
        mixer.set_occlusion(a, 1.0);
        let mut levels = Vec::new();
        for _ in 0..4 {
            mixer.push(a, vec![10_000; 2]);
            let mut out = [0f32; 2];
            mixer.mix(&mut out, 2);
            levels.push(out[0]);
        }
        assert!(
            levels[0] > blocked[0],
            "the first frame after the wall is louder: {levels:?} {blocked:?}"
        );
        assert!(
            levels[3] < 0.6 * levels[0] / 0.35,
            "and it is still well below full volume: {levels:?}"
        );
        for pair in levels.windows(2) {
            assert!(pair[1] > pair[0], "it climbs: {levels:?}");
        }
    }

    #[test]
    fn without_panning_both_ears_get_everything() {
        let mut mixer = Mixer::new(16.0);
        mixer.panning = false;
        let a = *b"player-a00000000";
        mixer.set_pan(a, 1.0);
        mixer.push(a, vec![10_000; 2]);

        let mut out = [0f32; 4];
        mixer.mix(&mut out, 2);
        assert!((out[0] - out[1]).abs() < 1e-6);
    }

    #[test]
    fn resampling_keeps_the_length_proportional() {
        let input: Vec<i16> = (0..480).map(|i| (i * 10) as i16).collect();
        assert_eq!(resample(&input, 48_000, 48_000).len(), 480);
        assert_eq!(resample(&input, 44_100, 48_000).len(), 522);
        assert_eq!(resample(&input, 48_000, 44_100).len(), 441);
        // The ends of the signal survive.
        let up = resample(&input, 24_000, 48_000);
        assert!(up.first().unwrap().abs() < 100);
    }

    #[test]
    fn the_last_frame_is_padded() {
        let frames = frame(&[1i16; 1000], 960);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].len(), 960);
        assert_eq!(frames[1].len(), 960);
        assert_eq!(frames[1][40], 0, "the tail is silence");
    }
}
