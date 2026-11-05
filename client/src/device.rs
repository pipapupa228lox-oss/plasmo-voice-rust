//! The sound card, behind the `device` feature: microphone frames in, mixed
//! audio out.
//!
//! This is the part the game process owns. It only knows rates and buffers, so
//! it can be lifted into the Horizon mod unchanged.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

use crate::audio::{frame, resample, Mixer};

/// Opens the default microphone and sends frames of `frame_size` samples at
/// `codec_rate`, whatever the device's own rate is.
///
/// The returned stream must be kept alive; dropping it stops the capture.
pub fn capture_frames(
    codec_rate: u32,
    frame_size: usize,
    sink: Sender<Vec<i16>>,
) -> Result<cpal::Stream, String> {
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or("no microphone: the default input device is missing")?;
    let config = device
        .default_input_config()
        .map_err(|error| format!("microphone config: {error}"))?;

    let device_rate = config.sample_rate().0;
    let channels = config.channels() as usize;
    let mut pending: Vec<i16> = Vec::new();

    let stream = device
        .build_input_stream(
            &config.into(),
            move |data: &[f32], _: &cpal::InputCallbackInfo| {
                // Downmix to mono and rescale from the device's rate.
                pending.extend(
                    data.chunks(channels.max(1))
                        .map(|frame| {
                            let sum: f32 = frame.iter().sum();
                            (sum / channels.max(1) as f32 * 32_767.0) as i16
                        }),
                );
                let needed = pending.len() as f64 * codec_rate as f64 / device_rate as f64;
                if needed >= frame_size as f64 {
                    let ready = resample(&pending, device_rate, codec_rate);
                    pending.clear();
                    for chunk in frame(&ready, frame_size) {
                        if sink.send(chunk).is_err() {
                            break;
                        }
                    }
                }
            },
            move |error| eprintln!("microphone error: {error}"),
            None,
        )
        .map_err(|error| format!("microphone stream: {error}"))?;

    stream
        .play()
        .map_err(|error| format!("microphone start: {error}"))?;
    Ok(stream)
}

/// Opens the default speakers and plays what the [`Mixer`] holds.
///
/// The returned stream must be kept alive; dropping it stops playback.
pub fn play_mixer(mixer: Arc<Mutex<Mixer>>) -> Result<cpal::Stream, String> {
    let host = cpal::default_host();
    let device = host
        .default_output_device()
        .ok_or("no speakers: the default output device is missing")?;
    let config = device
        .default_output_config()
        .map_err(|error| format!("speaker config: {error}"))?;
    let channels = config.channels() as usize;

    let stream = device
        .build_output_stream(
            &config.into(),
            move |data: &mut [f32], _: &cpal::OutputCallbackInfo| {
                if let Ok(mut mixer) = mixer.lock() {
                    mixer.mix(data, channels);
                } else {
                    data.fill(0.0);
                }
            },
            move |error| eprintln!("speaker error: {error}"),
            None,
        )
        .map_err(|error| format!("speaker stream: {error}"))?;

    stream
        .play()
        .map_err(|error| format!("speaker start: {error}"))?;
    Ok(stream)
}
