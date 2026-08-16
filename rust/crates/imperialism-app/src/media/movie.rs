//! GStreamer playbin adapter. Cinematic session wiring is a follow-up; this module is the
//! production decoder used by tests and by that later caller.

#![allow(dead_code)]

use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;
use gstreamer_video as gst_video;
use gstreamer_video::VideoFrameExt;
use std::path::Path;
use std::sync::Once;
use std::time::Duration;

static GST_INIT: Once = Once::new();

pub(crate) fn ensure_initialized() {
    GST_INIT.call_once(|| {
        gst::init().expect("GStreamer initialization");
    });
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MovieError {
    #[error("movie file is missing or unreadable: {}", path.display())]
    Missing { path: std::path::PathBuf },
    #[error("GStreamer failed to open {}: {detail}", path.display())]
    Unplayable {
        path: std::path::PathBuf,
        detail: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct RgbaFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

pub(crate) fn rgba_frame_to_image(frame: &RgbaFrame) -> Image {
    let mut image = Image::new(
        Extent3d {
            width: frame.width,
            height: frame.height,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        frame.rgba.clone(),
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::MAIN_WORLD | RenderAssetUsages::RENDER_WORLD,
    );
    image.sampler = ImageSampler::nearest();
    image
}

/// Playbin-backed decoder that feeds application-owned RGBA frames.
///
/// Audio stays inside GStreamer. Tests attach `appsink` pads so EOS, skip, and
/// one audio buffer can be observed without a window or sound device.
pub(crate) struct MovieBackend {
    playbin: gst::Element,
    video_sink: gst_app::AppSink,
    audio_sink: gst_app::AppSink,
    path: std::path::PathBuf,
}

impl MovieBackend {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, MovieError> {
        ensure_initialized();
        let path = path.as_ref();
        if !path.is_file() {
            return Err(MovieError::Missing {
                path: path.to_owned(),
            });
        }
        let uri =
            gst::glib::filename_to_uri(path, None).map_err(|error| MovieError::Unplayable {
                path: path.to_owned(),
                detail: error.to_string(),
            })?;

        let video_sink = gst_app::AppSink::builder()
            .caps(
                &gst::Caps::builder("video/x-raw")
                    .field("format", "RGBA")
                    .build(),
            )
            .max_buffers(4)
            .drop(true)
            .sync(false)
            .wait_on_eos(false)
            .build();
        let audio_sink = gst_app::AppSink::builder()
            .caps(&gst::Caps::builder("audio/x-raw").build())
            .max_buffers(4)
            .drop(true)
            .sync(false)
            .wait_on_eos(false)
            .build();
        let playbin = gst::ElementFactory::make("playbin")
            .property("uri", uri.as_str())
            .property("video-sink", &video_sink)
            .property("audio-sink", &audio_sink)
            .build()
            .map_err(|error| MovieError::Unplayable {
                path: path.to_owned(),
                detail: error.to_string(),
            })?;

        Ok(Self {
            playbin,
            video_sink,
            audio_sink,
            path: path.to_owned(),
        })
    }

    pub(crate) fn play(&self) -> Result<(), MovieError> {
        self.playbin
            .set_state(gst::State::Playing)
            .map_err(|error| MovieError::Unplayable {
                path: self.path.clone(),
                detail: error.to_string(),
            })?;
        Ok(())
    }

    pub(crate) fn stop(&self) {
        let _ = self.playbin.set_state(gst::State::Null);
    }

    pub(crate) fn pull_video_frame(
        &self,
        timeout: Duration,
    ) -> Result<Option<RgbaFrame>, MovieError> {
        self.fail_if_error()?;
        let Some(sample) = self.video_sink.try_pull_sample(clock_time(timeout)) else {
            return Ok(None);
        };
        Ok(Some(frame_from_sample(sample, &self.path)?))
    }

    pub(crate) fn pull_audio_buffer(&self, timeout: Duration) -> bool {
        self.audio_sink
            .try_pull_sample(clock_time(timeout))
            .is_some()
    }

    pub(crate) fn reached_eos(&self) -> bool {
        if self.video_sink.is_eos() {
            return true;
        }
        self.playbin.bus().is_some_and(|bus| {
            bus.timed_pop_filtered(gst::ClockTime::from_mseconds(1), &[gst::MessageType::Eos])
                .is_some()
        })
    }

    fn fail_if_error(&self) -> Result<(), MovieError> {
        if let Some(bus) = self.playbin.bus()
            && let Some(message) =
                bus.timed_pop_filtered(gst::ClockTime::ZERO, &[gst::MessageType::Error])
            && let gst::MessageView::Error(error) = message.view()
        {
            return Err(MovieError::Unplayable {
                path: self.path.clone(),
                detail: error.error().to_string(),
            });
        }
        Ok(())
    }
}

impl Drop for MovieBackend {
    fn drop(&mut self) {
        self.stop();
    }
}

fn clock_time(timeout: Duration) -> gst::ClockTime {
    gst::ClockTime::from_nseconds(timeout.as_nanos() as u64)
}

fn frame_from_sample(sample: gst::Sample, path: &Path) -> Result<RgbaFrame, MovieError> {
    let caps = sample.caps().ok_or_else(|| MovieError::Unplayable {
        path: path.to_owned(),
        detail: "video sample has no caps".to_owned(),
    })?;
    let info = gst_video::VideoInfo::from_caps(caps).map_err(|error| MovieError::Unplayable {
        path: path.to_owned(),
        detail: error.to_string(),
    })?;
    let buffer = sample
        .buffer_owned()
        .ok_or_else(|| MovieError::Unplayable {
            path: path.to_owned(),
            detail: "video sample has no buffer".to_owned(),
        })?;
    let frame = gst_video::VideoFrame::from_buffer_readable(buffer, &info).map_err(|_| {
        MovieError::Unplayable {
            path: path.to_owned(),
            detail: "video buffer is not readable".to_owned(),
        }
    })?;
    let plane = frame.plane_data(0).map_err(|_| MovieError::Unplayable {
        path: path.to_owned(),
        detail: "RGBA plane is missing".to_owned(),
    })?;
    let width = frame.width();
    let height = frame.height();
    let stride = frame.plane_stride()[0] as usize;
    let row_bytes = width as usize * 4;
    let mut rgba = Vec::with_capacity(row_bytes * height as usize);
    for row in 0..height as usize {
        let start = row * stride;
        rgba.extend_from_slice(&plane[start..start + row_bytes]);
    }
    Ok(RgbaFrame {
        width,
        height,
        rgba,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::MovieId;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    fn write_cinepak_avi(path: &Path) {
        let status = Command::new("ffmpeg")
            .args([
                "-y",
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=160x120:rate=10:duration=0.5",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=440:duration=0.5",
                "-c:v",
                "cinepak",
                "-c:a",
                "pcm_s16le",
                "-shortest",
            ])
            .arg(path)
            .status()
            .expect("ffmpeg is required to build the Cinepak AVI spike");
        assert!(status.success(), "ffmpeg failed to encode Cinepak AVI");
    }

    fn wait_for_video_frame(movie: &MovieBackend) -> RgbaFrame {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(frame) = movie
                .pull_video_frame(Duration::from_millis(100))
                .expect("video pull")
            {
                return frame;
            }
            assert!(
                deadline.elapsed() < Duration::from_secs(5),
                "timed out waiting for a decoded video frame"
            );
        }
    }

    #[test]
    fn missing_movie_is_unplayable_without_stranding() {
        match MovieBackend::open(Path::new("/tmp/imperialism-missing-open.avi")) {
            Err(error) => assert!(matches!(error, MovieError::Missing { .. })),
            Ok(_) => panic!("missing AVI must not open"),
        }
    }

    #[test]
    fn cinepak_avi_decodes_into_bevy_image_emits_audio_eos_and_stops() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("open.avi");
        write_cinepak_avi(&path);

        let movie = MovieBackend::open(&path).unwrap();
        movie.play().unwrap();
        let frame = wait_for_video_frame(&movie);
        assert_eq!(frame.width, 160);
        assert_eq!(frame.height, 120);
        assert_eq!(frame.rgba.len(), 160 * 120 * 4);
        assert!(
            frame.rgba.iter().any(|byte| *byte != 0),
            "decoded frame should not be empty"
        );

        let image = rgba_frame_to_image(&frame);
        assert_eq!(image.width(), 160);
        assert_eq!(image.height(), 120);

        let mut heard_audio = movie.pull_audio_buffer(Duration::from_millis(250));
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !heard_audio && deadline.elapsed() < Duration::from_secs(3) {
            heard_audio = movie.pull_audio_buffer(Duration::from_millis(100));
        }
        assert!(heard_audio, "GStreamer should deliver movie audio buffers");

        let mut frames = 1usize;
        let mut eos = false;
        let eos_deadline = std::time::Instant::now() + Duration::from_secs(4);
        while eos_deadline.elapsed() < Duration::from_secs(4) {
            let _ = movie.pull_audio_buffer(Duration::from_millis(10));
            if movie
                .pull_video_frame(Duration::from_millis(50))
                .unwrap()
                .is_some()
            {
                frames += 1;
            }
            if movie.reached_eos() {
                eos = true;
                break;
            }
        }
        assert!(
            frames >= 2,
            "Cinepak clip should yield multiple frames, got {frames}"
        );
        assert!(
            eos,
            "playbin/appsink should report EOS at the end of the clip"
        );

        movie.stop();
        assert!(
            movie
                .pull_video_frame(Duration::from_millis(50))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires IMPERIALISM_RETAIL_DIR pointing at the English GOG installation"]
    fn decodes_untouched_retail_open_avi() {
        let root = PathBuf::from(
            std::env::var_os("IMPERIALISM_RETAIL_DIR")
                .expect("IMPERIALISM_RETAIL_DIR must name the English GOG installation"),
        );
        let assets = imperialism_formats::RetailAssets::open(&root).unwrap();
        let path = assets.movie_path(MovieId::Open);
        let movie = MovieBackend::open(&path).unwrap();
        movie.play().unwrap();
        let frame = wait_for_video_frame(&movie);
        assert!(frame.width > 0 && frame.height > 0);
        let _image = rgba_frame_to_image(&frame);
        movie.stop();
    }
}
