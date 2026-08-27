//! GStreamer playbin adapter for retail AVI cinematics.

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

/// Playbin-backed decoder that feeds application-owned RGBA frames while
/// GStreamer owns synchronized movie audio in production.
pub(crate) struct MovieBackend {
    playbin: gst::Element,
    video_sink: gst_app::AppSink,
    path: std::path::PathBuf,
}

impl MovieBackend {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, MovieError> {
        Self::open_inner(path.as_ref())
    }

    fn open_inner(path: &Path) -> Result<Self, MovieError> {
        ensure_initialized();
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
            .sync(true)
            .wait_on_eos(false)
            .build();
        let playbin = gst::ElementFactory::make("playbin")
            .property("uri", uri.as_str())
            .property("video-sink", &video_sink)
            .build()
            .map_err(|error| MovieError::Unplayable {
                path: path.to_owned(),
                detail: error.to_string(),
            })?;

        Ok(Self {
            playbin,
            video_sink,
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

    pub(crate) fn reached_eos(&self) -> bool {
        self.video_sink.is_eos()
            || self.playbin.bus().is_some_and(|bus| {
                bus.timed_pop_filtered(gst::ClockTime::ZERO, &[gst::MessageType::Eos])
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
    use tempfile::TempDir;

    #[test]
    fn missing_movie_is_unplayable_without_stranding() {
        let dir = TempDir::new().unwrap();
        match MovieBackend::open(dir.path().join("missing.avi")) {
            Err(error) => assert!(matches!(error, MovieError::Missing { .. })),
            Ok(_) => panic!("missing AVI must not open"),
        }
    }
}
