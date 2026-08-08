use serde::Deserialize;
use serde::de::IntoDeserializer;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeCaptureError {
    #[error("could not read runtime result: {0}")]
    Io(#[source] std::io::Error),
    #[error("could not decode runtime result at {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("runtime result contains no {0} capture")]
    MissingCapture(String),
}

#[derive(Deserialize)]
struct RuntimeResult {
    captures: BTreeMap<String, serde_json::Value>,
}

pub fn read_runtime_capture<T: serde::de::DeserializeOwned>(
    path: impl AsRef<Path>,
    name: &str,
) -> Result<T, RuntimeCaptureError> {
    let file = File::open(path).map_err(RuntimeCaptureError::Io)?;
    decode_runtime_capture(file, name)
}

pub fn decode_runtime_capture<T: serde::de::DeserializeOwned>(
    reader: impl Read,
    name: &str,
) -> Result<T, RuntimeCaptureError> {
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let result: RuntimeResult =
        serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
            RuntimeCaptureError::Json {
                path: error.path().to_string(),
                source: error.into_inner(),
            }
        })?;
    let capture = result
        .captures
        .get(name)
        .cloned()
        .ok_or_else(|| RuntimeCaptureError::MissingCapture(name.to_owned()))?;
    serde_path_to_error::deserialize(capture.into_deserializer()).map_err(|error| {
        RuntimeCaptureError::Json {
            path: format!("captures.{name}.{}", error.path()),
            source: error.into_inner(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Probe {
        value: i32,
    }

    #[test]
    fn reads_named_captures() {
        let input = br#"{"captures":{"probe":{"value":7}}}"#;
        assert_eq!(
            decode_runtime_capture::<Probe>(&input[..], "probe").unwrap(),
            Probe { value: 7 }
        );
    }

    #[test]
    fn reports_the_semantic_capture_path() {
        let input = br#"{"captures":{"probe":{"value":"wrong"}}}"#;
        let error = decode_runtime_capture::<Probe>(&input[..], "probe").unwrap_err();
        assert!(error.to_string().contains("captures.probe.value"));
    }
}
