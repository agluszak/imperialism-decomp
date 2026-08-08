use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeCaptureError {
    #[error("could not read runtime result: {0}")]
    Io(#[source] std::io::Error),
    #[error("could not decode runtime result for {name}: {source}")]
    Json {
        name: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("runtime result contains no {0} capture")]
    MissingCapture(String),
}

/// Parsed native runtime result.json: outer seed plus named capture payloads.
#[derive(Debug, Deserialize)]
pub struct RuntimeResult {
    #[serde(default)]
    pub seed: u32,
    captures: BTreeMap<String, serde_json::Value>,
}

impl RuntimeResult {
    pub fn read(path: &Path) -> Result<Self, RuntimeCaptureError> {
        let file = File::open(path).map_err(RuntimeCaptureError::Io)?;
        Self::from_reader(file)
    }

    pub fn capture<T: DeserializeOwned>(&self, name: &str) -> Result<T, RuntimeCaptureError> {
        let capture = self
            .captures
            .get(name)
            .cloned()
            .ok_or_else(|| RuntimeCaptureError::MissingCapture(name.to_owned()))?;
        serde_json::from_value(capture).map_err(|source| RuntimeCaptureError::Json {
            name: name.to_owned(),
            source,
        })
    }

    pub(crate) fn from_reader(reader: impl Read) -> Result<Self, RuntimeCaptureError> {
        serde_json::from_reader(reader).map_err(|source| RuntimeCaptureError::Json {
            name: "runtime result".to_owned(),
            source,
        })
    }
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
        let result = RuntimeResult::from_reader(&input[..]).unwrap();
        assert_eq!(
            result.capture::<Probe>("probe").unwrap(),
            Probe { value: 7 }
        );
    }

    #[test]
    fn reads_the_outer_seed() {
        let input =
            br#"{"name":"probe","seed":123,"status":"passed","captures":{"probe":{"value":7}}}"#;
        let result = RuntimeResult::from_reader(&input[..]).unwrap();
        assert_eq!(result.seed, 123);
    }

    #[test]
    fn reports_decode_errors_with_capture_name() {
        let input = br#"{"captures":{"probe":{"value":"wrong"}}}"#;
        let result = RuntimeResult::from_reader(&input[..]).unwrap();
        let error = result.capture::<Probe>("probe").unwrap_err();
        assert!(error.to_string().contains("probe"));
        assert!(matches!(error, RuntimeCaptureError::Json { .. }));
    }
}
