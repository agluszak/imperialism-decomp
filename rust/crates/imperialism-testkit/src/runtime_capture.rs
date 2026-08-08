use serde::Deserialize;
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

#[derive(Deserialize)]
struct RuntimeResult {
    name: String,
    seed: u32,
    status: RuntimeStatus,
    captures: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeStatus {
    Passed,
    Failed,
    Skipped,
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
    let result: RuntimeResult =
        serde_json::from_reader(reader).map_err(|source| RuntimeCaptureError::Json {
            name: name.to_owned(),
            source,
        })?;
    let _ = (&result.name, result.seed, &result.status);
    let capture = result
        .captures
        .get(name)
        .cloned()
        .ok_or_else(|| RuntimeCaptureError::MissingCapture(name.to_owned()))?;
    serde_json::from_value(capture).map_err(|source| RuntimeCaptureError::Json {
        name: name.to_owned(),
        source,
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
        let input =
            br#"{"name":"probe","seed":1,"status":"passed","captures":{"probe":{"value":7}}}"#;
        assert_eq!(
            decode_runtime_capture::<Probe>(&input[..], "probe").unwrap(),
            Probe { value: 7 }
        );
    }

    #[test]
    fn ignores_unknown_top_level_fields() {
        let input = br#"{"name":"probe","seed":1,"status":"passed","captures":{"probe":{"value":7}},"obsolete_capture":{}}"#;
        assert_eq!(
            decode_runtime_capture::<Probe>(&input[..], "probe").unwrap(),
            Probe { value: 7 }
        );
    }

    #[test]
    fn reports_decode_errors_with_capture_name() {
        let input =
            br#"{"name":"probe","seed":1,"status":"passed","captures":{"probe":{"value":"wrong"}}}"#;
        let error = decode_runtime_capture::<Probe>(&input[..], "probe").unwrap_err();
        assert!(error.to_string().contains("probe"));
        assert!(matches!(error, RuntimeCaptureError::Json { .. }));
    }
}
