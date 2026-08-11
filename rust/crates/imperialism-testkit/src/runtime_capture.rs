use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Runtime catalog evidence classification. Same strings as
/// `decomp/tools/runtime/catalog.py` `EvidenceKind`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    SelfConsistency,
    InternalInvariant,
    MacResourceOracle,
    RetailFixtureOracle,
    RetailDifferential,
}

impl EvidenceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SelfConsistency => "self_consistency",
            Self::InternalInvariant => "internal_invariant",
            Self::MacResourceOracle => "mac_resource_oracle",
            Self::RetailFixtureOracle => "retail_fixture_oracle",
            Self::RetailDifferential => "retail_differential",
        }
    }
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EvidenceKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "self_consistency" => Ok(Self::SelfConsistency),
            "internal_invariant" => Ok(Self::InternalInvariant),
            "mac_resource_oracle" => Ok(Self::MacResourceOracle),
            "retail_fixture_oracle" => Ok(Self::RetailFixtureOracle),
            "retail_differential" => Ok(Self::RetailDifferential),
            other => Err(format!("unknown evidence kind {other:?}")),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeCaptureError {
    #[error("could not read runtime result: {0}")]
    Io(#[source] std::io::Error),
    #[error("could not decode runtime result: {0}")]
    Json(#[source] serde_json::Error),
    #[error("could not decode capture {name}: {source}")]
    CaptureJson {
        name: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("capture {name} contains unknown field(s): {fields}")]
    UnknownCaptureFields { name: String, fields: String },
    #[error("{0}")]
    Invalid(String),
    #[error("runtime result contains no {0} capture")]
    MissingCapture(String),
    #[error("captures checksum mismatch: expected {expected}, actual {actual}")]
    ChecksumMismatch { expected: String, actual: String },
}

/// Expectations for a published Python runtime result (`result.json`), not the
/// pre-enrichment `native-result.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeResultExpectations<'a> {
    pub name: &'a str,
    pub seed: u32,
    pub evidence_kind: EvidenceKind,
    pub required_captures: &'a [&'a str],
}

/// Published runtime result after name/seed/status/evidence/capture checks.
#[derive(Clone, Debug)]
pub struct ValidatedRuntimeResult {
    pub name: String,
    pub seed: u32,
    pub evidence_kind: EvidenceKind,
    captures: BTreeMap<String, serde_json::Value>,
}

impl ValidatedRuntimeResult {
    pub fn capture<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<T, RuntimeCaptureError> {
        let capture = self
            .captures
            .get(name)
            .cloned()
            .ok_or_else(|| RuntimeCaptureError::MissingCapture(name.to_owned()))?;
        deserialize_capture(name, capture)
    }
}

fn deserialize_capture<T: serde::de::DeserializeOwned>(
    name: &str,
    capture: serde_json::Value,
) -> Result<T, RuntimeCaptureError> {
    let mut unknown = Vec::new();
    let value: T = serde_ignored::deserialize(capture, |path| {
        unknown.push(path.to_string());
    })
    .map_err(|source| RuntimeCaptureError::CaptureJson {
        name: name.to_owned(),
        source,
    })?;
    if !unknown.is_empty() {
        unknown.sort();
        return Err(RuntimeCaptureError::UnknownCaptureFields {
            name: name.to_owned(),
            fields: unknown.join(", "),
        });
    }
    Ok(value)
}

#[derive(Deserialize)]
struct RawRuntimeResult {
    name: String,
    seed: u32,
    status: String,
    evidence_kind: Option<EvidenceKind>,
    captures_path: String,
    #[serde(default)]
    captures_sha256: Option<String>,
}

pub fn read_runtime_result(
    path: impl AsRef<Path>,
    expectations: RuntimeResultExpectations<'_>,
) -> Result<ValidatedRuntimeResult, RuntimeCaptureError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(RuntimeCaptureError::Io)?;
    let raw: RawRuntimeResult = serde_json::from_reader(file).map_err(RuntimeCaptureError::Json)?;
    let captures_path = resolve_captures_path(path, &raw.captures_path);
    let captures_bytes = fs::read(&captures_path).map_err(RuntimeCaptureError::Io)?;
    if let Some(expected) = raw.captures_sha256.as_deref() {
        let actual = hex_sha256(&captures_bytes);
        if !expected.eq_ignore_ascii_case(&actual) {
            return Err(RuntimeCaptureError::ChecksumMismatch {
                expected: expected.to_owned(),
                actual,
            });
        }
    }
    let captures: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&captures_bytes).map_err(RuntimeCaptureError::Json)?;
    validate_runtime_result(raw, captures, expectations)
}

/// Decode a published envelope whose captures are already inlined for unit tests.
pub fn decode_runtime_result(
    reader: impl Read,
    expectations: RuntimeResultExpectations<'_>,
) -> Result<ValidatedRuntimeResult, RuntimeCaptureError> {
    #[derive(Deserialize)]
    struct InlineRuntimeResult {
        name: String,
        seed: u32,
        status: String,
        evidence_kind: Option<EvidenceKind>,
        captures_path: Option<String>,
        captures: Option<BTreeMap<String, serde_json::Value>>,
        #[serde(default)]
        captures_sha256: Option<String>,
    }
    let inline: InlineRuntimeResult =
        serde_json::from_reader(reader).map_err(RuntimeCaptureError::Json)?;
    let captures = inline.captures.ok_or_else(|| {
        RuntimeCaptureError::Invalid(
            "decode_runtime_result requires inline captures for in-memory envelopes".to_owned(),
        )
    })?;
    let raw = RawRuntimeResult {
        name: inline.name,
        seed: inline.seed,
        status: inline.status,
        evidence_kind: inline.evidence_kind,
        captures_path: inline.captures_path.unwrap_or_default(),
        captures_sha256: inline.captures_sha256,
    };
    validate_runtime_result(raw, captures, expectations)
}

fn resolve_captures_path(envelope_path: &Path, captures_path: &str) -> PathBuf {
    let path = PathBuf::from(captures_path);
    if path.is_absolute() {
        path
    } else {
        envelope_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn validate_runtime_result(
    raw: RawRuntimeResult,
    captures: BTreeMap<String, serde_json::Value>,
    expectations: RuntimeResultExpectations<'_>,
) -> Result<ValidatedRuntimeResult, RuntimeCaptureError> {
    if raw.name != expectations.name {
        return Err(RuntimeCaptureError::Invalid(format!(
            "runtime result name {:?}, expected {:?}",
            raw.name, expectations.name
        )));
    }
    if raw.seed != expectations.seed {
        return Err(RuntimeCaptureError::Invalid(format!(
            "runtime result seed {}, expected {}",
            raw.seed, expectations.seed
        )));
    }
    if raw.status != "passed" {
        return Err(RuntimeCaptureError::Invalid(format!(
            "runtime result status {:?}, expected \"passed\"",
            raw.status
        )));
    }
    let evidence_kind = raw.evidence_kind.ok_or_else(|| {
        RuntimeCaptureError::Invalid(
            "runtime result is missing evidence_kind (native-result.json is not accepted; use the published result.json)"
                .to_owned(),
        )
    })?;
    if evidence_kind != expectations.evidence_kind {
        return Err(RuntimeCaptureError::Invalid(format!(
            "runtime result evidence_kind {evidence_kind}, expected {}",
            expectations.evidence_kind
        )));
    }
    for name in expectations.required_captures {
        if !captures.contains_key(*name) {
            return Err(RuntimeCaptureError::MissingCapture((*name).to_owned()));
        }
    }
    Ok(ValidatedRuntimeResult {
        name: raw.name,
        seed: raw.seed,
        evidence_kind,
        captures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_core::*;
    use serde_json::json;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Probe {
        value: i32,
    }

    fn passed_result() -> serde_json::Value {
        json!({
            "name": "probe",
            "seed": 1,
            "status": "passed",
            "evidence_kind": "retail_fixture_oracle",
            "captures_path": "captures.json",
            "captures": {"probe": {"value": 7}, "before": {}, "case": {}, "after": {}},
            "host": {"ignored": true},
            "summary": {"ignored": true},
        })
    }

    fn expectations() -> RuntimeResultExpectations<'static> {
        RuntimeResultExpectations {
            name: "probe",
            seed: 1,
            evidence_kind: EvidenceKind::RetailFixtureOracle,
            required_captures: &["probe"],
        }
    }

    #[test]
    fn accepts_a_published_result_and_keeps_evidence() {
        let bytes = serde_json::to_vec(&passed_result()).unwrap();
        let result = decode_runtime_result(&bytes[..], expectations()).unwrap();
        assert_eq!(result.name, "probe");
        assert_eq!(result.seed, 1);
        assert_eq!(result.evidence_kind, EvidenceKind::RetailFixtureOracle);
        assert_eq!(
            result.capture::<Probe>("probe").unwrap(),
            Probe { value: 7 }
        );
    }

    #[test]
    fn rejects_native_result_without_evidence_kind() {
        let input =
            br#"{"name":"probe","seed":1,"status":"passed","captures_path":"captures.json","captures":{"probe":{"value":7}}}"#;
        let error = decode_runtime_result(&input[..], expectations()).unwrap_err();
        assert!(error.to_string().contains("evidence_kind"));
    }

    #[test]
    fn rejects_wrong_name_seed_status_and_evidence() {
        let bytes = serde_json::to_vec(&passed_result()).unwrap();
        assert!(
            decode_runtime_result(
                &bytes[..],
                RuntimeResultExpectations {
                    name: "other",
                    ..expectations()
                },
            )
            .unwrap_err()
            .to_string()
            .contains("name")
        );
        assert!(
            decode_runtime_result(
                &bytes[..],
                RuntimeResultExpectations {
                    seed: 9,
                    ..expectations()
                },
            )
            .unwrap_err()
            .to_string()
            .contains("seed")
        );
        let failed = json!({
            "name": "probe",
            "seed": 1,
            "status": "failed",
            "evidence_kind": "retail_fixture_oracle",
            "captures_path": "captures.json",
            "captures": {"probe": {"value": 7}},
        });
        assert!(
            decode_runtime_result(
                serde_json::to_vec(&failed).unwrap().as_slice(),
                expectations(),
            )
            .unwrap_err()
            .to_string()
            .contains("status")
        );
        assert!(
            decode_runtime_result(
                &bytes[..],
                RuntimeResultExpectations {
                    evidence_kind: EvidenceKind::SelfConsistency,
                    ..expectations()
                },
            )
            .unwrap_err()
            .to_string()
            .contains("evidence_kind")
        );
    }

    #[test]
    fn rejects_missing_required_captures() {
        let bytes = serde_json::to_vec(&passed_result()).unwrap();
        let error = decode_runtime_result(
            &bytes[..],
            RuntimeResultExpectations {
                required_captures: &["before", "case", "after", "missing"],
                ..expectations()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            RuntimeCaptureError::MissingCapture(name) if name == "missing"
        ));
    }

    #[test]
    fn reports_capture_decode_errors_with_capture_name() {
        let input = json!({
            "name": "probe",
            "seed": 1,
            "status": "passed",
            "evidence_kind": "retail_fixture_oracle",
            "captures_path": "captures.json",
            "captures": {"probe": {"value": "wrong"}},
        });
        let result = decode_runtime_result(
            serde_json::to_vec(&input).unwrap().as_slice(),
            expectations(),
        )
        .unwrap();
        let error = result.capture::<Probe>("probe").unwrap_err();
        assert!(error.to_string().contains("probe"));
        assert!(matches!(error, RuntimeCaptureError::CaptureJson { .. }));
    }

    #[test]
    fn rejects_unknown_capture_fields() {
        let input = json!({
            "name": "probe",
            "seed": 1,
            "status": "passed",
            "evidence_kind": "retail_fixture_oracle",
            "captures_path": "captures.json",
            "captures": {"probe": {"value": 7, "extra_oracle_field": true}},
        });
        let result = decode_runtime_result(
            serde_json::to_vec(&input).unwrap().as_slice(),
            expectations(),
        )
        .unwrap();
        let error = result.capture::<Probe>("probe").unwrap_err();
        assert!(matches!(
            error,
            RuntimeCaptureError::UnknownCaptureFields { ref name, ref fields }
                if name == "probe" && fields.contains("extra_oracle_field")
        ));
    }

    #[test]
    fn rejects_an_unknown_nested_game_state_field() {
        let mut sea_zone_marker_crt = RetailCrtRng::from_state(1);
        let _ = sea_zone_marker_crt.next_rand();
        let preview = generate_random_setup_preview_with_clock_seed(
            b"Woopnist",
            MapTopology::Wrapping,
            1,
            sea_zone_marker_crt,
        );
        let state = create_random_game(&preview, MajorNationId::new(6), Difficulty::Easy, 1);
        let mut capture = serde_json::to_value(&state).unwrap();
        capture["turn"]["oracle_extra"] = json!(true);
        capture["diplomacy"]["oracle_extra"] = json!(true);
        capture["provinces"][0]["oracle_extra"] = json!(true);
        let input = json!({
            "name": "probe",
            "seed": 1,
            "status": "passed",
            "evidence_kind": "retail_fixture_oracle",
            "captures_path": "captures.json",
            "captures": {"probe": capture},
        });
        let result = decode_runtime_result(
            serde_json::to_vec(&input).unwrap().as_slice(),
            expectations(),
        )
        .unwrap();

        let error = result.capture::<GameState>("probe").unwrap_err();
        assert!(matches!(
            error,
            RuntimeCaptureError::UnknownCaptureFields { fields, .. }
                if fields.contains("turn.oracle_extra")
                    && fields.contains("diplomacy.oracle_extra")
                    && fields.contains("provinces.0.oracle_extra")
        ));
    }

    #[test]
    fn parses_evidence_kind_strings() {
        assert_eq!(
            "retail_differential".parse::<EvidenceKind>().unwrap(),
            EvidenceKind::RetailDifferential
        );
        assert!("nope".parse::<EvidenceKind>().is_err());
    }
}
