#![forbid(unsafe_code)]

use imperialism_core::{CoarseMapGeneration, GameState, RetailLcg, generate_coarse_random_map};
pub use imperialism_formats::RuntimeCaptureError;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Difference {
    pub path: String,
    pub original: Option<serde_json::Value>,
    pub reimplementation: Option<serde_json::Value>,
}

pub fn read_game_state(path: impl AsRef<Path>) -> Result<GameState, RuntimeCaptureError> {
    imperialism_formats::read_runtime_capture(path, "game_state")
}

pub fn read_coarse_map_generation(
    path: impl AsRef<Path>,
) -> Result<CoarseMapGeneration, RuntimeCaptureError> {
    imperialism_formats::read_runtime_capture(path, "coarse_map_generation")
}

pub fn generate_and_compare_coarse_capture(
    expected: &CoarseMapGeneration,
) -> Result<CoarseMapGeneration, Difference> {
    let mut rng = RetailLcg::from_state(expected.initial_map_lcg);
    let actual = generate_coarse_random_map(&mut rng);
    match first_serialized_difference(expected, &actual) {
        Ok(None) => Ok(actual),
        Ok(Some(difference)) => Err(difference),
        Err(error) => unreachable!("semantic state serialization failed: {error}"),
    }
}

pub fn first_serialized_difference<T: Serialize>(
    original: &T,
    reimplementation: &T,
) -> Result<Option<Difference>, serde_json::Error> {
    let original = serde_json::to_value(original)?;
    let reimplementation = serde_json::to_value(reimplementation)?;
    Ok(difference_at(
        String::new(),
        Some(&original),
        Some(&reimplementation),
    ))
}

fn difference_at(
    path: String,
    original: Option<&serde_json::Value>,
    reimplementation: Option<&serde_json::Value>,
) -> Option<Difference> {
    if original == reimplementation {
        return None;
    }
    match (original, reimplementation) {
        (Some(serde_json::Value::Object(left)), Some(serde_json::Value::Object(right))) => left
            .keys()
            .chain(right.keys())
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .find_map(|key| {
                let child = if path.is_empty() {
                    key.to_owned()
                } else {
                    format!("{path}.{key}")
                };
                difference_at(child, left.get(key), right.get(key))
            }),
        (Some(serde_json::Value::Array(left)), Some(serde_json::Value::Array(right))) => {
            (0..left.len().max(right.len())).find_map(|index| {
                difference_at(
                    format!("{path}[{index}]"),
                    left.get(index),
                    right.get(index),
                )
            })
        }
        _ => Some(Difference {
            path,
            original: original.cloned(),
            reimplementation: reimplementation.cloned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reports_the_first_serialized_path() {
        let original = json!({"cities": [{"stock": [2, 4, 6]}]});
        let reimplementation = json!({"cities": [{"stock": [2, 5, 6]}]});
        let difference = first_serialized_difference(&original, &reimplementation)
            .unwrap()
            .unwrap();
        assert_eq!(difference.path, "cities[0].stock[1]");
        assert_eq!(difference.original, Some(json!(4)));
        assert_eq!(difference.reimplementation, Some(json!(5)));
    }

    #[test]
    fn accepts_equal_values() {
        let value = json!({"turn": 3, "flags": [true, false]});
        assert_eq!(first_serialized_difference(&value, &value).unwrap(), None);
    }
}
