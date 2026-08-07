#![forbid(unsafe_code)]

use imperialism_core::{
    GameState, NationId, ProductionConstraint, ResourceCost, ResourceKind, SkillBand,
    UnitCostProfile, UnitProductionOrder,
};
use imperialism_formats::{LegacySaveV62, LegacySnapshotContext};
use imperialism_testkit::{first_snapshot_difference, read_game_snapshot};
use std::env;
use std::ffi::OsString;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_else(|| "differential".into());
    let fixture = required_argument(&program, arguments.next())?;
    let source = match required_argument(&program, arguments.next())? {
        flag if flag == "--legacy-save" => {
            RustSource::LegacySave(required_argument(&program, arguments.next())?)
        }
        snapshot => RustSource::Snapshot(snapshot),
    };
    let options = parse_options(arguments.collect())?;

    let repository = repository_root()?;
    let output = Command::new("just")
        .current_dir(repository)
        .arg("runtime-run")
        .arg(&fixture)
        .arg("--seed")
        .arg(options.seed.to_string())
        .output()
        .map_err(|error| format!("could not launch the C++ oracle: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "C++ oracle fixture {} failed:\n{}",
            Path::new(&fixture).display(),
            stderr.trim()
        ));
    }
    let artifact_dir = artifact_path(&stderr)
        .ok_or_else(|| "C++ oracle did not report its artifact directory".to_owned())?;
    let cpp_snapshot_path = artifact_dir.join("native-result.json");
    let cpp = read_game_snapshot(&cpp_snapshot_path)
        .map_err(|error| format!("C++ oracle snapshot is invalid: {error}"))?;
    let rust = match source {
        RustSource::Snapshot(path) => read_game_snapshot(Path::new(&path))
            .map_err(|error| format!("Rust snapshot is invalid: {error}"))?,
        RustSource::LegacySave(path) => {
            let bytes = fs::read(&path).map_err(|error| {
                format!(
                    "could not read retail save {}: {error}",
                    Path::new(&path).display()
                )
            })?;
            let save = LegacySaveV62::parse(&bytes)
                .map_err(|error| format!("could not decode retail save: {error}"))?;
            save.snapshot(LegacySnapshotContext {
                runtime_seed: cpp.rng.runtime_seed,
                crt_rand_state: cpp.rng.crt_rand_state,
                map_generation_lcg: cpp.rng.map_generation_lcg,
                zone_status_lcg: cpp.rng.zone_status_lcg,
                selected_nation: cpp.metadata.selected_nation,
            })
            .map_err(|error| format!("could not project retail save: {error}"))?
        }
    };

    if let DifferentialStep::SpecialistRecruitment {
        nation,
        unit_type,
        quantity,
    } = options.step
    {
        let cpp_state = GameState::try_from(cpp)
            .map_err(|error| format!("C++ oracle state is invalid: {error}"))?;
        let mut rust_state = GameState::try_from(rust)
            .map_err(|error| format!("Rust initial state is invalid: {error}"))?;
        let mut order = specialist_order(unit_type, quantity);
        let outcome = rust_state
            .produce_specialist_recruits(NationId::new(nation), &mut order)
            .map_err(|error| format!("Rust specialist recruitment failed: {error}"))?;
        if let Some(difference) = first_state_difference(&cpp_state, &rust_state) {
            return Err(format!("post-command GameState differs: {difference}"));
        }
        println!(
            "post-command GameState is identical ({} domain events)",
            outcome.events.len()
        );
        return Ok(());
    }

    println!("section       C++       Rust");
    for (section, cpp_hash, rust_hash) in [
        ("metadata", &cpp.hashes.metadata, &rust.hashes.metadata),
        ("rng", &cpp.hashes.rng, &rust.hashes.rng),
        ("world", &cpp.hashes.world, &rust.hashes.world),
        ("nations", &cpp.hashes.nations, &rust.hashes.nations),
        ("economy", &cpp.hashes.economy, &rust.hashes.economy),
        ("military", &cpp.hashes.military, &rust.hashes.military),
        ("missions", &cpp.hashes.missions, &rust.hashes.missions),
        ("pending", &cpp.hashes.pending, &rust.hashes.pending),
        ("state", &cpp.hashes.state, &rust.hashes.state),
    ] {
        println!("{section:<12} {cpp_hash}  {rust_hash}");
    }

    match first_snapshot_difference(&cpp, &rust)
        .map_err(|error| format!("could not compare snapshots: {error}"))?
    {
        None => {
            println!("semantic snapshots are identical");
            Ok(())
        }
        Some(difference) => Err(format!(
            "{} differs: C++ {:?}, Rust {:?}",
            difference.path, difference.original, difference.reimplementation
        )),
    }
}

enum RustSource {
    Snapshot(OsString),
    LegacySave(OsString),
}

fn required_argument(program: &OsString, value: Option<OsString>) -> Result<OsString, String> {
    value.ok_or_else(|| {
        format!(
            "usage: {} FIXTURE RUST_SNAPSHOT.json [--seed N]\n       {} FIXTURE --legacy-save SAVE.imp [--seed N] [--specialist-recruit NATION UNIT_TYPE QUANTITY]",
            Path::new(program).display(),
            Path::new(program).display()
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DifferentialOptions {
    seed: u32,
    step: DifferentialStep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DifferentialStep {
    None,
    SpecialistRecruitment {
        nation: u8,
        unit_type: i16,
        quantity: i16,
    },
}

fn parse_options(arguments: Vec<OsString>) -> Result<DifferentialOptions, String> {
    let mut options = DifferentialOptions {
        seed: 1,
        step: DifferentialStep::None,
    };
    let mut arguments = arguments.into_iter();
    while let Some(flag) = arguments.next() {
        if flag == "--seed" {
            options.seed = parse_number(arguments.next(), "--seed", "an unsigned integer")?;
        } else if flag == "--specialist-recruit" {
            if options.step != DifferentialStep::None {
                return Err("only one differential command may be supplied".to_owned());
            }
            options.step = DifferentialStep::SpecialistRecruitment {
                nation: parse_number(arguments.next(), "nation", "an unsigned 8-bit integer")?,
                unit_type: parse_number(arguments.next(), "unit type", "a signed 16-bit integer")?,
                quantity: parse_number(arguments.next(), "quantity", "a signed 16-bit integer")?,
            };
        } else {
            return Err(format!(
                "unexpected differential option {}",
                flag.to_string_lossy()
            ));
        }
    }
    Ok(options)
}

fn parse_number<T: std::str::FromStr>(
    value: Option<OsString>,
    label: &str,
    expected: &str,
) -> Result<T, String> {
    value
        .ok_or_else(|| format!("{label} is required"))?
        .to_string_lossy()
        .parse()
        .map_err(|_| format!("{label} must be {expected}"))
}

fn specialist_order(unit_type: i16, quantity: i16) -> UnitProductionOrder {
    UnitProductionOrder {
        profile: UnitCostProfile {
            entry_id: unit_type,
            primary: ResourceCost {
                resource: ResourceKind::Arms,
                per_unit: 0,
            },
            secondary: None,
            cash_per_unit: 0,
            workforce: Some(SkillBand::High),
            specialist: true,
        },
        quantity,
        tracking_by_resource: [0; ResourceKind::COUNT],
        reserved_workforce: 0,
        limiting_constraint: ProductionConstraint::Resources,
        accumulated_value: 0,
    }
}

fn first_state_difference(original: &GameState, reimplementation: &GameState) -> Option<String> {
    if original.turn != reimplementation.turn {
        return Some(format!(
            "turn: C++ {:?}, Rust {:?}",
            original.turn, reimplementation.turn
        ));
    }
    if original.persistent_unit_id_counter != reimplementation.persistent_unit_id_counter {
        return Some(format!(
            "persistent_unit_id_counter: C++ {}, Rust {}",
            original.persistent_unit_id_counter, reimplementation.persistent_unit_id_counter
        ));
    }
    if original.world != reimplementation.world {
        return Some("world differs".to_owned());
    }
    if original.rng != reimplementation.rng {
        return Some(format!(
            "rng: C++ {:?}, Rust {:?}",
            original.rng, reimplementation.rng
        ));
    }
    first_slice_difference("nations", &original.nations, &reimplementation.nations)
        .or_else(|| first_slice_difference("cities", &original.cities, &reimplementation.cities))
        .or_else(|| {
            first_slice_difference(
                "military_units",
                &original.military_units,
                &reimplementation.military_units,
            )
        })
        .or_else(|| {
            first_slice_difference(
                "civilian_units",
                &original.civilian_units,
                &reimplementation.civilian_units,
            )
        })
        .or_else(|| first_slice_difference("ships", &original.ships, &reimplementation.ships))
        .or_else(|| {
            first_slice_difference(
                "task_forces",
                &original.task_forces,
                &reimplementation.task_forces,
            )
        })
        .or_else(|| {
            first_slice_difference("missions", &original.missions, &reimplementation.missions)
        })
        .or_else(|| {
            (original.pending != reimplementation.pending).then(|| {
                format!(
                    "pending: C++ {:?}, Rust {:?}",
                    original.pending, reimplementation.pending
                )
            })
        })
}

fn first_slice_difference<T: Debug + PartialEq>(
    label: &str,
    original: &[T],
    reimplementation: &[T],
) -> Option<String> {
    let count = original.len().max(reimplementation.len());
    (0..count).find_map(|index| {
        let left = original.get(index);
        let right = reimplementation.get(index);
        (left != right).then(|| format!("{label}[{index}]: C++ {left:?}, Rust {right:?}"))
    })
}

fn repository_root() -> Result<&'static Path, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .ok_or_else(|| "could not locate the repository root".to_owned())
}

fn artifact_path(stderr: &str) -> Option<PathBuf> {
    stderr.lines().rev().find_map(|line| {
        line.split_whitespace()
            .find_map(|field| field.strip_prefix("artifacts="))
            .filter(|value| *value != "none")
            .map(PathBuf::from)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_artifact_path_from_runtime_summary() {
        assert_eq!(
            artifact_path("runtime fixture: passed artifacts=/tmp/result failure=none\n"),
            Some(PathBuf::from("/tmp/result"))
        );
    }

    #[test]
    fn rejects_missing_artifact_path() {
        assert_eq!(
            artifact_path("runtime fixture: failed artifacts=none"),
            None
        );
    }

    #[test]
    fn parses_seed_and_specialist_command_in_either_order() {
        assert_eq!(
            parse_options(vec![
                "--specialist-recruit".into(),
                "6".into(),
                "24".into(),
                "1".into(),
                "--seed".into(),
                "7".into(),
            ]),
            Ok(DifferentialOptions {
                seed: 7,
                step: DifferentialStep::SpecialistRecruitment {
                    nation: 6,
                    unit_type: 24,
                    quantity: 1,
                },
            })
        );
    }

    #[test]
    fn rejects_an_incomplete_specialist_command() {
        assert_eq!(
            parse_options(vec!["--specialist-recruit".into(), "6".into(), "24".into(),]),
            Err("quantity is required".to_owned())
        );
    }
}
