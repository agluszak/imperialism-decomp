#![forbid(unsafe_code)]

use anyhow::{Context, anyhow, bail};
use imperialism_core::{
    GameCommand, NationId, ProductionConstraint, ResourceCost, ResourceKind, ResourceTable,
    SkillBand, UnitCostProfile, UnitProductionOrder,
};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use imperialism_testkit::{first_serialized_difference, read_game_state};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> anyhow::Result<()> {
    run()
}

fn run() -> anyhow::Result<()> {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_else(|| "differential".into());
    let fixture = required_argument(&program, arguments.next()).map_err(anyhow::Error::msg)?;
    let source = match required_argument(&program, arguments.next()).map_err(anyhow::Error::msg)? {
        flag if flag == "--legacy-save" => RustSource::LegacySave(
            required_argument(&program, arguments.next()).map_err(anyhow::Error::msg)?,
        ),
        capture => RustSource::Capture(capture),
    };
    let options = parse_options(arguments.collect()).map_err(anyhow::Error::msg)?;

    let repository = repository_root()?;
    let output = Command::new("just")
        .current_dir(repository.join("decomp"))
        .arg("runtime-run")
        .arg(&fixture)
        .arg("--seed")
        .arg(options.seed.to_string())
        .output()
        .context("launching the C++ oracle")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!(
            "C++ oracle fixture {} failed:\n{}",
            Path::new(&fixture).display(),
            stderr.trim()
        );
    }
    let artifact_dir =
        artifact_path(&stderr).context("C++ oracle did not report its artifact directory")?;
    let cpp_result_path = artifact_dir.join("native-result.json");
    let cpp_state = read_game_state(&cpp_result_path).with_context(|| {
        format!(
            "reading C++ oracle game state {}",
            cpp_result_path.display()
        )
    })?;
    let mut rust_state = match source {
        RustSource::Capture(path) => read_game_state(Path::new(&path))
            .with_context(|| format!("reading Rust game state {}", Path::new(&path).display()))?,
        RustSource::LegacySave(path) => {
            let bytes = fs::read(&path)
                .with_context(|| format!("reading retail save {}", Path::new(&path).display()))?;
            let save = LegacySaveV62::parse(&bytes).context("decoding retail save")?;
            save.game_state(LegacyGameStateContext {
                crt_rand_state: cpp_state.rng.crt_rand,
                map_generation_lcg: cpp_state.rng.map_generation,
                zone_status_lcg: cpp_state.rng.zone_status,
                selected_nation: cpp_state.turn.selected_nation,
            })
            .context("projecting retail save")?
        }
    };

    if !options.steps.is_empty() {
        let mut event_count = 0;
        for step in options.steps {
            match step {
                DifferentialStep::SpecialistRecruitment {
                    nation,
                    unit_type,
                    quantity,
                } => {
                    let mut order = specialist_order(unit_type, quantity);
                    let outcome = rust_state
                        .produce_specialist_recruits(NationId::new(nation), &mut order)
                        .context("Rust specialist recruitment failed")?;
                    event_count += outcome.events.len();
                }
                DifferentialStep::PurchaseItem {
                    nation,
                    resource,
                    amount,
                    price,
                } => {
                    let resource = resource_kind(resource)?;
                    let outcome = rust_state
                        .apply_command(GameCommand::PurchaseItem {
                            nation: NationId::new(nation),
                            resource,
                            amount,
                            price,
                        })
                        .context("Rust trade settlement failed")?;
                    event_count += outcome.events.len();
                }
                DifferentialStep::PlaceTradeBid {
                    nation,
                    resource,
                    amount,
                } => {
                    let resource = resource_kind(resource)?;
                    let outcome = rust_state
                        .apply_command(GameCommand::PlaceTradeBid {
                            nation: NationId::new(nation),
                            resource,
                            amount,
                        })
                        .context("Rust trade bid failed")?;
                    event_count += outcome.events.len();
                }
                DifferentialStep::RememberTradeBids { nation } => {
                    let outcome = rust_state
                        .remember_trade_bids(NationId::new(nation))
                        .context("Rust bid snapshot failed")?;
                    event_count += outcome.events.len();
                }
                DifferentialStep::CommitPurchasedItems { nation } => {
                    let outcome = rust_state
                        .commit_purchased_items(NationId::new(nation))
                        .context("Rust purchased-item commit failed")?;
                    event_count += outcome.events.len();
                }
            }
        }
        if let Some(difference) = first_serialized_difference(&cpp_state, &rust_state)
            .context("comparing post-command game states")?
        {
            bail!(
                "post-command state differs at {}: C++ {:?}, Rust {:?}",
                difference.path,
                difference.original,
                difference.reimplementation
            );
        }
        println!(
            "post-command GameState is identical ({} domain events)",
            event_count
        );
        return Ok(());
    }

    match first_serialized_difference(&cpp_state, &rust_state).context("comparing game states")? {
        None => {
            println!("semantic game states are identical");
            Ok(())
        }
        Some(difference) => bail!(
            "{} differs: C++ {:?}, Rust {:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        ),
    }
}

enum RustSource {
    Capture(OsString),
    LegacySave(OsString),
}

fn required_argument(program: &OsString, value: Option<OsString>) -> Result<OsString, String> {
    value.ok_or_else(|| {
        format!(
            "usage: {} FIXTURE RUNTIME_RESULT.json [--seed N]\n       {} FIXTURE --legacy-save SAVE.imp [--seed N] [COMMAND]...\ncommands: --specialist-recruit NATION UNIT_TYPE QUANTITY | --place-trade-bid NATION RESOURCE AMOUNT | --remember-trade-bids NATION | --purchase-item NATION RESOURCE AMOUNT PRICE | --commit-purchased-items NATION",
            Path::new(program).display(),
            Path::new(program).display()
        )
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DifferentialOptions {
    seed: u32,
    steps: Vec<DifferentialStep>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DifferentialStep {
    SpecialistRecruitment {
        nation: u8,
        unit_type: i16,
        quantity: i16,
    },
    PurchaseItem {
        nation: u8,
        resource: i16,
        amount: i16,
        price: i16,
    },
    PlaceTradeBid {
        nation: u8,
        resource: i16,
        amount: i16,
    },
    RememberTradeBids {
        nation: u8,
    },
    CommitPurchasedItems {
        nation: u8,
    },
}

fn parse_options(arguments: Vec<OsString>) -> Result<DifferentialOptions, String> {
    let mut options = DifferentialOptions {
        seed: 1,
        steps: Vec::new(),
    };
    let mut arguments = arguments.into_iter();
    while let Some(flag) = arguments.next() {
        if flag == "--seed" {
            options.seed = parse_number(arguments.next(), "--seed", "an unsigned integer")?;
        } else if flag == "--specialist-recruit" {
            options.steps.push(DifferentialStep::SpecialistRecruitment {
                nation: parse_number(arguments.next(), "nation", "an unsigned 8-bit integer")?,
                unit_type: parse_number(arguments.next(), "unit type", "a signed 16-bit integer")?,
                quantity: parse_number(arguments.next(), "quantity", "a signed 16-bit integer")?,
            });
        } else if flag == "--purchase-item" {
            options.steps.push(DifferentialStep::PurchaseItem {
                nation: parse_number(arguments.next(), "nation", "an unsigned 8-bit integer")?,
                resource: parse_number(
                    arguments.next(),
                    "resource kind",
                    "a signed 16-bit integer",
                )?,
                amount: parse_number(arguments.next(), "amount", "a signed 16-bit integer")?,
                price: parse_number(arguments.next(), "price", "a signed 16-bit integer")?,
            });
        } else if flag == "--place-trade-bid" {
            options.steps.push(DifferentialStep::PlaceTradeBid {
                nation: parse_number(arguments.next(), "nation", "an unsigned 8-bit integer")?,
                resource: parse_number(
                    arguments.next(),
                    "resource kind",
                    "a signed 16-bit integer",
                )?,
                amount: parse_number(arguments.next(), "amount", "a signed 16-bit integer")?,
            });
        } else if flag == "--remember-trade-bids" {
            options.steps.push(DifferentialStep::RememberTradeBids {
                nation: parse_number(arguments.next(), "nation", "an unsigned 8-bit integer")?,
            });
        } else if flag == "--commit-purchased-items" {
            options.steps.push(DifferentialStep::CommitPurchasedItems {
                nation: parse_number(arguments.next(), "nation", "an unsigned 8-bit integer")?,
            });
        } else {
            return Err(format!(
                "unexpected differential option {}",
                flag.to_string_lossy()
            ));
        }
    }
    Ok(options)
}

fn resource_kind(value: i16) -> anyhow::Result<ResourceKind> {
    ResourceKind::from_retail_index(value)
        .ok_or_else(|| anyhow!("resource kind {value} is out of range"))
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
        tracking_by_resource: ResourceTable::default(),
        reserved_workforce: 0,
        limiting_constraint: ProductionConstraint::Resources,
        accumulated_value: 0,
    }
}

fn repository_root() -> anyhow::Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .context("could not locate the repository root")
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
                steps: vec![DifferentialStep::SpecialistRecruitment {
                    nation: 6,
                    unit_type: 24,
                    quantity: 1,
                }],
            })
        );
    }

    #[test]
    fn parses_a_repeated_trade_command_trace() {
        assert_eq!(
            parse_options(vec![
                "--purchase-item".into(),
                "6".into(),
                "8".into(),
                "3".into(),
                "7".into(),
                "--purchase-item".into(),
                "6".into(),
                "13".into(),
                "-2".into(),
                "5".into(),
                "--purchase-item".into(),
                "6".into(),
                "8".into(),
                "-1".into(),
                "4".into(),
            ]),
            Ok(DifferentialOptions {
                seed: 1,
                steps: vec![
                    DifferentialStep::PurchaseItem {
                        nation: 6,
                        resource: 8,
                        amount: 3,
                        price: 7,
                    },
                    DifferentialStep::PurchaseItem {
                        nation: 6,
                        resource: 13,
                        amount: -2,
                        price: 5,
                    },
                    DifferentialStep::PurchaseItem {
                        nation: 6,
                        resource: 8,
                        amount: -1,
                        price: 4,
                    },
                ],
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

    #[test]
    fn parses_the_purchased_items_phase_trace() {
        assert_eq!(
            parse_options(vec![
                "--place-trade-bid".into(),
                "6".into(),
                "8".into(),
                "-1".into(),
                "--remember-trade-bids".into(),
                "6".into(),
                "--commit-purchased-items".into(),
                "6".into(),
            ]),
            Ok(DifferentialOptions {
                seed: 1,
                steps: vec![
                    DifferentialStep::PlaceTradeBid {
                        nation: 6,
                        resource: 8,
                        amount: -1,
                    },
                    DifferentialStep::RememberTradeBids { nation: 6 },
                    DifferentialStep::CommitPurchasedItems { nation: 6 },
                ],
            })
        );
    }
}
