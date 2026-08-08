#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};
use clap::{ArgAction, ArgGroup, Parser, Subcommand};
use imperialism_core::{
    DiplomacyGrant, DiplomacyGrantFlags, GameState, MajorNationId, MilitaryUnitKind, NationId,
    ProductionConstraint, RecruitKind, ResourceCost, ResourceKind, ResourceTable, SkillBand,
    UnitCostProfile, UnitProductionOrder,
};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use imperialism_testkit::{first_serialized_difference, read_game_state, read_runtime_capture};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Parser)]
#[command(
    about = "Compare one semantic core operation with a native game-state capture",
    group(ArgGroup::new("state_source")
        .args(["runtime_result", "legacy_save", "input_capture"])
        .required(true)
        .multiple(false))
)]
struct Options {
    fixture: String,

    #[arg(value_name = "RUNTIME_RESULT")]
    runtime_result: Option<PathBuf>,

    #[arg(long, value_name = "SAVE")]
    legacy_save: Option<PathBuf>,

    /// Named GameState capture from the native result, used as the Rust pre-state.
    #[arg(long, value_name = "CAPTURE")]
    input_capture: Option<String>,

    #[arg(long, default_value_t = 1)]
    seed: u32,

    #[command(subcommand)]
    operation: Option<Operation>,
}

#[derive(Debug, Subcommand)]
enum Operation {
    SpecialistRecruit {
        #[arg(value_parser = parse_nation)]
        nation: NationId,
        #[arg(value_parser = parse_military_unit_kind)]
        unit_kind: MilitaryUnitKind,
        quantity: i16,
    },
    PurchaseItem {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
        #[arg(value_parser = parse_resource_kind)]
        resource: ResourceKind,
        amount: i16,
        price: i16,
    },
    PlaceTradeBid {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
        #[arg(value_parser = parse_resource_kind)]
        resource: ResourceKind,
        amount: i16,
    },
    RememberTradeBids {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
    },
    CommitPurchasedItems {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
    },
    SettleTransportedItems {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
    },
    AddCreatedItems {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
    },
    SetPowerPlantUpgrade {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
        #[arg(action = ArgAction::Set)]
        enabled: bool,
    },
    DirectTransport {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
        #[arg(value_parser = parse_resource_kind)]
        resource: ResourceKind,
        requested: i16,
    },
    AllocateTransportNeeds {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
    },
    RefreshTradeCapacity {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
    },
    RecallTradeBids {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
    },
    IncreaseRollingStock {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
    },
    DecrementTradePolicyScore {
        #[arg(value_parser = parse_major_nation)]
        source: MajorNationId,
        #[arg(value_parser = parse_nation)]
        target: NationId,
    },
    SetDiplomacyGrant {
        #[arg(value_parser = parse_major_nation)]
        nation: MajorNationId,
        #[arg(value_parser = parse_nation)]
        target: NationId,
        amount: i32,
    },
}

fn main() -> Result<()> {
    run(Options::parse())
}

fn run(options: Options) -> Result<()> {
    let repository = repository_root()?;
    let output = Command::new("just")
        .current_dir(repository.join("decomp"))
        .arg("runtime-run")
        .arg(&options.fixture)
        .arg("--seed")
        .arg(options.seed.to_string())
        .output()
        .context("launching the C++ oracle")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!(
            "C++ oracle fixture {} failed:\n{}",
            options.fixture,
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
    let mut rust_state = match (
        options.runtime_result.as_ref(),
        options.legacy_save.as_ref(),
        options.input_capture.as_deref(),
    ) {
        (Some(path), None, None) => read_game_state(path)
            .with_context(|| format!("reading Rust game state {}", path.display()))?,
        (None, Some(path), None) => {
            let bytes = fs::read(path)
                .with_context(|| format!("reading retail save {}", path.display()))?;
            let save = LegacySaveV62::parse(&bytes).context("decoding retail save")?;
            save.game_state(LegacyGameStateContext {
                crt_rand_state: cpp_state.rng.crt_rand,
                map_generation_lcg: cpp_state.rng.map_generation,
                zone_status_lcg: cpp_state.rng.zone_status,
                selected_nation: cpp_state.turn.selected_nation,
            })
            .context("projecting retail save")?
        }
        (None, None, Some(capture)) => read_runtime_capture(&cpp_result_path, capture)
            .with_context(|| format!("reading native {capture} capture"))?,
        _ => unreachable!("Clap enforces exactly one Rust-state source"),
    };

    if let Some(operation) = options.operation {
        apply_operation(&mut rust_state, operation)?;
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

fn apply_operation(state: &mut GameState, operation: Operation) -> Result<()> {
    match operation {
        Operation::SpecialistRecruit {
            nation,
            unit_kind,
            quantity,
        } => {
            let mut order = specialist_order(unit_kind, quantity);
            state
                .produce_specialist_recruits(nation, &mut order)
                .context("Rust specialist recruitment failed")?;
        }
        Operation::PurchaseItem {
            nation,
            resource,
            amount,
            price,
        } => {
            state
                .purchase_item(nation, resource, amount, price)
                .context("Rust trade settlement failed")?;
        }
        Operation::PlaceTradeBid {
            nation,
            resource,
            amount,
        } => {
            state
                .place_trade_bid(nation, resource, amount)
                .context("Rust trade bid failed")?;
        }
        Operation::RememberTradeBids { nation } => {
            state
                .remember_trade_bids(nation)
                .context("Rust bid snapshot failed")?;
        }
        Operation::CommitPurchasedItems { nation } => {
            state
                .commit_purchased_items(nation)
                .context("Rust purchased-item commit failed")?;
        }
        Operation::SettleTransportedItems { nation } => {
            state
                .settle_transported_items(nation)
                .context("Rust transported-item settlement failed")?;
        }
        Operation::AddCreatedItems { nation } => {
            state
                .add_created_items(nation)
                .context("Rust created-item settlement failed")?;
        }
        Operation::SetPowerPlantUpgrade { nation, enabled } => {
            state
                .set_power_plant_upgrade(nation, enabled)
                .context("Rust power-plant upgrade change failed")?;
        }
        Operation::DirectTransport {
            nation,
            resource,
            requested,
        } => {
            state
                .direct_transport(nation, resource, requested)
                .context("Rust direct transport failed")?;
        }
        Operation::AllocateTransportNeeds { nation } => {
            state
                .allocate_transport_needs(nation)
                .context("Rust transport-need allocation failed")?;
        }
        Operation::RefreshTradeCapacity { nation } => {
            state
                .refresh_trade_capacity(nation)
                .context("Rust trade-capacity refresh failed")?;
        }
        Operation::RecallTradeBids { nation } => {
            state
                .recall_trade_bids(nation)
                .context("Rust trade-bid recall failed")?;
        }
        Operation::IncreaseRollingStock { nation } => {
            if !state
                .increase_rolling_stock(nation)
                .context("Rust rolling-stock increase failed")?
            {
                bail!("Rust could not increase rolling stock");
            }
        }
        Operation::DecrementTradePolicyScore { source, target } => {
            state
                .decrement_trade_policy_score(source, target)
                .context("Rust trade-policy update failed")?;
        }
        Operation::SetDiplomacyGrant {
            nation,
            target,
            amount,
        } => {
            if !state
                .set_diplomacy_grant(
                    nation,
                    target,
                    Some(DiplomacyGrant {
                        amount,
                        flags: DiplomacyGrantFlags::empty(),
                    }),
                )
                .context("Rust diplomacy grant failed")?
            {
                bail!("Rust rejected the diplomacy grant");
            }
        }
    }
    Ok(())
}

fn parse_nation(value: &str) -> Result<NationId, String> {
    let index = value
        .parse()
        .map_err(|_| format!("{value:?} is not a nation ID"))?;
    NationId::try_new(index).ok_or_else(|| format!("nation ID {index} is out of range"))
}

fn parse_major_nation(value: &str) -> Result<MajorNationId, String> {
    let index = value
        .parse()
        .map_err(|_| format!("{value:?} is not a major-nation ID"))?;
    MajorNationId::try_new(index).ok_or_else(|| format!("major-nation ID {index} is out of range"))
}

fn parse_resource_kind(value: &str) -> Result<ResourceKind, String> {
    let index = value
        .parse()
        .map_err(|_| format!("{value:?} is not a resource kind"))?;
    ResourceKind::from_index(index).ok_or_else(|| format!("resource kind {index} is out of range"))
}

fn parse_military_unit_kind(value: &str) -> Result<MilitaryUnitKind, String> {
    let index = value
        .parse()
        .map_err(|_| format!("{value:?} is not a military unit kind"))?;
    MilitaryUnitKind::from_index(index)
        .ok_or_else(|| format!("military unit kind {index} is out of range"))
}

fn specialist_order(unit_kind: MilitaryUnitKind, quantity: i16) -> UnitProductionOrder {
    UnitProductionOrder {
        profile: UnitCostProfile {
            recruit_kind: RecruitKind::Military(unit_kind),
            primary: ResourceCost {
                resource: ResourceKind::Arms,
                per_unit: 0,
            },
            secondary: None,
            cash_per_unit: 0,
            workforce: Some(SkillBand::High),
        },
        quantity,
        tracking_by_resource: ResourceTable::default(),
        reserved_workforce: 0,
        limiting_constraint: ProductionConstraint::Resources,
        accumulated_value: 0,
    }
}

fn repository_root() -> Result<&'static Path> {
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
