//! Process-isolated differential helper: run a native scenario, apply the Rust
//! operation to the captured `before` state, and compare against `after`.

use anyhow::{Context, Result, bail};
use imperialism_core::GameState;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{first_serialized_difference, read_runtime_capture};

/// Run `scenario` under the native harness, apply `apply` to the captured
/// `before`/`case` pair, and require the resulting state to match `after`.
pub fn differential<T, F>(scenario: &str, apply: F) -> Result<()>
where
    T: DeserializeOwned,
    F: FnOnce(&mut GameState, T) -> Result<()>,
{
    let result = run_native_scenario(scenario)?;
    differential_from_result(&result, apply)
}

/// Same comparison as [`differential`], but against an already-written native result.
pub fn differential_from_result<T, F>(result: &Path, apply: F) -> Result<()>
where
    T: DeserializeOwned,
    F: FnOnce(&mut GameState, T) -> Result<()>,
{
    let mut actual: GameState = read_runtime_capture(result, "before")
        .with_context(|| format!("reading before from {}", result.display()))?;
    let case: T = read_runtime_capture(result, "case")
        .with_context(|| format!("reading case from {}", result.display()))?;
    let expected: GameState = read_runtime_capture(result, "after")
        .with_context(|| format!("reading after from {}", result.display()))?;

    apply(&mut actual, case)?;
    assert_game_state_eq(&expected, &actual)
}

pub fn assert_game_state_eq(expected: &GameState, actual: &GameState) -> Result<()> {
    match first_serialized_difference(expected, actual).context("comparing game states")? {
        None => Ok(()),
        Some(difference) => bail!(
            "{} differs: expected {:?}, actual {:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        ),
    }
}

fn run_native_scenario(scenario: &str) -> Result<PathBuf> {
    let repository = repository_root()?;
    let output = Command::new("just")
        .current_dir(repository.join("decomp"))
        .arg("runtime-run")
        .arg(scenario)
        .arg("--seed")
        .arg("1")
        .output()
        .context("launching the native runtime scenario")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!("native scenario {scenario} failed:\n{}", stderr.trim());
    }
    let artifact_dir =
        artifact_path(&stderr).context("native scenario did not report its artifact directory")?;
    Ok(artifact_dir.join("native-result.json"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_core::{
        DiplomacyGrant, MajorNationId, MilitaryUnitKind, MinorNationId,
        NationId, ProductionConstraint, RecruitKind, ResourceCost, ResourceKind, ResourceTable,
        SkillBand, TradePolicyScore, UnitCostProfile, UnitProductionOrder,
    };
    use serde::Deserialize;
    use std::path::PathBuf;

    #[derive(Debug, Deserialize)]
    struct NationCase {
        nation: MajorNationId,
    }

    #[derive(Debug, Deserialize)]
    struct SpecialistRecruitmentCase {
        nation: MajorNationId,
        unit_kind: MilitaryUnitKind,
        quantity: i16,
    }

    #[derive(Debug, Deserialize)]
    struct Purchase {
        resource: ResourceKind,
        amount: i16,
        price: i16,
    }

    #[derive(Debug, Deserialize)]
    struct MajorTradeSettlementCase {
        nation: MajorNationId,
        purchases: Vec<Purchase>,
    }

    #[derive(Debug, Deserialize)]
    struct DiplomacyGrantCase {
        nation: MajorNationId,
        target: NationId,
        amount: i32,
    }

    #[derive(Debug, Deserialize)]
    struct AidAllocationCase {
        nation: MajorNationId,
        minor_nation: MinorNationId,
        resource: ResourceKind,
        amount: i32,
    }

    #[derive(Debug, Deserialize)]
    struct DirectTransportCase {
        nation: MajorNationId,
        resource: ResourceKind,
        requested: i16,
    }

    #[derive(Debug, Deserialize)]
    struct PowerPlantUpgradeCase {
        nation: MajorNationId,
        enabled: bool,
    }

    #[derive(Debug, Deserialize)]
    struct TradePolicyStepCase {
        source: MajorNationId,
        target: NationId,
    }

    #[derive(Debug, Deserialize)]
    struct TradePolicySetCase {
        nation: MajorNationId,
        target: NationId,
        policy: TradePolicyScore,
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

    #[test]
    fn artifact_path_reads_the_trailing_artifacts_field() {
        let stderr = "progress\nstatus=passed artifacts=/tmp/run-1\n";
        assert_eq!(artifact_path(stderr), Some(PathBuf::from("/tmp/run-1")));
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn specialist_recruitment() {
        differential(
            "specialist_recruitment",
            |state, case: SpecialistRecruitmentCase| {
                let mut order = specialist_order(case.unit_kind, case.quantity);
                state.produce_specialist_recruits(case.nation, &mut order)?;
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn major_trade_settlement() {
        differential(
            "major_trade_settlement",
            |state, case: MajorTradeSettlementCase| {
                for purchase in case.purchases {
                    state.purchase_item(
                        case.nation,
                        purchase.resource,
                        purchase.amount,
                        purchase.price,
                    )?;
                }
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn purchased_items_phase() {
        differential("purchased_items_phase", |state, case: NationCase| {
            state.remember_trade_bids(case.nation)?;
            state.purchase_item(case.nation, ResourceKind::Fabric, 3, 7)?;
            state.purchase_item(case.nation, ResourceKind::Food, -30, 1)?;
            state.commit_purchased_items(case.nation)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn created_items_phase() {
        differential("created_items_phase", |state, case: NationCase| {
            state.add_created_items(case.nation)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn transported_items_phase() {
        differential("transported_items_phase", |state, case: NationCase| {
            state.settle_transported_items(case.nation)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn diplomacy_grant_entry() {
        differential(
            "diplomacy_grant_entry_updates_treasury",
            |state, case: DiplomacyGrantCase| {
                let accepted = state.set_diplomacy_grant(
                    case.nation,
                    case.target,
                    Some(DiplomacyGrant {
                        amount: case.amount,
                        recurring: false,
                    }),
                )?;
                anyhow::ensure!(accepted, "Rust rejected the diplomacy grant");
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn diplomacy_reset() {
        differential(
            "diplomacy_reset_preserves_recurring_grants",
            |state, case: NationCase| {
                state.reset_diplomacy_commitments(case.nation)?;
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn aid_allocation() {
        differential("aid_allocation", |state, case: AidAllocationCase| {
            state.add_aid_allocation(case.nation, case.minor_nation, case.resource, case.amount)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn direct_transport() {
        differential("direct_transport", |state, case: DirectTransportCase| {
            state.direct_transport(case.nation, case.resource, case.requested)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn rolling_stock() {
        differential("rolling_stock", |state, case: NationCase| {
            anyhow::ensure!(
                state.increase_rolling_stock(case.nation)?,
                "Rust could not increase rolling stock"
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn merchant_marine() {
        differential("merchant_marine", |state, case: NationCase| {
            anyhow::ensure!(
                state.increase_merchant_marine(case.nation)?,
                "Rust could not increase merchant marine"
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn power_plant_upgrade() {
        differential(
            "power_plant_upgrade",
            |state, case: PowerPlantUpgradeCase| {
                state.set_power_plant_upgrade(case.nation, case.enabled)?;
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn trade_policy_step() {
        differential("trade_policy_step", |state, case: TradePolicyStepCase| {
            state.decrement_trade_policy_score(case.source, case.target)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn trade_policy_set() {
        differential("trade_policy_set", |state, case: TradePolicySetCase| {
            state.set_trade_policy(case.nation, case.target, case.policy)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn trade_capacity_refresh() {
        differential("trade_capacity_refresh", |state, case: NationCase| {
            state.refresh_merchant_capacity(case.nation)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn recall_trade_bids() {
        differential("recall_trade_bids", |state, case: NationCase| {
            state.recall_trade_bids(case.nation)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn transport_need_allocation() {
        differential("transport_need_allocation", |state, case: NationCase| {
            state.allocate_transport_needs(case.nation)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[ignore = "requires the native C++ runtime oracle (just runtime-run)"]
    fn player_trade_phase_reset() {
        differential("player_trade_phase_reset", |state, case: NationCase| {
            state.reset_player_trade_phase(case.nation)?;
            Ok(())
        })
        .unwrap();
    }
}
