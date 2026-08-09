//! Centralized semantic differential scenario contracts.

use imperialism_core::{GameState, MajorNationId, NationId, ResourceKind};
use serde::{Deserialize, Serialize};

use crate::{EvidenceKind, RuntimeResultExpectations};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DiffOpResult { Accepted, Rejected { reason: DiffRejectReason } }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffRejectReason { NotMajorNation }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScenarioMeta {
    pub name: &'static str,
    pub evidence_kind: EvidenceKind,
    pub required_captures: &'static [&'static str],
}
impl ScenarioMeta {
    pub const fn expectations(self) -> RuntimeResultExpectations<'static> {
        RuntimeResultExpectations { name: self.name, seed: Some(1), evidence_kind: self.evidence_kind, required_captures: self.required_captures }
    }
}

pub const MAJOR_TRADE_SETTLEMENT: ScenarioMeta = ScenarioMeta { name: "major_trade_settlement", evidence_kind: EvidenceKind::RetailFixtureOracle, required_captures: &["before", "case", "after", "result"] };
pub const MAJOR_TRADE_NOT_MAJOR: ScenarioMeta = ScenarioMeta { name: "major_trade_not_major", evidence_kind: EvidenceKind::RetailFixtureOracle, required_captures: &["before", "case", "after", "result"] };
pub const EASY_TURN_FROM_SAVE: ScenarioMeta = ScenarioMeta { name: "easy_turn_from_save", evidence_kind: EvidenceKind::RetailFixtureOracle, required_captures: &["before", "case", "after", "result"] };

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TradeSettlement { pub resource: ResourceKind, pub amount: i16, pub price: i16 }
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TradeCase { pub nation: NationId, pub settlements: Vec<TradeSettlement> }

pub fn apply_trade_case(state: &mut GameState, case: &TradeCase) -> DiffOpResult {
    let Some(nation) = MajorNationId::from_nation(case.nation) else { return DiffOpResult::Rejected { reason: DiffRejectReason::NotMajorNation }; };
    for settlement in &case.settlements { state.purchase_item(nation, settlement.resource, settlement.amount, settlement.price); }
    DiffOpResult::Accepted
}


/// Compare the semantic `before`/`case`/`after`/`result` envelope for a trade scenario.
pub fn compare_trade_from_result(path: &std::path::Path, meta: ScenarioMeta) -> anyhow::Result<()> {
    let runtime = crate::read_runtime_result(path, meta.expectations())?;
    let mut actual: GameState = runtime.capture("before")?;
    let case: TradeCase = runtime.capture("case")?;
    let expected: GameState = runtime.capture("after")?;
    let expected_result: DiffOpResult = runtime.capture("result")?;
    let actual_result = apply_trade_case(&mut actual, &case);
    anyhow::ensure!(actual_result == expected_result, "operation result differs: native {expected_result:?}, Rust {actual_result:?}");
    crate::assert_game_state_eq(&expected, &actual)
}

pub fn scenario_meta(name: &str) -> Option<ScenarioMeta> {
    [MAJOR_TRADE_SETTLEMENT, MAJOR_TRADE_NOT_MAJOR, EASY_TURN_FROM_SAVE].into_iter().find(|meta| meta.name == name)
}
