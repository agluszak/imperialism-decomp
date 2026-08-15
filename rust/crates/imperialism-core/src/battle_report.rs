//! Retail `MapContextActionRecord` / `BattleRecord` (`TArmyMgr.cpp` 0x004a13c0).

use crate::*;
use serde::{Deserialize, Serialize};

/// `MapContextReportKind` (`map_order_battle_snapshot.h`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(i32)]
#[serde(rename_all = "snake_case")]
pub enum BattleReportKind {
    LandBattle = 0,
    SeaBattle = 1,
    MerchantInterception = 2,
    PreemptedLandBattle = 3,
    UncontestedTakeover = 4,
}

impl BattleReportKind {
    pub const fn retail(self) -> i32 {
        self as i32
    }

    pub fn from_retail(value: i32) -> Option<Self> {
        Some(match value {
            0 => Self::LandBattle,
            1 => Self::SeaBattle,
            2 => Self::MerchantInterception,
            3 => Self::PreemptedLandBattle,
            4 => Self::UncontestedTakeover,
            _ => return None,
        })
    }

    pub const fn is_land(self) -> bool {
        matches!(
            self,
            Self::LandBattle | Self::PreemptedLandBattle | Self::UncontestedTakeover
        )
    }
}

/// Land reports store a province index; sea/interception reports store a zone.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BattleReportLocation {
    Province(ProvinceId),
    Zone(OceanZoneId),
}

/// `MapOrderBattleSideChildRecord` (0x2c). Aliased as the detailed battle-report row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BattleReportUnit {
    pub resource_type: i16,
    pub stock_or_required: i16,
    pub name: String,
    pub strength_bucket: i16,
    /// `kControlTagArmy` (`'army'`) for land rows; ship type identity for sea rows.
    pub detail_identity: u32,
}

/// One participating side of a `BattleRecord`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BattleReportSide {
    pub nation: NationId,
    pub name: String,
    pub overlay: String,
    pub children: Vec<BattleReportUnit>,
}

/// Authoritative combat/naval report. Marker fields are omitted from `.imp`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BattleReport {
    pub participant_index: u8,
    pub displayed_participant: u8,
    pub kind: BattleReportKind,
    pub location: BattleReportLocation,
    pub sides: [BattleReportSide; 2],
    #[serde(default)]
    pub marker_pixel_x: i32,
    #[serde(default)]
    pub marker_pixel_y: i32,
    #[serde(default)]
    pub placed: bool,
    #[serde(default)]
    pub marker_sprite: i16,
    #[serde(default)]
    pub list_ordinal: i16,
}

/// `'army'` (`IMPERIALISM_FOURCC('a','r','m','y')`) written to land detail rows.
pub const BATTLE_REPORT_ARMY_IDENTITY: u32 = 0x6172_6d79;

impl GameState {
    pub fn battle_reports(&self) -> &[BattleReport] {
        &self.battle_reports
    }

    pub fn battle_reports_pending(&self) -> bool {
        !self.battle_reports.is_empty()
    }

    pub(crate) fn append_battle_report(&mut self, report: BattleReport) {
        self.battle_reports.push(report);
    }

    /// `BuildArmyContextActionRecordsAndDispatchLabel` (0x004a2900).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn append_land_battle_report(
        &mut self,
        kind: BattleReportKind,
        province: ProvinceId,
        attacker: NationId,
        defender: NationId,
        attacker_units: &[MilitaryUnitId],
        defender_units: &[MilitaryUnitId],
        attacker_won: bool,
    ) {
        let attacker_side = self.land_report_side(attacker, attacker_units);
        let defender_side = self.land_report_side(defender, defender_units);
        self.append_battle_report(BattleReport {
            participant_index: u8::from(!attacker_won),
            displayed_participant: 0,
            kind,
            location: BattleReportLocation::Province(province),
            sides: [attacker_side, defender_side],
            marker_pixel_x: 0,
            marker_pixel_y: 0,
            placed: false,
            marker_sprite: 0,
            list_ordinal: 0,
        });
    }

    fn land_report_side(&self, nation: NationId, units: &[MilitaryUnitId]) -> BattleReportSide {
        let name = self
            .nation(nation)
            .map(|common| common.display_name.clone())
            .unwrap_or_default();
        let mut overlay = String::new();
        let mut children = Vec::new();
        for &id in units {
            let Some(index) = self.military_units.iter().position(|unit| unit.id() == id) else {
                continue;
            };
            let unit = &self.military_units[index];
            let mut stock = unit.strength();
            if stock == -86 {
                stock = 0;
            }
            if !overlay.is_empty() {
                overlay.push(' ');
            }
            overlay.push_str(unit.name());
            children.push(BattleReportUnit {
                resource_type: i16::from(unit.unit_type() as u8),
                stock_or_required: stock,
                name: unit.name().to_string(),
                strength_bucket: unit.experience() / 100,
                detail_identity: BATTLE_REPORT_ARMY_IDENTITY,
            });
        }
        BattleReportSide {
            nation,
            name,
            overlay,
            children,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    #[test]
    fn land_report_rows_follow_unit_strength_and_army_identity() {
        let mut state = game_state();
        let province = ProvinceId::new(3);
        let attacker = state.turn.active_nation;
        let defender = NationId::new(1);
        let id = MilitaryUnitId::new(1);
        state.military_units.push(MilitaryUnitState::new(
            id,
            attacker,
            MilitaryUnitKind::Regulars,
            Some(province),
            MilitaryOrder::idle([None; 3], [None; 3]),
            attacker,
            0,
            true,
            "1st Regulars".to_string(),
            0x1f4,
            0,
            150,
            0,
        ));
        state.append_land_battle_report(
            BattleReportKind::LandBattle,
            province,
            attacker,
            defender,
            &[id],
            &[],
            true,
        );
        assert!(state.battle_reports_pending());
        let report = &state.battle_reports[0];
        assert_eq!(report.kind, BattleReportKind::LandBattle);
        assert_eq!(report.participant_index, 0);
        assert_eq!(report.sides[0].children[0].name, "1st Regulars");
        assert_eq!(report.sides[0].children[0].strength_bucket, 1);
        assert_eq!(
            report.sides[0].children[0].detail_identity,
            BATTLE_REPORT_ARMY_IDENTITY
        );
        assert!(report.sides[1].children.is_empty());
    }
}
