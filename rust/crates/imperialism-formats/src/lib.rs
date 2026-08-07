#![forbid(unsafe_code)]

//! Compatibility boundary for retail saves, scenarios, maps, resources, and asset imports.
//!
//! Format implementations will decode into versioned legacy DTOs before converting into
//! `imperialism-core` state. This crate intentionally contains no live game rules or Bevy types.

mod legacy_save;
mod legacy_stream;

pub use legacy_save::{
    LegacyAdmiral, LegacyArmyMission, LegacyAutoGreatPowerPrefix, LegacyAutoGreatPowerState,
    LegacyCityState, LegacyCityTask, LegacyCivilianUnit, LegacyCountryBase,
    LegacyDefenseMinisterState, LegacyFixedRecordList, LegacyForeignMinisterState, LegacyGameSetup,
    LegacyGreatPowerMinisters, LegacyGreatPowerPostCity, LegacyGreatPowerPrefix,
    LegacyGreatPowerState, LegacyHelpState, LegacyInteriorMinisterState, LegacyMajorNationState,
    LegacyMapState, LegacyMfcArchiveState, LegacyMilitaryUnit, LegacyMinorState, LegacyMission,
    LegacyNavyMission, LegacyNavyState, LegacyOceanState, LegacyPopulationState, LegacyProvince,
    LegacySaveError, LegacySaveHeader, LegacySaveV62, LegacyShip, LegacySimulationPrefix,
    LegacySnapshotContext, LegacyTaskForce, LegacyTerrainTile, LegacyTown, LegacyZone,
    parse_auto_great_power_prefix_at, parse_auto_great_power_record_at, parse_city_at,
    parse_country_base_at, parse_great_power_ministers_at, parse_great_power_post_city_at,
    parse_great_power_prefix_at, parse_great_power_record_at, parse_help_manager_at,
    parse_minor_record_at, parse_missions_at,
};
pub use legacy_stream::{LegacyStream, StreamError};
