#![forbid(unsafe_code)]

//! Compatibility boundary for retail saves, scenarios, maps, resources, and asset imports.
//!
//! Retail format implementations decode into explicit retail DTOs before converting into
//! `imperialism-core` state. This crate intentionally contains no live game rules or Bevy types.

mod legacy_save;
mod legacy_stream;
mod retail_assets;
mod retail_fonts;
mod retail_resources;
mod runtime_capture;
mod ui_catalog;

pub use legacy_save::{
    LegacyAdmiral, LegacyArmyMission, LegacyAutoGreatPowerPrefix, LegacyAutoGreatPowerState,
    LegacyCityState, LegacyCityTask, LegacyCivilianUnit, LegacyCountryBase,
    LegacyDefenseMinisterState, LegacyFixedRecordList, LegacyForeignMinisterState, LegacyGameSetup,
    LegacyGameStateContext, LegacyGreatPowerMinisters, LegacyGreatPowerPostCity,
    LegacyGreatPowerPrefix, LegacyGreatPowerState, LegacyHelpState, LegacyInteriorMinisterState,
    LegacyMajorNationState, LegacyMapState, LegacyMfcArchiveState, LegacyMilitaryUnit,
    LegacyMinorState, LegacyMission, LegacyNavyMission, LegacyNavyState, LegacyOceanState,
    LegacyPopulationState, LegacyProvince, LegacySaveError, LegacySaveHeader, LegacySaveV62,
    LegacyShip, LegacySimulationPrefix, LegacyTaskForce, LegacyTerrainTile, LegacyTown, LegacyZone,
    parse_auto_great_power_prefix_at, parse_auto_great_power_record_at, parse_city_at,
    parse_country_base_at, parse_great_power_ministers_at, parse_great_power_post_city_at,
    parse_great_power_prefix_at, parse_great_power_record_at, parse_help_manager_at,
    parse_minor_record_at, parse_missions_at,
};
pub use legacy_stream::{LegacyStream, StreamError};
pub use retail_assets::{RetailAssetError, RetailAssets};
pub use retail_fonts::{
    ResolvedRetailTextStyle, RetailFontDecodeError, RetailFontFace, RetailFontMetrics,
    RetailGlyphBounds, RetailGlyphMetrics, RetailTextAlignment, RetailTextStyleError,
    RetailTextStylePreset, decode_retail_font_metrics, resolve_retail_text_style,
    retail_logical_font_height,
};
pub use runtime_capture::{RuntimeCaptureError, decode_runtime_capture, read_runtime_capture};
pub use ui_catalog::{
    FourCc, LogicalRect, ScopedViewId, UiCatalog, UiNode, UiNodeId, UiNumberRange, UiStyle,
    UiTextBinding, UiView, UiWindowColor, UiWindowProperties, WidgetKind, WidgetProperties,
};
