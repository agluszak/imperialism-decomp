#![forbid(unsafe_code)]

//! Compatibility boundary for retail saves, maps, resources, and direct asset access.
//!
//! Retail format implementations keep binary-layout DTOs private and project into
//! `imperialism-core` state. This crate intentionally contains no live game rules or Bevy types.

mod color;
mod legacy_save;
mod legacy_stream;
mod retail_assets;
mod retail_fonts;
mod retail_resources;
mod ui_catalog;

pub use color::{DibPalette, PaletteIndex, Rgb};
pub use legacy_save::{LegacyGameStateContext, LegacySaveError, LegacySaveV62};
pub use retail_assets::{RetailAssetError, RetailAssets};
pub use retail_fonts::{
    ResolvedRetailTextStyle, RetailFontFace, RetailTextAlignment, RetailTextStyleError,
    RetailTextStylePreset, resolve_retail_text_style,
};
pub use ui_catalog::{
    FourCc, LogicalRect, ScopedViewId, UiBehavior, UiCatalog, UiNode, UiNodeId, UiNumberRange,
    UiStyle, UiTextBinding, UiView, UiViewIndex, UiWindowColor, UiWindowProperties, WidgetKind,
    WidgetProperties,
};
