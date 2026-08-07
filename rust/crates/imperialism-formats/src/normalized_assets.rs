use imperialism_core::{STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const ASSET_PACK_SCHEMA: &str = "imperialism.asset_pack.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Rgba8(pub [u8; 4]);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NormalizedAssetManifestV1 {
    pub schema: String,
    pub logical_resolution: [u32; 2],
    pub strategic_map: StrategicMapAssetManifest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StrategicMapAssetManifest {
    pub tile_size: [u32; 2],
    pub row_stride: u32,
    pub odd_row_offset: u32,
    pub terrain_palette: Vec<Rgba8>,
    pub nation_palette: Vec<Rgba8>,
    pub city_marker: Rgba8,
    pub army_marker: Rgba8,
    pub navy_marker: Rgba8,
    pub selection_marker: Rgba8,
}

#[derive(Debug, thiserror::Error)]
pub enum AssetManifestError {
    #[error("could not read normalized asset manifest: {0}")]
    Io(#[source] std::io::Error),
    #[error("could not decode normalized asset manifest: {0}")]
    Json(#[source] serde_json::Error),
    #[error("invalid normalized asset manifest: {0}")]
    Validation(String),
}

impl NormalizedAssetManifestV1 {
    pub fn validate(&self) -> Result<(), AssetManifestError> {
        if self.schema != ASSET_PACK_SCHEMA {
            return Err(AssetManifestError::Validation(format!(
                "unsupported schema {:?}",
                self.schema
            )));
        }
        let [logical_width, logical_height] = self.logical_resolution;
        if logical_width == 0 || logical_height == 0 {
            return Err(AssetManifestError::Validation(
                "logical resolution must be nonzero".to_owned(),
            ));
        }
        let map = &self.strategic_map;
        let [tile_width, tile_height] = map.tile_size;
        if tile_width < 4 || tile_height < 4 || tile_width % 2 != 0 || tile_height % 4 != 0 {
            return Err(AssetManifestError::Validation(
                "strategic-map tile dimensions must be even, at least 4px, and height must be divisible by four"
                    .to_owned(),
            ));
        }
        if map.row_stride == 0 || map.row_stride >= tile_height {
            return Err(AssetManifestError::Validation(
                "strategic-map row stride must be between zero and tile height".to_owned(),
            ));
        }
        if map.odd_row_offset >= tile_width {
            return Err(AssetManifestError::Validation(
                "strategic-map odd-row offset must be smaller than tile width".to_owned(),
            ));
        }
        if map.terrain_palette.len() < 8 {
            return Err(AssetManifestError::Validation(
                "terrain palette must contain the eight retail terrain classes".to_owned(),
            ));
        }
        if map.nation_palette.len() < 23 {
            return Err(AssetManifestError::Validation(
                "nation palette must contain all 23 retail nation slots".to_owned(),
            ));
        }
        let map_width = u32::from(STRATEGIC_MAP_WIDTH) * tile_width + map.odd_row_offset;
        let map_height = (u32::from(STRATEGIC_MAP_HEIGHT) - 1) * map.row_stride + tile_height;
        if map_width > logical_width || map_height > logical_height {
            return Err(AssetManifestError::Validation(format!(
                "strategic map is {map_width}x{map_height}, larger than the {logical_width}x{logical_height} logical canvas"
            )));
        }
        Ok(())
    }
}

pub fn read_normalized_asset_manifest(
    path: &Path,
) -> Result<NormalizedAssetManifestV1, AssetManifestError> {
    let bytes = fs::read(path).map_err(AssetManifestError::Io)?;
    let manifest = serde_json::from_slice::<NormalizedAssetManifestV1>(&bytes)
        .map_err(AssetManifestError::Json)?;
    manifest.validate()?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> NormalizedAssetManifestV1 {
        NormalizedAssetManifestV1 {
            schema: ASSET_PACK_SCHEMA.to_owned(),
            logical_resolution: [960, 540],
            strategic_map: StrategicMapAssetManifest {
                tile_size: [8, 8],
                row_stride: 6,
                odd_row_offset: 4,
                terrain_palette: vec![Rgba8([0, 0, 0, 255]); 8],
                nation_palette: vec![Rgba8([255, 255, 255, 255]); 23],
                city_marker: Rgba8([255, 255, 255, 255]),
                army_marker: Rgba8([255, 255, 255, 255]),
                navy_marker: Rgba8([255, 255, 255, 255]),
                selection_marker: Rgba8([255, 255, 255, 255]),
            },
        }
    }

    #[test]
    fn accepts_the_normalized_retail_map_contract() {
        manifest().validate().unwrap();
    }

    #[test]
    fn rejects_incomplete_nation_palettes() {
        let mut manifest = manifest();
        manifest.strategic_map.nation_palette.truncate(22);
        assert!(matches!(
            manifest.validate(),
            Err(AssetManifestError::Validation(_))
        ));
    }
}
