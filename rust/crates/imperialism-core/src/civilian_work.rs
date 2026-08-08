use crate::{CivilianUnitId, CivilianUnitKind, GameState, MajorNationTable, TileId};

/// A recovered civilian work-order kind.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CivilianWorkOrder {
    Idle,
    Redeploy,
    Sleep,
    LayRail,
    BuildDepot,
    BuildPort,
    Prospect,
    DevelopResource,
    BuildFort,
    PurchaseLand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CivilianWorkError {
    #[error("civilian unit {} is not present", .id.get())]
    MissingCivilian { id: CivilianUnitId },
    #[error("civilian unit {} is not developing a resource", .id.get())]
    NotDevelopingResource { id: CivilianUnitId },
    #[error("civilian unit {} has no map tile", .id.get())]
    MissingTile { id: CivilianUnitId },
    #[error(
        "civilian unit {} is on tile {}, outside the world",
        .id.get(),
        .tile.get()
    )]
    InvalidTile { id: CivilianUnitId, tile: TileId },
}

impl GameState {
    /// Advances one retail `DevelopResource` order by one turn.
    ///
    /// This is the `TCivUnit::ContinueOrders` final-tick transition for
    /// resource development only. Depot and port completion require map state
    /// that is not represented here and are intentionally separate operations.
    pub fn advance_resource_development(
        &mut self,
        civilian: CivilianUnitId,
    ) -> Result<(), CivilianWorkError> {
        let index = self
            .civilian_units
            .iter()
            .position(|unit| unit.id == civilian)
            .ok_or(CivilianWorkError::MissingCivilian { id: civilian })?;

        let (tile, uses_extractive_development) = {
            let unit = &self.civilian_units[index];
            if !matches!(unit.order, CivilianWorkOrder::DevelopResource) {
                return Err(CivilianWorkError::NotDevelopingResource { id: civilian });
            }
            (
                unit.tile
                    .ok_or(CivilianWorkError::MissingTile { id: civilian })?,
                matches!(
                    unit.unit_type,
                    CivilianUnitKind::Miner | CivilianUnitKind::Driller
                ),
            )
        };
        let tile_index = usize::from(tile.get());
        if tile_index >= self.world.tiles.len() {
            return Err(CivilianWorkError::InvalidTile { id: civilian, tile });
        }

        let unit = &mut self.civilian_units[index];
        unit.remaining_turns -= 1;
        let completes = unit.remaining_turns < 1;

        if !completes {
            return Ok(());
        }

        let tile_state = &mut self.world.tiles[tile_index];
        if uses_extractive_development {
            tile_state.development.extractive.advance();
            tile_state.development.resource_visible_to_majors = MajorNationTable::from_fn(|_| true);
        } else {
            tile_state.development.surface.advance();
        }
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
        Ok(())
    }
}
