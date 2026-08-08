use crate::{CivilianUnitId, CivilianUnitKind, GameState, MajorNationTable, MapGeometry, TileId};

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
    #[error("civilian unit {} is not laying rail", .id.get())]
    NotLayingRail { id: CivilianUnitId },
    #[error("civilian unit {} has no map tile", .id.get())]
    MissingTile { id: CivilianUnitId },
    #[error("civilian unit {} has no rail source tile", .id.get())]
    MissingRailSource { id: CivilianUnitId },
    #[error(
        "civilian unit {} references tile {}, outside the world",
        .id.get(),
        .tile.get()
    )]
    InvalidTile { id: CivilianUnitId, tile: TileId },
    #[error(
        "civilian unit {} cannot lay rail from tile {} to non-adjacent tile {}",
        .id.get(),
        .origin.get(),
        .destination.get()
    )]
    NonAdjacentRailTiles {
        id: CivilianUnitId,
        origin: TileId,
        destination: TileId,
    },
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

    /// Advances one retail `LayRail` order by one turn.
    ///
    /// A completed rail section becomes a pair of permanent directional
    /// transport links. The pending rail links are placed when the order is
    /// issued and therefore remain unchanged here.
    pub fn advance_rail_construction(
        &mut self,
        civilian: CivilianUnitId,
    ) -> Result<(), CivilianWorkError> {
        let index = self
            .civilian_units
            .iter()
            .position(|unit| unit.id == civilian)
            .ok_or(CivilianWorkError::MissingCivilian { id: civilian })?;

        let (remaining_turns, source, destination) = {
            let unit = &self.civilian_units[index];
            if !matches!(unit.order, CivilianWorkOrder::LayRail) {
                return Err(CivilianWorkError::NotLayingRail { id: civilian });
            }
            (unit.remaining_turns, unit.order_target, unit.tile)
        };

        if remaining_turns > 1 {
            self.civilian_units[index].remaining_turns -= 1;
            return Ok(());
        }

        let source = source.ok_or(CivilianWorkError::MissingRailSource { id: civilian })?;
        let destination = destination.ok_or(CivilianWorkError::MissingTile { id: civilian })?;
        for tile in [source, destination] {
            if usize::from(tile.get()) >= self.world.tiles.len() {
                return Err(CivilianWorkError::InvalidTile { id: civilian, tile });
            }
        }
        let direction = MapGeometry::new(self.world.wraps_horizontally)
            .direction_to(source, destination)
            .ok_or(CivilianWorkError::NonAdjacentRailTiles {
                id: civilian,
                origin: source,
                destination,
            })?;

        self.civilian_units[index].remaining_turns -= 1;
        self.world.tiles[usize::from(source.get())]
            .transport_links
            .insert_direction(direction);
        self.world.tiles[usize::from(destination.get())]
            .transport_links
            .insert_direction(direction.opposite());
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
        Ok(())
    }
}
