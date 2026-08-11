use crate::{CivilianUnitId, CivilianUnitKind, GameState, HexDirection, MajorNationTable, TileId};

/// A recovered civilian work-order kind.
#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CivilianWorkOrder {
    Idle,
    Redeploy {
        destination: TileId,
        turns: TurnsRemaining,
    },
    Sleep,
    LayRail {
        segment: RailSegment,
        turns: TurnsRemaining,
    },
    BuildDepot {
        turns: TurnsRemaining,
    },
    BuildPort {
        turns: TurnsRemaining,
    },
    Prospect {
        turns: TurnsRemaining,
    },
    DevelopResource {
        turns: TurnsRemaining,
    },
    BuildFort {
        turns: TurnsRemaining,
    },
    PurchaseLand {
        turns: TurnsRemaining,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(transparent)]
pub struct TurnsRemaining(i16);

impl<'de> serde::Deserialize<'de> for TurnsRemaining {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <i16 as serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(value).ok_or_else(|| {
            serde::de::Error::custom("civilian work orders require a positive turn count")
        })
    }
}
impl TurnsRemaining {
    pub const fn try_new(value: i16) -> Option<Self> {
        if value > 0 { Some(Self(value)) } else { None }
    }
    fn advance(&mut self) -> bool {
        self.0 -= 1;
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RailSegment {
    origin: TileId,
    destination: TileId,
    direction: HexDirection,
}

impl<'de> serde::Deserialize<'de> for RailSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct SerializedRailSegment {
            origin: TileId,
            destination: TileId,
            direction: HexDirection,
        }

        let segment = SerializedRailSegment::deserialize(deserializer)?;
        let valid = Self::between(
            crate::MapTopology::Wrapping,
            segment.origin,
            segment.destination,
        )
        .is_some_and(|valid| valid.direction == segment.direction);
        valid
            .then_some(Self {
                origin: segment.origin,
                destination: segment.destination,
                direction: segment.direction,
            })
            .ok_or_else(|| serde::de::Error::custom("rail segment is not an adjacent direction"))
    }
}
impl RailSegment {
    pub fn between(
        topology: crate::MapTopology,
        origin: TileId,
        destination: TileId,
    ) -> Option<Self> {
        let direction = crate::MapGeometry::new(topology).direction_to(origin, destination)?;
        Some(Self {
            origin,
            destination,
            direction,
        })
    }
    pub const fn origin(self) -> TileId {
        self.origin
    }
    pub const fn destination(self) -> TileId {
        self.destination
    }
    pub const fn direction(self) -> HexDirection {
        self.direction
    }
}

impl GameState {
    pub fn advance_civilian_work(&mut self, civilian: CivilianUnitId) {
        let index = self
            .civilian_units
            .iter()
            .position(|unit| unit.id == civilian)
            .expect("scheduled civilian work references a present unit");
        #[allow(clippy::collapsible_match)] // match-guard form cannot mutably borrow `turns`
        match &mut self.civilian_units[index].order {
            #[allow(clippy::collapsible_match)]
            CivilianWorkOrder::DevelopResource { turns } => {
                if turns.advance() {
                    self.complete_resource_development(index);
                }
            }
            CivilianWorkOrder::LayRail { segment, turns } => {
                let segment = *segment;
                if turns.advance() {
                    self.complete_rail_construction(index, segment);
                }
            }
            _ => {}
        }
    }

    fn complete_resource_development(&mut self, index: usize) {
        let unit = &self.civilian_units[index];
        let tile = unit
            .location
            .tile()
            .expect("development orders are normalized with an on-map location");
        let uses_extractive_development = matches!(
            unit.unit_type,
            CivilianUnitKind::Miner | CivilianUnitKind::Driller
        );

        let tile_state = &mut self.map[tile];
        if uses_extractive_development {
            tile_state.development.extractive.advance();
            tile_state.development.resource_visible_to_majors = MajorNationTable::from_fn(|_| true);
        } else {
            tile_state.development.surface.advance();
        }
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }

    /// Completes one retail `LayRail` order.
    ///
    /// A completed rail section becomes a pair of permanent directional
    /// transport links. The pending rail links are placed when the order is
    /// issued and therefore remain unchanged here.
    fn complete_rail_construction(&mut self, index: usize, segment: RailSegment) {
        let source = segment.origin();
        let destination = segment.destination();
        let direction = segment.direction();
        self.map[source].transport_links.insert_direction(direction);
        self.map[destination]
            .transport_links
            .insert_direction(direction.opposite());
        self.civilian_units[index].order = CivilianWorkOrder::Idle;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MapTopology;

    #[test]
    fn rail_segment_deserialization_requires_its_stored_direction() {
        let segment =
            RailSegment::between(MapTopology::Wrapping, TileId::new(0), TileId::new(1)).unwrap();
        let mut serialized = serde_json::to_value(segment).unwrap();
        serialized["direction"] = serde_json::json!("West");

        assert!(serde_json::from_value::<RailSegment>(serialized).is_err());
    }

    #[test]
    fn rail_segment_deserialization_accepts_bounded_and_wrapping_neighbors() {
        let bounded =
            RailSegment::between(MapTopology::Bounded, TileId::new(0), TileId::new(1)).unwrap();
        let wrapping =
            RailSegment::between(MapTopology::Wrapping, TileId::new(0), TileId::new(107)).unwrap();

        assert_eq!(
            serde_json::from_value::<RailSegment>(serde_json::to_value(bounded).unwrap()).unwrap(),
            bounded
        );
        assert_eq!(
            serde_json::from_value::<RailSegment>(serde_json::to_value(wrapping).unwrap()).unwrap(),
            wrapping
        );
    }
}
