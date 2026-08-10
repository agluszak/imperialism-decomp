//! First-turn military work (`TSimMgr` phase 10).

use crate::*;

const HEATMAP_NEIGHBOR_DIFFUSION: f32 = 0.2;
const MILITARY_MAINTENANCE_MULTIPLIER: i32 = 25;
const FIRST_TURN_AI_COUNT: usize = 6;
const FIRST_TURN_MISSIONS_PER_AI: usize = 11;
const FIRST_TURN_DEFEND_MISSIONS_PER_AI: usize = 8;
const FIRST_TURN_CONTROL_ZONE_BY_AI: [u16; FIRST_TURN_AI_COUNT] = [22, 42, 26, 21, 8, 11];
const FIRST_PORT_ZONE_BY_MAJOR: [u16; MajorNationId::COUNT as usize] = [66, 65, 64, 63, 62, 61, 60];

/// The 24 four-byte rows at `g_abUniversityRequirementLevelById`.
const HEATMAP_REQUIREMENT_LEVELS: [u8; 96] = [
    1, 2, 3, 4, // Cotton
    1, 2, 3, 4, // Wool
    1, 2, 3, 4, // Timber
    0, 2, 4, 6, // Coal
    0, 2, 4, 6, // Iron
    1, 1, 1, 1, // Horses
    0, 2, 4, 6, // Oil
    0, 0, 0, 0, // Food
    0, 0, 0, 0, // Fabric
    0, 0, 0, 0, // Lumber
    0, 0, 0, 0, // Paper
    0, 0, 0, 0, // Steel
    0, 0, 0, 0, // Fuel
    0, 0, 0, 0, // Clothing
    0, 0, 0, 0, // Furniture
    0, 0, 0, 0, // Hardware
    0, 0, 0, 0, // Arms
    1, 2, 3, 4, // Grain
    1, 2, 3, 4, // Fruit
    1, 2, 3, 4, // Fish
    1, 2, 3, 4, // Livestock
    0, 1, 2, 3, // Gems
    0, 1, 2, 3, // Gold
    0, 0, 0, 0, // Unused retail row 23
];

/// The exact globals at `0x696df8..=0x696e23`, which retail reaches when it indexes the
/// requirement table with the whole packed development byte instead of one nibble.
const HEATMAP_PACKED_DEVELOPMENT_OVERFLOW: [u8; 44] = [
    0, 0, 0, 1, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 10, 0, 4, 0, 7, 0, 6,
    0, 8, 0, 0, 0, 9, 0, 5, 0, 1, 0, 2, 0,
];

#[derive(Clone, Copy, Debug)]
struct PlannedControlZoneResolution {
    mission_index: usize,
    port_zone: OceanZoneId,
}

#[derive(Debug)]
struct MilitaryPhasePlan {
    city_scores: ProvinceTable<i32>,
    control_zone_by_nation: MajorNationTable<Option<PlannedControlZoneResolution>>,
    human: MajorNationId,
}

impl GameState {
    /// Whether phase ten is the recovered Easy beginning-save military pass.
    pub(crate) fn supports_first_turn_military_phase(&self) -> bool {
        self.first_turn_military_plan().is_some()
    }

    /// Runs retail's first-turn heatmap, upkeep, movement, cleanup, and navy preparation.
    ///
    /// Phase advancement remains the turn driver's responsibility. The complete plan is
    /// validated before any authoritative state changes, so an unrecovered AI or navy branch
    /// cannot leave a partial military phase behind.
    pub(crate) fn run_first_turn_military_phase(&mut self) {
        let plan = self
            .first_turn_military_plan()
            .expect("first-turn military phase contains an unrecovered branch");

        // `TMapMgr::RecomputeTileStrategicScoreHeatmap` runs before nation work.
        for slot in 0..ProvinceId::COUNT {
            let province = ProvinceId::new(slot);
            self.provinces[province].set_city_score(plan.city_scores[province]);
        }

        // `TCountry::GrowMilitia` visits all 23 countries here. Economic turn one does not
        // satisfy its quarterly recruitment gate, so every call is a proven no-op.

        // Retail visits major slots 0 through 6 and performs these three calls per nation:
        // upkeep, advisory mission selection, then army movement.
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            self.pay_for_military(nation);

            // Preflight proves that AI advisory target population has no transient candidates,
            // no enemies, and no historical demand. The selector therefore queues nothing.
            if nation == plan.human {
                let transport = self.nations.majors[nation].economy.capacities.transport;
                self.nations.majors[nation].economy.army_movement_budget = i32::from(transport) / 5;
            } else {
                let resolution = plan.control_zone_by_nation[nation]
                    .expect("every first-turn AI has one control-sea-zone mission");
                let MissionData::ControlSeaZone(navy) =
                    &mut self.missions[resolution.mission_index].data
                else {
                    unreachable!("the preflight retained a control-sea-zone mission index");
                };
                navy.resolved_port_zone = Some(resolution.port_zone);
            }
        }

        // `TArmyMgr::CleanUpStacks` only clears transient map-order records in this slice.
        // `TNavyMgr::PrepareToCarryOutAllOrders(1)` then clears exploration bits. Empty ship
        // and task-force collections make the remaining preparation and execution calls no-ops.
        for slot in 0..ProvinceId::COUNT {
            self.provinces[ProvinceId::new(slot)].clear_explored_by_majors();
        }
    }

    fn first_turn_military_plan(&self) -> Option<MilitaryPhasePlan> {
        let human = MajorNationId::from_nation(self.turn.active_nation)?;
        if self.turn.phase != PhaseCode::MILITARY
            || self.turn.economic_turn != 1
            || self.turn.difficulty != Difficulty::Easy
            || self.turn.scenario_map.is_some()
            || self.turn.selected_nation != self.turn.active_nation
            || human.get() != FIRST_TURN_AI_COUNT as u8
            || self.world.topology() != MapTopology::Wrapping
            || !self.ships.is_empty()
            || !self.task_forces.is_empty()
            || self.port_zone_owners.len() != usize::from(NationId::COUNT)
            || NationId::all().any(|nation| {
                !matches!(
                    self.nations.common(nation),
                    Some(common) if common.status == CountryStatus::Independent
                ) || NationId::all().any(|target| {
                    self.diplomacy.relationships[nation][target] != DiplomaticRelationship::Peace
                })
            })
            || self.world.iter().any(|tile| {
                tile.development.extractive.get() > 3 || tile.development.surface.get() > 3
            })
        {
            return None;
        }

        for nation in NationId::all() {
            if self
                .port_zone_owners
                .iter()
                .filter(|entry| entry.former_owner == nation)
                .count()
                != 1
            {
                return None;
            }
        }
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            let expected_zone = OceanZoneId::new(FIRST_PORT_ZONE_BY_MAJOR[usize::from(slot)]);
            if !self
                .port_zone_owners
                .iter()
                .any(|entry| entry.former_owner == nation.nation() && entry.zone == expected_zone)
            {
                return None;
            }
        }

        let control_zone_by_nation = self.first_turn_control_zone_plan(human)?;
        let city_scores = self.first_turn_heatmap_plan()?;
        Some(MilitaryPhasePlan {
            city_scores,
            control_zone_by_nation,
            human,
        })
    }

    fn first_turn_control_zone_plan(
        &self,
        human: MajorNationId,
    ) -> Option<MajorNationTable<Option<PlannedControlZoneResolution>>> {
        if self.missions.len() != FIRST_TURN_AI_COUNT * FIRST_TURN_MISSIONS_PER_AI {
            return None;
        }

        let mut plan = MajorNationTable::default();
        for slot in 0..MajorNationId::COUNT {
            let nation = MajorNationId::new(slot);
            let major = &self.nations.majors[nation];
            if major.economy.controller.is_human() != (nation == human)
                || !self.first_turn_payment_is_safe(nation)
            {
                return None;
            }

            if nation == human {
                if major.economy.ai_province_targets.is_some()
                    || major.economy.ai_zone_targets.is_some()
                    || self
                        .missions
                        .iter()
                        .any(|mission| mission.nation == nation.nation())
                {
                    return None;
                }
                continue;
            }

            if NationId::all().any(|target| major.economy.candidate_nation_flags[target] != 0)
                || all_resources().any(|resource| {
                    major.economy.interior_civilian.historical_need_by_resource[resource] != 0
                })
            {
                return None;
            }

            let mission_start = usize::from(slot) * FIRST_TURN_MISSIONS_PER_AI;
            let mission_end = mission_start + FIRST_TURN_MISSIONS_PER_AI;
            if self.missions[mission_start..mission_end]
                .iter()
                .any(|mission| mission.nation != nation.nation())
            {
                return None;
            }

            let mut expected_province_targets = ProvinceTable::default();
            if major.common.owned_regions.len() != FIRST_TURN_DEFEND_MISSIONS_PER_AI {
                return None;
            }
            for offset in 0..FIRST_TURN_DEFEND_MISSIONS_PER_AI {
                let MissionData::DefendProvince { province, army } =
                    &self.missions[mission_start + offset].data
                else {
                    return None;
                };
                if *province != major.common.owned_regions[offset]
                    || !army.units.is_empty()
                    || expected_province_targets[*province] != AiTargetState::Unmarked
                {
                    return None;
                }
                expected_province_targets[*province] = AiTargetState::MissionQueued;
            }
            if major.economy.ai_province_targets.as_ref()? != &expected_province_targets {
                return None;
            }

            let control_mission_index = mission_start + FIRST_TURN_DEFEND_MISSIONS_PER_AI;
            let control_zone = OceanZoneId::new(FIRST_TURN_CONTROL_ZONE_BY_AI[usize::from(slot)]);
            let port_zone = OceanZoneId::new(FIRST_PORT_ZONE_BY_MAJOR[usize::from(slot)]);
            let MissionData::ControlSeaZone(control) = &self.missions[control_mission_index].data
            else {
                return None;
            };
            if control.target_zone != Some(control_zone)
                || control.resolved_port_zone.is_some()
                || !first_turn_navy_mission_has_no_orders(control)
            {
                return None;
            }

            let MissionData::Escort(escort) = &self.missions[control_mission_index + 1].data else {
                return None;
            };
            if escort.target_zone != Some(port_zone)
                || escort.resolved_port_zone != Some(port_zone)
                || !first_turn_navy_mission_has_no_orders(escort)
            {
                return None;
            }

            let MissionData::ScatteredShips(scattered) =
                &self.missions[control_mission_index + 2].data
            else {
                return None;
            };
            if scattered.target_zone.is_some()
                || scattered.resolved_port_zone.is_some()
                || !first_turn_navy_mission_has_no_orders(scattered)
            {
                return None;
            }

            let zone_targets = major.economy.ai_zone_targets.as_ref()?;
            let mut expected_zone_targets = vec![AiTargetState::Unmarked; zone_targets.len()];
            for zone in [control_zone, port_zone] {
                let target = expected_zone_targets.get_mut(usize::from(zone.get()))?;
                *target = AiTargetState::MissionQueued;
            }
            if zone_targets != &expected_zone_targets {
                return None;
            }

            plan[nation] = Some(PlannedControlZoneResolution {
                mission_index: control_mission_index,
                port_zone,
            });
        }
        Some(plan)
    }

    fn first_turn_payment_is_safe(&self, nation: MajorNationId) -> bool {
        let arms = self
            .military_units
            .iter()
            .filter(|unit| unit.nation == nation.nation())
            .try_fold(0_i32, |total, unit| {
                total.checked_add(unit.unit_type.arms_required())
            });
        arms.and_then(|arms| arms.checked_mul(MILITARY_MAINTENANCE_MULTIPLIER))
            .and_then(|charge| {
                self.nations.majors[nation]
                    .common
                    .treasury
                    .checked_sub(charge)
            })
            .is_some()
    }

    fn first_turn_heatmap_plan(&self) -> Option<ProvinceTable<i32>> {
        let mut weights = ResourceTable::<i32>::default();
        for commodity in crate::market::all_trade_commodities() {
            weights[commodity.resource()] = self.market.rows[commodity].base_price;
        }
        weights[ResourceKind::Gems] = 500;
        weights[ResourceKind::Gold] = 200;

        let mut base_scores = ProvinceTable::from_array([200_i32; PROVINCE_COUNT]);
        for tile in self.world.iter() {
            let Some(province) = tile.province else {
                continue;
            };
            let packed_development = usize::from(
                tile.development.extractive.get() << 4 | tile.development.surface.get(),
            );
            for &resource in tile.edge_resources.iter().flatten() {
                if resource == ResourceKind::Oil && !self.technology.oil_drilling_available {
                    continue;
                }
                let value = i32::from(heatmap_requirement_level(resource, packed_development));
                let contribution = value.checked_mul(weights[resource])?;
                base_scores[province] = base_scores[province].checked_add(contribution)?;
            }
        }

        for slot in 0..ProvinceId::COUNT {
            let province = ProvinceId::new(slot);
            let stage_bonus =
                (i32::from(self.provinces[province].development_stage()) + 3).checked_mul(1_000)?;
            base_scores[province] = base_scores[province].checked_add(stage_bonus)?;
        }

        for nation in NationId::all() {
            let common = self.nations.common(nation)?;
            let capital = common.home_tile?;
            let province = self.world[capital].province?;
            let bonus = if MajorNationId::from_nation(nation).is_some() {
                10_000
            } else {
                8_000
            };
            base_scores[province] = base_scores[province].checked_add(bonus)?;
        }

        let mut city_scores = ProvinceTable::default();
        for slot in 0..ProvinceId::COUNT {
            let province = ProvinceId::new(slot);
            let mut score = base_scores[province];
            for &adjacent in self.provinces[province].adjacency().iter().rev() {
                score = (base_scores[adjacent] as f32 * HEATMAP_NEIGHBOR_DIFFUSION + score as f32)
                    as i32;
            }
            city_scores[province] = score;
        }
        Some(city_scores)
    }
}

fn first_turn_navy_mission_has_no_orders(mission: &NavyMissionState) -> bool {
    mission.state == 0
        && mission.selected_ship.is_none()
        && mission.task_force.is_none()
        && mission.ships.is_empty()
}

fn heatmap_requirement_level(resource: ResourceKind, packed_development: usize) -> u8 {
    debug_assert!(packed_development >> 4 <= 3 && packed_development & 0x0f <= 3);
    let flat_index = resource as usize * 4 + packed_development;
    if flat_index < HEATMAP_REQUIREMENT_LEVELS.len() {
        HEATMAP_REQUIREMENT_LEVELS[flat_index]
    } else {
        HEATMAP_PACKED_DEVELOPMENT_OVERFLOW[flat_index - HEATMAP_REQUIREMENT_LEVELS.len()]
    }
}
