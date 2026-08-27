use crate::*;

/// One semantic operation from a retail `Scenario/sN.scn` startup script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScenarioInstruction {
    SetLabor {
        nation: MajorNationId,
        unskilled: i16,
        skilled: i16,
        professionals: i16,
    },
    SetProductionCapacity {
        nation: MajorNationId,
        slot: u16,
        value: i16,
    },
    SetStockpile {
        nation: MajorNationId,
        resource: ResourceKind,
        value: i16,
    },
    CreateArmy {
        province: ProvinceId,
        kind: MilitaryUnitKind,
        count: u32,
    },
    CreateCivilian {
        kind: CivilianUnitKind,
        tile: TileId,
    },
    CreateShips {
        nation: MajorNationId,
        kind: ShipType,
        zone: u16,
        count: u32,
    },
    SetTransportCapacity {
        nation: MajorNationId,
        value: i16,
    },
    SetDevelopment {
        tile: TileId,
        value: u8,
    },
    BuildDepot {
        tile: TileId,
    },
    BuildPort {
        tile: TileId,
    },
    UnlockTechnology {
        nation: MajorNationId,
        technology: Technology,
    },
    SetMarketPrice {
        commodity: TradeCommodity,
        value: i16,
    },
    SetMissionLevel {
        source: NationId,
        target: NationId,
        level: DiplomaticMissionLevel,
    },
    SetTradePolicy {
        owner: MajorNationId,
        target: NationId,
        score: TradePolicyScore,
    },
    SetTreaty {
        source: NationId,
        target: NationId,
        relationship: DiplomaticRelationship,
    },
    SetYear(i16),
    SetProvinceOwner {
        province: ProvinceId,
        nation: NationId,
    },
    SetZoneName {
        zone: u16,
        name: String,
    },
    SetCountryName {
        nation: NationId,
        name: String,
    },
    SetStanding {
        source: NationId,
        target: NationId,
        value: i16,
    },
    SetProvinceName {
        tile: TileId,
        name: String,
    },
    SetCash {
        nation: MajorNationId,
        value: i32,
    },
    SetFlag(u16),
    SetCapabilityTier {
        technology: Technology,
        value: i32,
    },
    SetNeedTarget {
        nation: MajorNationId,
        resource: ResourceKind,
        value: i16,
    },
    ClearNeedTargets {
        nation: MajorNationId,
    },
    SetCouncilState {
        decade: u8,
        state: u8,
    },
}

impl GameState {
    /// Applies the retail startup script before normal scenario turn flow begins.
    pub fn apply_scenario_script(&mut self, instructions: &[ScenarioInstruction]) {
        for instruction in instructions {
            self.apply_scenario_instruction(instruction);
        }
        for nation in MajorNationId::all() {
            self.name_land_units(nation.nation());
            self.nations.major_mut(nation).economy.scenario_initialized = true;
        }
    }

    fn apply_scenario_instruction(&mut self, instruction: &ScenarioInstruction) {
        match instruction {
            ScenarioInstruction::SetLabor {
                nation,
                unskilled,
                skilled,
                professionals,
            } => {
                self.nations.city_mut(*nation).population.set_population(
                    *unskilled,
                    *skilled,
                    *professionals,
                );
                self.rebuild_nation_resource_yields(*nation);
            }
            ScenarioInstruction::SetProductionCapacity {
                nation,
                slot,
                value,
            } => {
                let slot = CityFacilitySlot::from_index(*slot as u8)
                    .expect("scenario production-capacity slot");
                let city = self.nations.city_mut(*nation);
                let delta = value.wrapping_sub(city.production_orders[slot]);
                city.production_accum[slot] = city.production_accum[slot].wrapping_add(delta);
                city.production_orders[slot] = *value;
            }
            ScenarioInstruction::SetStockpile {
                nation,
                resource,
                value,
            } => {
                let stockpile = &mut self.nations.city_mut(*nation).stockpile;
                stockpile[*resource] = *value;
                stockpile.verify_stocks();
            }
            ScenarioInstruction::CreateArmy {
                province,
                kind,
                count,
            } => {
                let owner = self.map.provinces[*province]
                    .owner()
                    .expect("scenario army province has an owner");
                for _ in 0..*count {
                    self.insert_land_unit(owner, *kind, Some(*province), MilitaryOrderCode::Sleep);
                }
            }
            ScenarioInstruction::CreateCivilian { kind, tile } => {
                let owner = self.map[*tile]
                    .owner_nation
                    .and_then(TileOwnerTag::nation)
                    .expect("scenario civilian tile has a nation owner");
                let id = self.unit_ids.next_civilian();
                self.civilian_units.insert(
                    id,
                    CivilianUnitState {
                        nation: owner,
                        unit_type: *kind,
                        location: CivilianLocation::OnMap(*tile),
                        order: CivilianWorkOrder::Idle,
                        owner_nation: owner,
                        roster_id: 0,
                        registered: false,
                    },
                );
            }
            ScenarioInstruction::CreateShips {
                nation,
                kind,
                zone,
                count,
            } => {
                let city = self.nations.city_mut(*nation);
                city.ship_order_count_by_type[*kind] =
                    city.ship_order_count_by_type[*kind].wrapping_add(*count as i16);
                for _ in 0..*count {
                    self.insert_named_ship(ShipState {
                        ship_type: *kind,
                        location: OceanZoneId::new(*zone),
                        aggression: NavalAggression::Cautious,
                        nation: nation.nation(),
                        name: String::new(),
                        strength: crate::city::ship_stock_cap(*kind),
                        experience: 0,
                        selection: ShipSelection::Available,
                    });
                }
            }
            ScenarioInstruction::SetTransportCapacity { nation, value } => {
                self.nations.major_mut(*nation).economy.capacities.transport = *value;
            }
            ScenarioInstruction::SetDevelopment { tile, value } => {
                let state = &mut self.map[*tile];
                if state.edge_resources[0].is_some_and(|resource| {
                    matches!(
                        resource,
                        ResourceKind::Gold
                            | ResourceKind::Gems
                            | ResourceKind::Iron
                            | ResourceKind::Coal
                            | ResourceKind::Oil
                    )
                }) {
                    state.development.extractive = DevelopmentLevel::new(*value);
                } else {
                    state.development.surface = DevelopmentLevel::new(*value);
                }
                state.development.resource_visible_to_majors = MajorNationTable::from_fn(|_| true);
            }
            ScenarioInstruction::BuildDepot { tile } => {
                let nation = scenario_tile_major(&self.map, *tile);
                self.queue_depot_construction(*tile, nation, &mut Vec::new());
                if !self.nations.major(nation).economy.diplomacy_eligible {
                    self.nations.major_mut(nation).common.treasury += 2_000;
                }
            }
            ScenarioInstruction::BuildPort { tile } => {
                let nation = scenario_tile_major(&self.map, *tile);
                self.queue_port_construction(*tile, nation, &mut Vec::new());
                if !self.nations.major(nation).economy.diplomacy_eligible {
                    self.nations.major_mut(nation).common.treasury += 3_000;
                }
            }
            ScenarioInstruction::UnlockTechnology { nation, technology } => {
                self.apply_scenario_technology(*technology, *nation);
            }
            ScenarioInstruction::SetMarketPrice { commodity, value } => {
                self.market.rows[*commodity].price = i32::from(*value);
            }
            ScenarioInstruction::SetMissionLevel {
                source,
                target,
                level,
            } => {
                self.diplomacy.mission_levels[*source][*target] = *level;
                self.diplomacy.mission_levels[*target][*source] = *level;
            }
            ScenarioInstruction::SetTradePolicy {
                owner,
                target,
                score,
            } => {
                if owner.nation() != *target {
                    self.nations.major_mut(*owner).common.trade_policy_by_nation[*target] = *score;
                }
                if score.get() == 300 {
                    let _ = self.set_diplomacy_grant(*owner, *target, None);
                }
            }
            ScenarioInstruction::SetTreaty {
                source,
                target,
                relationship,
            } => {
                self.set_nation_pair_relationship(*source, *target, *relationship, false);
                if *relationship == DiplomaticRelationship::JoinedEmpire {
                    self.nations
                        .set_country_status(*target, CountryStatus::ColonyOf(*source));
                }
            }
            ScenarioInstruction::SetYear(year) => self.turn.economic_turn = i32::from(*year) * 4,
            ScenarioInstruction::SetProvinceOwner { province, nation } => {
                self.change_province_owner(*province, *nation);
            }
            ScenarioInstruction::SetZoneName { zone, name } => {
                let context = self
                    .ocean
                    .zones
                    .get_mut(usize::from(*zone))
                    .expect("scenario zone exists");
                match context {
                    ZoneKind::Zone(zone) => zone.display_name.clone_from(name),
                    ZoneKind::PortZone(port) => port.zone.display_name.clone_from(name),
                }
            }
            ScenarioInstruction::SetCountryName { nation, name } => self
                .nations
                .common_mut(*nation)
                .expect("scenario country exists")
                .display_name
                .clone_from(name),
            ScenarioInstruction::SetStanding {
                source,
                target,
                value,
            } => self.set_relationship(*source, *target, *value),
            ScenarioInstruction::SetProvinceName { tile, name } => {
                if let Some(province) = self.map[*tile].province {
                    self.map.provinces[province].name.clone_from(name);
                }
            }
            ScenarioInstruction::SetCash { nation, value } => {
                self.nations.major_mut(*nation).common.treasury = *value;
            }
            ScenarioInstruction::SetFlag(index) => self.turn.selected_asset_set = *index as i16,
            ScenarioInstruction::SetCapabilityTier { technology, value } => {
                self.technology.scheduled_unlock_turn_by_technology[*technology] =
                    value.wrapping_add(1).wrapping_mul(4) as i16;
            }
            ScenarioInstruction::SetNeedTarget {
                nation,
                resource,
                value,
            } => self.apply_scenario_need_target(*nation, *resource, *value),
            ScenarioInstruction::ClearNeedTargets { nation } => {
                self.rebuild_nation_resource_yields(*nation);
                for resource in crate::all_resources() {
                    self.nations
                        .major_mut(*nation)
                        .economy
                        .update_need_target(resource, 0);
                }
            }
            ScenarioInstruction::SetCouncilState { decade, state } => {
                self.turn.phase_state_by_decade[usize::from(*decade)] = *state;
                if *state == 2 {
                    self.turn.diplomacy_year_term_raw = i16::from(*decade) * 10 + 0x717;
                }
            }
        }
    }

    fn apply_scenario_need_target(
        &mut self,
        nation: MajorNationId,
        resource: ResourceKind,
        mut value: i16,
    ) {
        let current = self.nations.major(nation).economy.need_current_by_type[resource];
        if current < value {
            self.rebuild_nation_resource_yields(nation);
        }
        if matches!(resource, ResourceKind::Cotton | ResourceKind::Livestock) {
            let mapped = if resource == ResourceKind::Cotton {
                ResourceKind::Wool
            } else {
                ResourceKind::Fish
            };
            if current < value {
                self.nations
                    .major_mut(nation)
                    .economy
                    .update_need_target(mapped, value - current);
                value = current;
            }
        }
        self.nations
            .major_mut(nation)
            .economy
            .update_need_target(resource, value);
    }
}

fn scenario_tile_major(map: &MapMgr, tile: TileId) -> MajorNationId {
    map[tile]
        .owner_nation
        .and_then(TileOwnerTag::nation)
        .and_then(MajorNationId::from_nation)
        .expect("scenario construction tile belongs to a major nation")
}
