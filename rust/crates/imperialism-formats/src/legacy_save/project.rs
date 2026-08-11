use super::PROVINCE_COUNT;
use super::errors::*;
use super::model::*;
use super::normalize::*;
use super::*;
use imperialism_core::*;

impl LegacyCountryBase {
    pub(super) fn military_unit_states(
        &self,
        nation: NationId,
    ) -> Result<Vec<MilitaryUnitState>, LegacySaveError> {
        self.military_units
            .iter()
            .map(|unit| {
                let unit_type = u8::try_from(unit.unit_type)
                    .ok()
                    .and_then(MilitaryUnitKind::from_index)
                    .ok_or_else(|| {
                        LegacySaveError::StateProjection(format!(
                            "invalid military unit type {}",
                            unit.unit_type
                        ))
                    })?;
                let targets = optional_province_array(unit.order_target_tiles)?;
                let target_mirrors = optional_province_array(unit.order_target_mirrors)?;
                let target = optional_province_id(unit.order_target)?;
                let order = if unit.order == 0 && target.is_none() {
                    MilitaryOrder::idle(targets, target_mirrors)
                } else {
                    MilitaryOrder::retail(
                        MilitaryOrderCode::from_retail(unit.order),
                        target,
                        targets,
                        target_mirrors,
                    )
                };
                Ok(MilitaryUnitState::new(
                    MilitaryUnitId::from_serialized(unit.persistent_id),
                    nation,
                    unit_type,
                    optional_province_id(unit.stationed_province)?,
                    order,
                    nation_id_from_retail_i16(unit.owner_nation)?,
                    unit.roster_id,
                    unit.registered != 0,
                    unit.name.clone(),
                    unit.strength,
                    unit.era,
                    unit.experience,
                    unit.battle_flags,
                ))
            })
            .collect()
    }
}

impl LegacyGreatPowerPostCity {
    fn civilian_unit_states(
        &self,
        nation: NationId,
        topology: MapTopology,
    ) -> Result<Vec<CivilianUnitState>, LegacySaveError> {
        self.civilian_units
            .iter()
            .map(|unit| {
                let unit_type = u8::try_from(unit.unit_type)
                    .ok()
                    .and_then(CivilianUnitKind::from_index)
                    .ok_or_else(|| {
                        LegacySaveError::StateProjection(format!(
                            "invalid civilian unit type {}",
                            unit.unit_type
                        ))
                    })?;
                let tile = optional_tile_id(i32::from(unit.tile_index))?;
                let target = optional_tile_id(i32::from(unit.order_target))?;
                CivilianUnitState::new(
                    CivilianUnitId::from_serialized(unit.persistent_id),
                    nation,
                    unit_type,
                    tile.map_or(CivilianLocation::OffMap, CivilianLocation::OnMap),
                    civilian_work_order(unit.order, tile, target, unit.remaining_turns, topology)?,
                    nation_id_from_retail_i16(unit.owner_nation)?,
                    unit.roster_id,
                    unit.registered != 0,
                )
                .ok_or_else(|| {
                    LegacySaveError::StateProjection(format!(
                        "civilian unit {} has an order inconsistent with its location",
                        unit.persistent_id
                    ))
                })
            })
            .collect()
    }
}

impl LegacyMission {
    pub(super) fn mission_state(
        &self,
        nation: NationId,
        queue_index: usize,
        military_units: &[LegacyMilitaryUnit],
    ) -> Result<MissionState, LegacySaveError> {
        let army = if let Some(army) = &self.army {
            let mut units = Vec::with_capacity(army.unit_ordinals.len());
            for ordinal in &army.unit_ordinals {
                let unit = usize::try_from(*ordinal - 1)
                    .ok()
                    .and_then(|unit_index| military_units.get(unit_index))
                    .ok_or_else(|| {
                        LegacySaveError::StateProjection(format!(
                            "mission queue {queue_index} references absent unit ordinal {ordinal} for nation {}",
                            nation.get()
                        ))
                    })?;
                units.push(MilitaryUnitId::from_serialized(unit.persistent_id));
            }
            Some((
                optional_province_id(army.present_location)?,
                ArmyMissionState {
                    required_equipage_bits: army.required_equipage_bits,
                    units,
                },
            ))
        } else {
            None
        };
        let navy = self.navy.as_ref().map(navy_mission_state).transpose()?;
        let beachhead = self
            .beachhead
            .as_ref()
            .map(navy_mission_state)
            .transpose()?;
        let attack = match (self.target_province, self.amassing_province, army.clone()) {
            (Some(target_province), Some(amassing_province), Some((present_province, army))) => {
                Some(AttackMissionState {
                    army,
                    present_province,
                    target_province: required_state(
                        optional_province_id(target_province)?,
                        "attack target province",
                    )?,
                    amassing_province: optional_province_id(amassing_province)?,
                })
            }
            _ => None,
        };
        let data = match self.class.as_str() {
            "TDefendProvinceMission" => {
                let (province, army) = required_state(army, "defend-province army mission")?;
                MissionData::DefendProvince {
                    province: required_state(province, "defend-province mission province")?,
                    army,
                }
            }
            "TAttackProvinceMission" => MissionData::AttackProvince(required_state(
                attack,
                "attack-province mission payload",
            )?),
            "TInvadeMission" => MissionData::Invade {
                attack: required_state(attack, "invade mission payload")?,
                beachhead,
            },
            "TControlSeaZoneMission" => {
                MissionData::ControlSeaZone(required_state(navy, "control-sea-zone navy mission")?)
            }
            "TEscortMission" => MissionData::Escort(required_state(navy, "escort navy mission")?),
            "TScatteredShipsMission" => {
                MissionData::ScatteredShips(required_state(navy, "scattered-ships navy mission")?)
            }
            "TBlockadePortMission" => {
                let port_zone = required_state(self.blockade_port_zone, "blockade port zone")?;
                MissionData::BlockadePort {
                    navy: required_state(navy, "blockade-port navy mission")?,
                    port_zone: required_state(
                        optional_ocean_zone_id(port_zone)?,
                        "blockade port zone",
                    )?,
                }
            }
            "TBeachheadMission" => {
                MissionData::Beachhead(required_state(navy, "beachhead navy mission")?)
            }
            class => {
                return Err(LegacySaveError::StateProjection(format!(
                    "unsupported mission class {class}"
                )));
            }
        };
        let source_nation = nation_id_from_retail_i16(self.source_nation)?;
        if source_nation != nation {
            return Err(LegacySaveError::StateProjection(format!(
                "mission queue {queue_index} belongs to nation {} but stores source nation {}",
                nation.get(),
                source_nation.get()
            )));
        }
        Ok(MissionState {
            nation,
            data,
            path_nation: optional_nation_id(self.path_marker)?,
            state: self.state,
            importance_bits: self.importance_bits,
            held: self.flag != 0,
            marker: self.marker,
        })
    }
}

pub(super) fn navy_mission_state(
    mission: &LegacyNavyMission,
) -> Result<NavyMissionState, LegacySaveError> {
    if let Some(ordinal) = mission.ship_ordinals.first() {
        return Err(LegacySaveError::StateProjection(format!(
            "semantic projection of navy mission ship ordinal {ordinal} is not implemented"
        )));
    }
    Ok(NavyMissionState {
        target_zone: optional_ocean_zone_id(mission.target_zone)?,
        resolved_port_zone: optional_ocean_zone_id(mission.resolved_port_zone)?,
        // TNavyMission::ReadFrom rebuilds these runtime-only links as null.
        selected_ship: None,
        task_force: None,
        state: mission.state,
        required_equipage_bits: mission.required_equipage_bits,
        ships: Vec::new(),
    })
}

impl LegacyCityState {
    pub(super) fn city_state(&self) -> Result<CityState, LegacySaveError> {
        if !self.tasks.is_empty() {
            return Err(LegacySaveError::StateProjection(
                "semantic projection of city tasks is not implemented".into(),
            ));
        }
        if !self.transport_requests.records.is_empty() {
            return Err(LegacySaveError::StateProjection(
                "semantic projection of city transport requests is not implemented".into(),
            ));
        }

        let strike_phase =
            StrikePhase::from_retail(self.population.phase_value).ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "invalid population strike phase {}",
                    self.population.phase_value
                ))
            })?;
        let accumulator =
            PopulationAccumulator::new(f32::from_bits(self.population.count_float_bits))
                .ok_or_else(|| {
                    LegacySaveError::StateProjection("population accumulator is not finite".into())
                })?;

        Ok(CityState {
            orders: Box::new(self.orders.clone()),
            power_plant_upgrade_queued: self.power_plant_upgrade_queued != 0,
            food_substitution_count: self.food_substitution_count,
            starvation_population_loss: self.starvation_population_loss,
            serialized_state: self.serialized_state,
            phase_counter: self.phase_counter,
            military_recruit_count_by_kind: MilitaryUnitTable::from_array(
                self.military_recruit_count_by_kind,
            ),
            civilian_recruit_count_by_kind: CivilianUnitTable::from_array(
                self.civilian_recruit_count_by_kind,
            ),
            ship_order_count_by_type: ShipTypeTable::from_array(self.order_count_by_type),
            rolling_item_production_score: self.rolling_item_production_score,
            low_production: self.low_production != 0,
            low_stock: self.low_stock != 0,
            reserved_by_type: ResourceTable::from_array(self.reserved_by_type),
            power_available: self.power_available,
            stockpile: Stockpile::from_table(ResourceTable::from_array(self.stockpile)),
            production_orders: ProductionTable::from_array(self.production_orders),
            production_accum: ProductionTable::from_array(self.production_accum),
            production_flags: ProductionTable::from_array(self.production_flags),
            production_current: ProductionTable::from_array(self.production_current),
            production_progress: ProductionTable::from_array(self.production_progress),
            // This constructed cache is not persisted by TCity::ReadFrom.
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::from_array(self.unmet_resource_retries),
            consumed_production_input_by_type: ResourceTable::from_array(
                self.consumed_production_input_by_type,
            ),
            population: PopulationState::new(
                self.population.count,
                accumulator,
                self.population.strength,
                self.population.extra,
                strike_phase,
                LaborPool::from(self.population.baseline_labor),
                LaborPool::from(self.population.production_labor),
                LaborPool::from(self.population.pending_labor_delta),
                ResourceTable::from_array(self.population.predicted_need_by_resource),
            ),
        })
    }
}

impl LegacyTerrainTile {
    fn tile_state(self, tile: usize) -> Result<TileState, LegacySaveError> {
        let rendering = TileRendering::from_retail(
            self.sprite_variant,
            self.river_sprite,
            self.adjacency_mask_a,
            self.adjacency_mask_b,
        )
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "tile {tile} has invalid rendering state: sprite variant {:#04x}, river sprite {:#04x}, transition mask {:#04x}, secondary mask {:#04x}",
                self.sprite_variant,
                self.river_sprite,
                self.adjacency_mask_a,
                self.adjacency_mask_b,
            ))
        })?;
        Ok(TileState {
            terrain: TerrainKind::from_retail(self.terrain_kind).ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "tile {tile} has invalid terrain {}",
                    self.terrain_kind
                ))
            })?,
            rendering,
            owner_nation: optional_tile_owner_tag(self.owner_nation)?,
            former_owner_nation: optional_tile_owner_tag(self.former_owner_nation)?,
            secondary_owner_nation: optional_major_nation_id(self.secondary_owner_nation, tile)?,
            owner_border_mask: self.owner_border_mask,
            city_border_mask: self.city_border_mask,
            water_adjacency_mask: self.water_adjacency_mask,
            province: optional_province_id(self.city_record_index)?,
            gate: self.gate,
            recruit_search_visited: self.recruit_search_visited,
            per_tile_visited: self.per_tile_visited,
            marker_slot_index: self.marker_slot_index,
            tile_action_ordinal: self.tile_action_ordinal,
            development: TileDevelopment {
                surface: DevelopmentLevel::new((self.development_classes as u8) & 0x0f),
                extractive: DevelopmentLevel::new((self.development_classes as u8) >> 4),
                resource_visible_to_majors: MajorNationTable::from_fn(|nation| {
                    self.pending_development_visibility & (1 << nation.get()) != 0
                }),
            },
            edge_resources: [
                optional_resource_kind(self.edge_resources[0], tile)?,
                optional_resource_kind(self.edge_resources[1], tile)?,
            ],
            transport_links: decode_tile_transport_links(
                tile,
                "transport_links",
                self.adjacency_bits,
            )?,
            pending_rail_links: decode_tile_transport_links(
                tile,
                "pending_rail_links",
                self.rail_flags,
            )?,
            action: TileAction::try_from_retail(i16::from(self.action_state)),
            flags: TileFlags::from_bits_retain(self.active_flags),
            region: optional_region_id(self.region)?,
        })
    }
}

impl LegacyMapState {
    const fn topology(&self) -> MapTopology {
        if self.no_horizontal_wrap == 0 {
            MapTopology::Wrapping
        } else {
            MapTopology::Bounded
        }
    }

    fn map_mgr(&self) -> Result<MapMgr, LegacySaveError> {
        let view_origin = u16::try_from(self.view_origin_tile)
            .ok()
            .and_then(TileId::try_new)
            .ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "map view origin {} is outside the strategic map",
                    self.view_origin_tile
                ))
            })?;
        let mut map = MapMgr::from_parts(
            self.topology(),
            self.tiles
                .iter()
                .copied()
                .enumerate()
                .map(|(tile, terrain)| terrain.tile_state(tile))
                .collect::<Result<Vec<_>, _>>()?,
            self.province_states()?,
        )
        .map_err(|error| LegacySaveError::StateProjection(error.to_string()))?;
        map.view_origin = view_origin;
        map.map_data_ready = retail_boolean(self.map_data_ready, "map-data-ready flag")?;
        map.recruit_search_active =
            retail_boolean(self.recruit_search_active, "map recruit-search-active flag")?;
        map.city_score_total = self.city_score_total;
        map.scenario_tag.clone_from(&self.scenario_tag);
        map.pending_river_mouth_tile = optional_tile_id(i32::from(self.pending_river_mouth_tile))?;
        Ok(map)
    }

    fn province_states(&self) -> Result<ProvinceTable<ProvinceState>, LegacySaveError> {
        if self.provinces.len() != PROVINCE_COUNT {
            return Err(LegacySaveError::StateProjection(format!(
                "province table has {} records; expected {PROVINCE_COUNT}",
                self.provinces.len()
            )));
        }
        let provinces = self
            .provinces
            .iter()
            .enumerate()
            .map(|(index, province)| province_state(index, province))
            .collect::<Result<Vec<_>, _>>()?;
        let provinces: [ProvinceState; PROVINCE_COUNT] = provinces
            .try_into()
            .expect("province table length was checked before projection");
        Ok(ProvinceTable::from_array(provinces))
    }
}

impl LegacySaveV62 {
    /// Projects the decoded strategic-map manager into semantic state.
    pub fn map_mgr(&self) -> Result<MapMgr, LegacySaveError> {
        self.map.map_mgr()
    }

    /// Projects the fully decoded save directly into live semantic state.
    /// Runtime-only RNG and selection state must be supplied by the process that loaded
    /// the save because the retail stream does not contain them.
    pub fn game_state(
        &self,
        context: LegacyGameStateContext,
    ) -> Result<GameState, LegacySaveError> {
        if !self.navy.ships.is_empty()
            || !self.navy.admirals.is_empty()
            || !self.navy.task_forces.is_empty()
        {
            return Err(LegacySaveError::StateProjection(
                "semantic projection of non-empty retail navy relationships is not implemented"
                    .to_owned(),
            ));
        }

        let mut minors = MinorNationTable::default();
        let mut military_units = Vec::new();
        let mut civilian_units = Vec::new();
        let mut missions = Vec::new();
        let mut pending = PendingWorkState {
            combat_reports_pending: self.army_report_count != 0,
            ..PendingWorkState::default()
        };
        let map = self.map.map_mgr()?;
        let ocean = ocean_state(&self.ocean, &map)?;
        let live_ocean_context_count = ocean.zones.len();
        let mut majors = Vec::with_capacity(MAJOR_NATION_COUNT);
        for slot in 0..MAJOR_NATION_COUNT {
            let major_id = MajorNationId::new(slot as u8);
            let nation_id = major_id.nation();
            let nation = self
                .major_nations
                .iter()
                .find(|nation| nation.great_power().country.nation_slot == slot as i16)
                .ok_or_else(|| {
                    LegacySaveError::StateProjection(format!("major nation slot {slot} is absent"))
                })?;
            let great_power = nation.great_power();
            let city = great_power.city.as_ref().ok_or_else(|| {
                LegacySaveError::StateProjection(format!("major nation slot {slot} has no city"))
            })?;
            let towns = great_power
                .post_city
                .towns
                .iter()
                .map(|town| {
                    let tile = optional_tile_id(i32::from(town.tile_index))?.ok_or_else(|| {
                        LegacySaveError::StateProjection(format!(
                            "major nation slot {slot} town has no tile"
                        ))
                    })?;
                    let owner_nation = u8::try_from(town.owner_nation)
                        .ok()
                        .and_then(NationId::try_new)
                        .ok_or_else(|| {
                            LegacySaveError::StateProjection(format!(
                                "major nation slot {slot} town owner {} is out of range",
                                town.owner_nation
                            ))
                        })?;
                    Ok::<TownState, LegacySaveError>(TownState {
                        name: town.name.clone(),
                        tile,
                        created_turn: town.created_turn,
                        owner_nation,
                        resource_yield_by_type: ResourceTable::from_array(
                            town.resource_yield_by_type,
                        ),
                        transport_linked: retail_boolean(
                            town.transport_linked,
                            "town transport-linked flag",
                        )?,
                        enabled: town.enabled,
                        has_adjacent_city: town.has_adjacent_city,
                        active: retail_boolean(town.active, "town active flag")?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let city = city.city_state()?;
            let foreign_minister_personality = foreign_minister_personality(
                nation,
                self.simulation.game_setup.foreign_minister_policy_ids[slot],
            )?;
            let (ai_zone_targets, ai_province_targets, ai_trade, ai_development_pressure) =
                match nation {
                    LegacyMajorNationState::Auto(auto) => (
                        Some(ai_zone_targets(
                            &auto.auto_prefix.port_zone_state_flags,
                            live_ocean_context_count,
                            slot,
                        )?),
                        Some(ai_province_targets(
                            &auto.auto_prefix.map_node_state_flags,
                            slot,
                        )?),
                        Some(AiTradeState {
                            temporary_processed_stock: ProcessedTradeCommodityTable::from_array(
                                auto.auto_prefix.action_metric_by_quarter,
                            ),
                        }),
                        Some(AiDevelopmentPressureState::default()),
                    ),
                    LegacyMajorNationState::Other(_) => (None, None, None, None),
                };
            majors.push(MajorNation {
                kind: match nation {
                    LegacyMajorNationState::Auto(_) => MajorNationKind::AutoGreatPower,
                    LegacyMajorNationState::Other(_) => MajorNationKind::GreatPower,
                },
                common: country_common(&great_power.country)?,
                economy: great_power_state(
                    great_power,
                    foreign_minister_personality,
                    ai_zone_targets,
                    ai_province_targets,
                    ai_trade,
                    ai_development_pressure,
                )?,
                city,
                towns,
            });
            military_units.extend(great_power.country.military_unit_states(nation_id)?);
            civilian_units.extend(
                great_power
                    .post_city
                    .civilian_unit_states(nation_id, self.map.topology())?,
            );
            if let LegacyMajorNationState::Auto(auto) = nation {
                for (queue_index, mission) in auto.missions.iter().enumerate() {
                    missions.push(mission.mission_state(
                        nation_id,
                        queue_index,
                        &great_power.country.military_units,
                    )?);
                }
            }
            let lists = &great_power.prefix.relationship_lists;
            pending.nations[major_id].turn_events =
                diplomacy_notices(&lists[0], great_power.country.nation_slot)?;
            pending.nations[major_id].proposals =
                diplomacy_proposals(&lists[1], great_power.country.nation_slot)?;
        }
        let majors = MajorNationTable::from_array(majors.try_into().map_err(
            |majors: Vec<MajorNation>| {
                LegacySaveError::StateProjection(format!(
                    "expected {MAJOR_NATION_COUNT} major nations, found {}",
                    majors.len()
                ))
            },
        )?);
        for slot in MAJOR_NATION_COUNT..NATION_COUNT {
            let minor_id = MinorNationId::new(slot as u8);
            if let Some(nation) = self
                .minor_nations
                .iter()
                .find(|nation| nation.country.nation_slot == slot as i16)
            {
                minors[minor_id] = Some(MinorNation {
                    common: country_common(&nation.country)?,
                    consortium_members: nation
                        .diplomacy_save_fields
                        .map(minor_nation_id_from_retail_i16)
                        .into_iter()
                        .collect::<Result<Vec<_>, _>>()?
                        .try_into()
                        .expect("four persisted consortium members"),
                    trade: minor_trade_state(nation)?,
                });
                military_units.extend(
                    nation
                        .country
                        .military_unit_states(NationId::new(slot as u8))?,
                );
            }
        }

        // The retail load path restores this counter before deserializing units.
        // Every TUnit constructor increments it once, even though ReadFrom then
        // replaces the unit's generated ID with the persisted ID.
        let loaded_unit_count = military_units.len() + civilian_units.len();
        let loaded_unit_count = i32::try_from(loaded_unit_count).map_err(|_| {
            LegacySaveError::StateProjection("loaded unit count does not fit an i32".into())
        })?;
        let persistent_unit_id_counter = self
            .simulation
            .persistent_unit_id_counter
            .checked_add(loaded_unit_count)
            .ok_or_else(|| {
                LegacySaveError::StateProjection(
                    "persistent unit ID counter overflows while loading units".into(),
                )
            })?;

        let state = GameState::from_parts(GameStateParts {
            turn: TurnState::new(
                self.simulation.game_setup.scenario_map,
                i32::from(self.simulation.economic_turn),
                self.simulation.diplomacy_year_term_raw,
                PhaseCode::from_retail(i32::from(self.simulation.turn_state_code)),
                self.simulation.turn_flow_status_flags,
                self.simulation.phase_state_by_decade[..10]
                    .try_into()
                    .expect("ten retail decade-gate bytes"),
                Difficulty::try_from(self.simulation.difficulty).map_err(|_| {
                    LegacySaveError::StateProjection(format!(
                        "invalid difficulty {}",
                        self.simulation.difficulty
                    ))
                })?,
                nation_id_from_retail_i16(self.simulation.active_nation)?,
                context.selected_nation,
            ),
            unit_ids: UnitIdAllocator::from_retail(persistent_unit_id_counter),
            map,
            ocean,
            rng: RngState {
                crt_rand: RetailCrtRng::from_state(context.crt_rand_state),
                map_generation: RetailLcg::from_state(context.map_generation_lcg),
                zone_status: RetailLcg::from_state(context.zone_status_lcg),
            },
            market: self.market.clone(),
            technology: self.technology,
            diplomacy: self.diplomacy.clone(),
            nations: Nations::new(majors, minors),
            military_units,
            civilian_units,
            ships: Vec::new(),
            task_forces: Vec::new(),
            missions,
            news: NewsState::default(),
            pending,
        });
        state.validate_territory_index().map_err(|error| {
            LegacySaveError::StateProjection(format!("invalid territory index: {error}"))
        })?;
        Ok(state)
    }
}

pub(super) fn diplomacy_notices(
    list: &LegacyFixedRecordList,
    owner: i16,
) -> Result<Vec<DiplomacyNotice>, LegacySaveError> {
    let records = relationship_records(list, owner, "turn-event queue")?;
    Ok(records
        .into_iter()
        .map(|(code, source)| DiplomacyNotice { source, code })
        .collect())
}

pub(super) fn diplomacy_proposals(
    list: &LegacyFixedRecordList,
    owner: i16,
) -> Result<Vec<DiplomacyProposal>, LegacySaveError> {
    let records = relationship_records(list, owner, "proposal queue")?;
    records
        .into_iter()
        .map(|(entry, source)| {
            Ok(DiplomacyProposal {
                source,
                policy: diplomacy_policy_from_retail(entry, owner, usize::from(source.get()))?,
            })
        })
        .collect()
}

pub(super) fn relationship_records(
    list: &LegacyFixedRecordList,
    owner: i16,
    queue: &'static str,
) -> Result<Vec<(i16, NationId)>, LegacySaveError> {
    if list.record_size != 4 {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} {queue} has record size {}; expected 4",
            list.record_size
        )));
    }
    let mut records = list
        .records
        .iter()
        .map(|record| {
            let value = i16::from_le_bytes(record[0..2].try_into().unwrap());
            let source =
                nation_id_from_retail_i16(i16::from_le_bytes(record[2..4].try_into().unwrap()))?;
            Ok((value, source))
        })
        .collect::<Result<Vec<_>, LegacySaveError>>()?;
    records.sort_by_key(|(_, source)| *source);
    if let Some((_, source)) = records
        .windows(2)
        .find(|pair| pair[0].1 == pair[1].1 && pair[0].0 != pair[1].0)
        .map(|pair| pair[0])
    {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} {queue} contains distinguishable records from source {}; retail load order depends on unavailable pre-load CRT state",
            source.get()
        )));
    }
    Ok(records)
}

pub(super) fn deal_book_state(
    lists: &[LegacyFixedRecordList],
    owner: i16,
) -> Result<TradeCommodityTable<Vec<TradeDealBookEntry>>, LegacySaveError> {
    let deal_lists = lists.get(2..).ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "nation {owner} has {} relationship lists; expected 19",
            lists.len()
        ))
    })?;
    if deal_lists.len() != TRADE_CATEGORY_COUNT {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} has {} deal-book lists; expected {TRADE_CATEGORY_COUNT}",
            deal_lists.len()
        )));
    }

    let mut deal_book = TradeCommodityTable::default();
    for (commodity_index, list) in deal_lists.iter().enumerate() {
        let commodity = TradeCommodity::from_retail(commodity_index as i16)
            .expect("the deal-book list count equals the trade-commodity count");
        deal_book[commodity] = deal_book_entries(list, owner, commodity)?;
    }
    Ok(deal_book)
}

pub(super) fn deal_book_entries(
    list: &LegacyFixedRecordList,
    owner: i16,
    commodity: TradeCommodity,
) -> Result<Vec<TradeDealBookEntry>, LegacySaveError> {
    if list.record_size != 12 {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} {commodity:?} deal book has record size {}; expected 12",
            list.record_size
        )));
    }
    let mut entries = list
        .records
        .iter()
        .map(|record| {
            let kind = match i16::from_le_bytes(record[0..2].try_into().unwrap()) {
                0 => DealBookEntryKind::Accept,
                1 => DealBookEntryKind::Offer,
                value => {
                    return Err(LegacySaveError::StateProjection(format!(
                        "nation {owner} {commodity:?} deal-book entry kind {value} is invalid"
                    )));
                }
            };
            let nation_raw = i16::from_le_bytes(record[2..4].try_into().unwrap());
            let nation = nation_id_from_retail_i16(nation_raw)?;
            let amount = i16::from_le_bytes(record[4..6].try_into().unwrap());
            let eligibility = i16::from_le_bytes(record[6..8].try_into().unwrap());
            let expected_eligibility = match kind {
                DealBookEntryKind::Offer => 1,
                DealBookEntryKind::Accept
                    if nation.get() >= MajorNationId::COUNT =>
                {
                    1
                }
                DealBookEntryKind::Accept => 0,
            };
            if eligibility != expected_eligibility {
                return Err(LegacySaveError::StateProjection(format!(
                    "nation {owner} {commodity:?} deal-book entry for nation {nation_raw} has eligibility {eligibility}; expected {expected_eligibility}"
                )));
            }
            Ok(TradeDealBookEntry {
                kind,
                nation,
                amount,
                unit_price: i32::from_le_bytes(record[8..12].try_into().unwrap()),
            })
        })
        .collect::<Result<Vec<_>, LegacySaveError>>()?;
    entries.sort_by_key(|entry| entry.nation);
    if let Some(entry) = entries.windows(2).find_map(|pair| {
        (pair[0].nation == pair[1].nation && pair[0] != pair[1]).then_some(pair[0])
    }) {
        return Err(LegacySaveError::StateProjection(format!(
            "nation {owner} {commodity:?} deal book contains distinguishable records for nation {}; retail load order depends on unavailable pre-load CRT state",
            entry.nation.get()
        )));
    }
    Ok(entries)
}

pub(super) fn validate_ocean_contexts(ocean: &LegacyOceanState) -> Result<usize, LegacySaveError> {
    let live_count = ocean.zones.len() + ocean.port_zones.len();
    if live_count > AI_ZONE_TARGET_CAPACITY {
        return Err(LegacySaveError::StateProjection(format!(
            "ocean has {live_count} live contexts; AI state supports at most {AI_ZONE_TARGET_CAPACITY}"
        )));
    }
    let mut seen = vec![false; live_count];
    for context in ocean.zones.iter().chain(&ocean.port_zones) {
        let ordinal = usize::try_from(context.context_ordinal).map_err(|_| {
            LegacySaveError::StateProjection(format!(
                "ocean context ordinal {} is negative",
                context.context_ordinal
            ))
        })?;
        if ordinal >= live_count {
            return Err(LegacySaveError::StateProjection(format!(
                "ocean context ordinal {ordinal} is outside the live range 0..{live_count}"
            )));
        }
        if std::mem::replace(&mut seen[ordinal], true) {
            return Err(LegacySaveError::StateProjection(format!(
                "ocean context ordinal {ordinal} is duplicated"
            )));
        }
    }
    Ok(live_count)
}

pub(super) fn ai_zone_targets(
    flags: &[u8; AI_ZONE_TARGET_CAPACITY],
    live_count: usize,
    nation: usize,
) -> Result<Vec<AiTargetState>, LegacySaveError> {
    let targets = flags[..live_count]
        .iter()
        .enumerate()
        .map(|(ordinal, value)| match value {
            0 => Ok(AiTargetState::Unmarked),
            1 => Ok(AiTargetState::Candidate),
            2 => Ok(AiTargetState::MissionQueued),
            value => Err(LegacySaveError::StateProjection(format!(
                "AI nation {nation} ocean context {ordinal} has invalid target state {value}"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some((offset, value)) = flags[live_count..]
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| *value != 0)
    {
        let ordinal = live_count + offset;
        return Err(LegacySaveError::StateProjection(format!(
            "AI nation {nation} unused ocean context {ordinal} has nonzero target state {value}"
        )));
    }
    Ok(targets)
}

pub(super) fn ai_province_targets(
    flags: &[u8; PROVINCE_COUNT],
    nation: usize,
) -> Result<ProvinceTable<AiTargetState>, LegacySaveError> {
    let mut targets = ProvinceTable::default();
    for (index, &value) in flags.iter().enumerate() {
        let province = ProvinceId::new(index as u16);
        targets[province] = match value {
            0 => AiTargetState::Unmarked,
            1 => AiTargetState::Candidate,
            2 => AiTargetState::MissionQueued,
            value => {
                return Err(LegacySaveError::StateProjection(format!(
                    "AI nation {nation} province {index} has invalid target state {value}"
                )));
            }
        };
    }
    Ok(targets)
}

pub(super) fn ocean_state(
    ocean: &LegacyOceanState,
    map: &MapMgr,
) -> Result<Ocean, LegacySaveError> {
    let live_count = validate_ocean_contexts(ocean)?;
    let mut zones = vec![None; live_count];

    for context in &ocean.zones {
        let ordinal = usize::try_from(context.context_ordinal)
            .expect("validated ocean context ordinal is nonnegative");
        zones[ordinal] = Some(ZoneKind::Zone(zone_state(context)?));
    }
    for context in &ocean.port_zones {
        let ordinal = usize::try_from(context.context_ordinal)
            .expect("validated ocean context ordinal is nonnegative");
        let port_tile = required_state(
            optional_tile_id(i32::from(required_state(
                context.port_tile_index,
                "port-zone tile index",
            )?))?,
            "port-zone tile",
        )?;
        map[port_tile]
            .former_owner_nation
            .and_then(TileOwnerTag::nation)
            .ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "missing port-zone {ordinal} former owner"
                ))
            })?;
        zones[ordinal] = Some(ZoneKind::PortZone(PortZone {
            zone: zone_state(context)?,
            port_tile,
        }));
    }

    let zones = zones
        .into_iter()
        .enumerate()
        .map(|(ordinal, zone)| {
            zone.ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "ocean context ordinal {ordinal} is absent"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let routes = ocean
        .route_segments
        .iter()
        .map(
            |&[start_row, start_column, end_row, end_column]| OceanRoute {
                start_column,
                start_row,
                end_column,
                end_row,
            },
        )
        .collect();
    let mut ocean = Ocean { zones, routes };
    rebuild_ocean_neighbors(&mut ocean, map)?;
    Ok(ocean)
}

fn zone_state(context: &LegacyZone) -> Result<Zone, LegacySaveError> {
    let seed_owner = match context.seed_nation_id {
        -1 => None,
        value => Some(TileOwnerTag::new(u8::try_from(value).map_err(|_| {
            LegacySaveError::StateProjection(format!("zone seed owner tag {value} is invalid"))
        })?)),
    };
    Ok(Zone {
        display_name: context.display_name.clone(),
        status_code: (context.status_code != -1).then_some(context.status_code),
        target_tile: optional_tile_id(context.tile_or_terrain_id)?,
        seed_owner,
        active_tile: optional_tile_id(i32::from(context.active_tile_index))?,
        primary_neighbors: Vec::new(),
        secondary_neighbors: Vec::new(),
    })
}

fn rebuild_ocean_neighbors(ocean: &mut Ocean, map: &MapMgr) -> Result<(), LegacySaveError> {
    for zone in &mut ocean.zones {
        let zone = match zone {
            ZoneKind::Zone(zone) => zone,
            ZoneKind::PortZone(port) => &mut port.zone,
        };
        zone.primary_neighbors.clear();
        zone.secondary_neighbors.clear();
    }

    let geometry = map.geometry();
    for tile_index in 0..TileId::COUNT {
        let tile = TileId::new(tile_index);
        let Some(zone_index) = ocean_zone_for_tile(ocean, map, tile) else {
            continue;
        };
        if matches!(ocean.zones[zone_index], ZoneKind::PortZone(_)) {
            let has_primary = match &ocean.zones[zone_index] {
                ZoneKind::PortZone(port) => !port.zone.primary_neighbors.is_empty(),
                ZoneKind::Zone(_) => unreachable!(),
            };
            if has_primary {
                continue;
            }
            let target_tile = match &ocean.zones[zone_index] {
                ZoneKind::PortZone(port) => port.zone.target_tile,
                ZoneKind::Zone(_) => unreachable!(),
            }
            .ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "port-zone {zone_index} has no target tile"
                ))
            })?;
            let owner = map[target_tile]
                .owner_nation
                .map(TileOwnerTag::get)
                .filter(|&owner| owner >= 0x17)
                .ok_or_else(|| {
                    LegacySaveError::StateProjection(format!(
                        "port-zone {zone_index} target tile {} has no base ocean zone",
                        target_tile.get()
                    ))
                })?;
            let base_index = usize::from(owner - 0x17);
            if !matches!(ocean.zones.get(base_index), Some(ZoneKind::Zone(_))) {
                return Err(LegacySaveError::StateProjection(format!(
                    "port-zone {zone_index} target tile {} names missing base ocean zone {base_index}",
                    target_tile.get()
                )));
            }
            let port_id = OceanZoneId::new(zone_index as u16);
            let base_id = OceanZoneId::new(base_index as u16);
            let ZoneKind::PortZone(port) = &mut ocean.zones[zone_index] else {
                unreachable!()
            };
            port.zone.primary_neighbors.push(base_id);
            let ZoneKind::Zone(base) = &mut ocean.zones[base_index] else {
                unreachable!()
            };
            base.primary_neighbors.push(port_id);
            continue;
        }

        for neighbor in geometry.neighbors(tile).into_iter().flatten() {
            if let Some(province) = map[neighbor].province {
                let ZoneKind::Zone(zone) = &mut ocean.zones[zone_index] else {
                    unreachable!()
                };
                if !zone.secondary_neighbors.contains(&province) {
                    zone.secondary_neighbors.push(province);
                }
                continue;
            }
            let Some(candidate) = ocean_zone_for_tile(ocean, map, neighbor) else {
                continue;
            };
            if candidate == zone_index || matches!(ocean.zones[candidate], ZoneKind::PortZone(_)) {
                continue;
            }
            let candidate = OceanZoneId::new(candidate as u16);
            let ZoneKind::Zone(zone) = &mut ocean.zones[zone_index] else {
                unreachable!()
            };
            if !zone.primary_neighbors.contains(&candidate) {
                zone.primary_neighbors.push(candidate);
            }
        }
    }
    Ok(())
}

fn ocean_zone_for_tile(ocean: &Ocean, map: &MapMgr, tile: TileId) -> Option<usize> {
    if map[tile]
        .action
        .is_some_and(|action| matches!(action.retail(), 3 | 14))
    {
        return ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(ordinal, zone)| match zone {
                ZoneKind::PortZone(port)
                    if port.port_tile == tile
                        || port.zone.target_tile == Some(tile)
                        || port.zone.active_tile == Some(tile) =>
                {
                    Some(ordinal)
                }
                _ => None,
            });
    }
    let ordinal = map[tile]
        .owner_nation
        .map(TileOwnerTag::get)?
        .checked_sub(0x17)?;
    let ordinal = usize::from(ordinal);
    matches!(ocean.zones.get(ordinal), Some(ZoneKind::Zone(_))).then_some(ordinal)
}

pub(super) fn foreign_minister_personality(
    nation: &LegacyMajorNationState,
    setup_policy_id: i16,
) -> Result<ForeignMinisterPersonality, LegacySaveError> {
    if !matches!(nation, LegacyMajorNationState::Auto(_)) {
        return Ok(ForeignMinisterPersonality::Base);
    }
    match setup_policy_id {
        0 => Ok(ForeignMinisterPersonality::Arms),
        1 => Ok(ForeignMinisterPersonality::Trader),
        2 => Ok(ForeignMinisterPersonality::Textile),
        3 => Ok(ForeignMinisterPersonality::Diplomat),
        4 => Ok(ForeignMinisterPersonality::Bill),
        5 => Ok(ForeignMinisterPersonality::Ted),
        _ => Err(LegacySaveError::StateProjection(format!(
            "unsupported AI foreign-minister setup policy {setup_policy_id}"
        ))),
    }
}

pub(super) fn trade_commodity_from_retail(
    value: i16,
    context: impl std::fmt::Display,
) -> Result<TradeCommodity, LegacySaveError> {
    TradeCommodity::from_retail(value).ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "{context} trade commodity {value} is out of range"
        ))
    })
}

pub(super) fn optional_trade_commodity_from_retail(
    value: i16,
    context: impl std::fmt::Display,
) -> Result<Option<TradeCommodity>, LegacySaveError> {
    if value == -10 {
        return Ok(None);
    }
    trade_commodity_from_retail(value, context).map(Some)
}

pub(super) fn optional_manufactured_trade_commodity_from_retail(
    value: i16,
    context: impl std::fmt::Display,
) -> Result<Option<TradeCommodity>, LegacySaveError> {
    let commodity = optional_trade_commodity_from_retail(value, context)?;
    if matches!(
        commodity,
        None | Some(
            TradeCommodity::Clothing
                | TradeCommodity::Furniture
                | TradeCommodity::Hardware
                | TradeCommodity::Arms
        )
    ) {
        Ok(commodity)
    } else {
        Err(LegacySaveError::StateProjection(format!(
            "manufactured trade request {value} is outside the recovered range"
        )))
    }
}

pub(super) fn foreign_trade_state(
    minister: &LegacyForeignMinisterState,
    nation: i16,
) -> Result<ForeignTradeState, LegacySaveError> {
    let interior_bid = optional_trade_commodity_from_retail(
        minister.scalar_fields[0],
        format_args!("major nation {nation} interior-bid"),
    )?
    .map(|commodity| ForeignTradeBid {
        commodity,
        amount: minister.scalar_fields[1],
    });
    let requested_ship = match minister.scalar_fields[6] {
        1 => ShipType::Trader,
        2 => ShipType::Indiaman,
        value => {
            return Err(LegacySaveError::StateProjection(format!(
                "major nation {nation} foreign-minister ship order kind {value} is outside the recovered range"
            )));
        }
    };
    let mut preferred_resources = [None; 4];
    for (index, value) in minister.preferred_resource_slots.into_iter().enumerate() {
        preferred_resources[index] = optional_trade_commodity_from_retail(
            value,
            format_args!("major nation {nation} preferred-resource slot {index}"),
        )?;
    }
    Ok(ForeignTradeState {
        interior_bid,
        phase_counter: minister.scalar_fields[4],
        refresh_interval: minister.scalar_fields[5],
        requested_ship,
        purchase_priority: TradeCommodityTable::from_array(minister.purchase_priority_by_resource),
        preferred_resources,
    })
}

pub(super) fn pending_ship(
    minister: &LegacyInteriorMinisterState,
    nation: i16,
) -> Result<Option<ShipType>, LegacySaveError> {
    match minister.order_scalars[1] {
        0 => Ok(None),
        1 => Ok(Some(ShipType::Trader)),
        2 => Ok(Some(ShipType::Indiaman)),
        value => Err(LegacySaveError::StateProjection(format!(
            "major nation {nation} pending ship type {value} is outside the recovered range"
        ))),
    }
}

pub(super) fn minor_trade_state(
    nation: &LegacyMinorState,
) -> Result<MinorTradeState, LegacySaveError> {
    let slot = nation.country.nation_slot;
    Ok(MinorTradeState {
        current_supply: ResourceTable::from_array(nation.need_current_by_type),
        offers: ResourceTable::from_array(nation.trade_offers_by_resource),
        grant_deltas: ResourceTable::from_array(nation.grant_amounts_by_resource),
        thresholds: MinorTradeThresholds {
            primary_manufactured_price: nation.diplomacy_thresholds[0],
            secondary_manufactured_price: nation.diplomacy_thresholds[1],
            general_offer_price: nation.diplomacy_thresholds[2],
            random_offer_price: nation.diplomacy_thresholds[3],
            coal_offer_price: nation.diplomacy_thresholds[4],
            iron_offer_price: nation.diplomacy_thresholds[5],
            oil_offer_price: nation.diplomacy_thresholds[6],
        },
        primary_manufactured_request: optional_manufactured_trade_commodity_from_retail(
            nation.diplomacy_policy_fields[0],
            format_args!("minor nation {slot} primary request"),
        )?,
        secondary_manufactured_request: optional_manufactured_trade_commodity_from_retail(
            nation.diplomacy_policy_fields[1],
            format_args!("minor nation {slot} secondary request"),
        )?,
        primary_request_fulfilled: nation.diplomacy_policy_fields[2],
        secondary_request_fulfilled: nation.diplomacy_policy_fields[3],
        independent_resource_counts: ResourceTable::from_array(nation.diplomacy_save_extension),
    })
}

pub(super) fn great_power_state(
    nation: &LegacyGreatPowerState,
    foreign_minister_personality: ForeignMinisterPersonality,
    ai_zone_targets: Option<Vec<AiTargetState>>,
    ai_province_targets: Option<ProvinceTable<AiTargetState>>,
    ai_trade: Option<AiTradeState>,
    ai_development_pressure: Option<AiDevelopmentPressureState>,
) -> Result<GreatPowerState, LegacySaveError> {
    let prefix = &nation.prefix;
    let post = &nation.post_city;
    let foreign_minister = nation.ministers.foreign.as_ref().ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "major nation slot {} has no foreign minister",
            nation.country.nation_slot
        ))
    })?;
    let defense_minister = nation.ministers.defense.as_ref().ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "major nation slot {} has no defense minister",
            nation.country.nation_slot
        ))
    })?;
    let interior_minister = nation.ministers.interior.as_ref().ok_or_else(|| {
        LegacySaveError::StateProjection(format!(
            "major nation slot {} has no interior minister",
            nation.country.nation_slot
        ))
    })?;
    Ok(GreatPowerState {
        controller: if prefix.diplomacy_eligible != 0 {
            MajorNationController::Human
        } else {
            MajorNationController::Computer
        },
        ai_zone_targets,
        ai_province_targets,
        foreign_minister_personality,
        foreign_minister_skill_index: foreign_minister.skill_index,
        foreign_trade: foreign_trade_state(foreign_minister, nation.country.nation_slot)?,
        development_grant_by_nation: NationTable::from_array(
            foreign_minister.development_grant_by_nation,
        ),
        defense_minister_skill_index: defense_minister.skill_index,
        capacities: NationCapacities::from_array(prefix.capacities),
        grant_total_cost: prefix.grant_total_cost,
        unfilled_trade_offer_count: prefix.unfilled_trade_offer_count,
        diplomacy_policy_by_nation: diplomacy_policies_from_retail_entries(
            prefix.diplomacy_policy_by_nation,
            nation.country.nation_slot,
        )?,
        diplomacy_grants_by_nation: diplomacy_grants_from_retail_entries(
            prefix.diplomacy_grant_by_nation,
            nation.country.nation_slot,
        )?,
        need_current_by_type: ResourceTable::from_array(prefix.need_current_by_type),
        need_target_by_type: ResourceTable::from_array(prefix.need_target_by_type),
        relation_delta_current: ResourceTable::from_array(prefix.relation_delta_current),
        purchased_items_by_resource: ResourceTable::from_array(prefix.purchased_items_by_resource),
        item_potentials: ResourceTable::from_array(prefix.item_potentials),
        unfilled_trade_turns_by_resource: ResourceTable::from_array(
            prefix.unfilled_trade_turns_by_resource,
        ),
        transported_items_by_resource: ResourceTable::from_array(
            prefix.transported_items_by_resource,
        ),
        remembered_trade_offers_by_resource: ResourceTable::from_array(
            prefix.remembered_trade_offers_by_resource,
        ),
        deal_book: deal_book_state(&prefix.relationship_lists, nation.country.nation_slot)?,
        pending_ship: pending_ship(interior_minister, nation.country.nation_slot)?,
        interior_civilian: Box::new(interior_civilian_state(
            interior_minister,
            nation.country.nation_slot,
        )?),
        ai_trade,
        ai_development_pressure,
        aid_allocation_by_minor_nation: MinorNationTable::from_array(
            prefix
                .aid_allocation_by_minor_nation
                .map(ResourceTable::from_array),
        ),
        budget_pool_base: prefix.budget_pool_base,
        budget_pool_delta: prefix.budget_pool_delta,
        special_resource_trade_balance: post.special_resource_trade_balance,
        candidate_nation_flags: NationTable::from_array(post.candidate_nation_flags),
        // scenarioInitFlag is constructed as zero and is not part of the save stream.
        scenario_initialized: false,
        turn_finished: post.turn_finished_flag != 0,
        pending_actions: prefix.pending_actions,
        diplomacy_budget_base: post.diplomacy_budget_base,
        escalation_counter: i16::from(post.escalation_counter),
        pending_commitment_cost: post.pending_commitment_cost,
        pressure_counter: i16::from(post.pressure_counter),
        army_movement_budget: post.army_movement_budget,
        aid_allocation_total: post.aid_allocation_total,
        colony_boycott_flags: NationTable::from_array(post.colony_boycott_flags),
        military_expenses: post.military_expenses,
    })
}

pub(super) fn interior_civilian_state(
    minister: &LegacyInteriorMinisterState,
    nation: i16,
) -> Result<InteriorCivilianState, LegacySaveError> {
    let pending_recruitment = match minister.order_scalars[3] {
        -1 => None,
        value => Some(
            u8::try_from(value)
                .ok()
                .and_then(CivilianUnitKind::from_index)
                .ok_or_else(|| {
                    LegacySaveError::StateProjection(format!(
                        "major nation {nation} pending civilian recruitment kind {value} is out of range"
                    ))
                })?,
        ),
    };
    let resource_order_metrics = ResourceTable::from_array(
        minister.order_metrics[..RESOURCE_KIND_COUNT]
            .try_into()
            .expect("resource metric prefix has the fixed resource-table length"),
    );
    if minister.order_metrics[33] != 0 || minister.order_metrics[52] != 0 {
        return Err(LegacySaveError::StateProjection(format!(
            "major nation {nation} has demand in a fixed null city-order slot"
        )));
    }
    let mut expansion_demand = [0_i16; CityFacilitySlot::COUNT];
    expansion_demand[..7].copy_from_slice(&minister.order_metrics[53..60]);
    let city_order_demand = AiCityOrderDemand::from_parts(
        TrainingOrderTable::from_array(
            minister.order_metrics[23..25]
                .try_into()
                .expect("training demand has two fixed slots"),
        ),
        MilitaryRecruitOrderTable::from_array(
            minister.order_metrics[25..33]
                .try_into()
                .expect("military recruitment demand has eight fixed slots"),
        ),
        CivilianUnitTable::from_array(
            minister.order_metrics[34..43]
                .try_into()
                .expect("civilian recruitment demand has nine fixed slots"),
        ),
        ShipOrderTable::from_array(
            minister.order_metrics[43..51]
                .try_into()
                .expect("ship demand has eight fixed slots"),
        ),
        minister.order_metrics[51],
        ProductionTable::from_array(expansion_demand),
        minister.order_metrics[60],
    );
    let pending_development_actions = minister.integer_lists[2]
        .iter()
        .map(|&value| {
            let action = match value {
                0..=29 => MilitaryUnitKind::from_index(value as u8)
                    .map(|unit_type| PendingDevelopmentAction::LandUnit { unit_type }),
                30..=43 => CityFacilitySlot::from_index((value - 30) as u8)
                    .map(|slot| PendingDevelopmentAction::Industry { slot }),
                _ => None,
            };
            action.ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "major nation {nation} pending development action {value} is out of range"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(InteriorCivilianState::from_parts(
        pending_recruitment,
        optional_tile_id(i32::from(minister.order_scalars[6]))?,
        resource_order_metrics,
        city_order_demand,
        minister.deferred_labor_shortfall,
        ProductionTable::from_array(minister.order_short_table),
        minister.temporarily_reserved_ship_arms,
        ResourceTable::from_array(minister.order_type_tables[0]),
        ResourceTable::from_array(minister.order_type_tables[1]),
        ResourceTable::from_array(minister.order_type_tables[2]),
        ResourceTable::from_array(minister.civilian_order_demand_by_resource),
        // Retail constructs this transient table as zero and does not deserialize it.
        // The city-and-transport phase rebuilds it only after this loaded-save turn slice.
        0,
        pending_development_actions,
    ))
}

pub(super) fn pending_action_from_retail(
    status: i8,
    payload: i16,
) -> Result<PendingActionState, LegacySaveError> {
    if payload < -1 {
        return Err(LegacySaveError::StateProjection(format!(
            "pending-action payload {payload} is below the -1 sentinel"
        )));
    }
    let status = match status {
        0 => PendingActionStatus::None,
        0x32 => PendingActionStatus::Queued,
        0x33 => PendingActionStatus::Level3,
        0x34 => PendingActionStatus::Level4,
        _ => {
            return Err(LegacySaveError::StateProjection(format!(
                "unsupported pending-action status {status}"
            )));
        }
    };
    Ok(PendingActionState::new(
        status,
        (payload != -1).then_some(payload),
    ))
}

pub(super) fn diplomacy_grants_from_retail_entries(
    entries: [i16; NATION_COUNT],
    nation: i16,
) -> Result<NationTable<Option<DiplomacyGrant>>, LegacySaveError> {
    let mut grants = NationTable::default();
    for (target, entry) in entries.into_iter().enumerate() {
        grants[NationId::new(target as u8)] = if entry == -1 {
            None
        } else {
            if entry < 0 {
                return Err(LegacySaveError::UnsupportedDiplomacyGrantFlags {
                    nation,
                    target,
                    entry,
                });
            }
            Some(DiplomacyGrant {
                amount: i32::from(entry & 0x3fff),
                recurring: entry & 0x4000 != 0,
            })
        };
    }
    Ok(grants)
}

pub(super) fn diplomacy_policies_from_retail_entries(
    entries: [i16; NATION_COUNT],
    nation: i16,
) -> Result<NationTable<Option<DiplomacyPolicy>>, LegacySaveError> {
    let mut policies = NationTable::default();
    for (target, entry) in entries.into_iter().enumerate() {
        policies[NationId::new(target as u8)] = match entry {
            -1 => None,
            _ => Some(diplomacy_policy_from_retail(entry, nation, target)?),
        };
    }
    Ok(policies)
}

pub(super) fn diplomacy_policy_from_retail(
    entry: i16,
    nation: i16,
    target: usize,
) -> Result<DiplomacyPolicy, LegacySaveError> {
    match entry {
        0x12d => Ok(DiplomacyPolicy::JoinEmpire),
        0x12e => Ok(DiplomacyPolicy::Alliance),
        0x12f => Ok(DiplomacyPolicy::NonAggressionPact),
        0x130 => Ok(DiplomacyPolicy::PeaceTreaty),
        0x131 => Ok(DiplomacyPolicy::DeclareWar),
        0x132 => Ok(DiplomacyPolicy::JoinEmpireWithWarEntanglements),
        0x133 => Ok(DiplomacyPolicy::BuildConsulate),
        0x134 => Ok(DiplomacyPolicy::BuildEmbassy),
        _ => Err(LegacySaveError::UnsupportedDiplomacyPolicy {
            nation,
            target,
            entry,
        }),
    }
}

pub(super) fn country_status_from_retail(value: i16) -> Result<CountryStatus, LegacySaveError> {
    match value {
        -1 => Ok(CountryStatus::Independent),
        100..=122 => Ok(CountryStatus::ProtectorateOf(NationId::new(
            (value - 100) as u8,
        ))),
        200..=222 => Ok(CountryStatus::ColonyOf(NationId::new((value - 200) as u8))),
        _ => Err(LegacySaveError::StateProjection(format!(
            "invalid encoded nation status {value}"
        ))),
    }
}

pub(super) fn owned_region_id_from_retail(value: i32) -> Result<ProvinceId, LegacySaveError> {
    u16::try_from(value)
        .ok()
        .and_then(ProvinceId::try_new)
        .ok_or_else(|| {
            LegacySaveError::StateProjection(format!(
                "owned-region province ID {value} is out of range"
            ))
        })
}

pub(super) fn province_state(
    index: usize,
    province: &LegacyProvince,
) -> Result<ProvinceState, LegacySaveError> {
    let count = usize::try_from(province.adjacent_region_count).map_err(|_| {
        LegacySaveError::StateProjection(format!(
            "province {index} has negative adjacency count {}",
            province.adjacent_region_count
        ))
    })?;
    if count > province.adjacent_region_ids.len() {
        return Err(LegacySaveError::StateProjection(format!(
            "province {index} has adjacency count {count}; maximum is {}",
            province.adjacent_region_ids.len()
        )));
    }
    let adjacency = province.adjacent_region_ids[..count]
        .iter()
        .copied()
        .map(|value| {
            u16::try_from(value)
                .ok()
                .and_then(ProvinceId::try_new)
                .ok_or_else(|| {
                    LegacySaveError::StateProjection(format!(
                        "province {index} adjacency ID {value} is out of range"
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let adjacency_anchor_tiles = province.adjacent_region_anchor_tiles[..count]
        .iter()
        .copied()
        .map(|value| {
            optional_tile_id(i32::from(value))?.ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "province {index} adjacency anchor tile is absent"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let linked_count = usize::try_from(province.linked_region_count).map_err(|_| {
        LegacySaveError::StateProjection(format!(
            "province {index} has negative linked-tile count {}",
            province.linked_region_count
        ))
    })?;
    if linked_count > province.linked_tile_indices.len() {
        return Err(LegacySaveError::StateProjection(format!(
            "province {index} has linked-tile count {linked_count}; maximum is {}",
            province.linked_tile_indices.len()
        )));
    }
    let linked_tiles = province.linked_tile_indices[..linked_count]
        .iter()
        .copied()
        .map(|value| {
            optional_tile_id(i32::from(value))?.ok_or_else(|| {
                LegacySaveError::StateProjection(format!("province {index} linked tile is absent"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let optional_owner = |value: i8, field: &str| {
        if value == -1 {
            return Ok(None);
        }
        u8::try_from(value)
            .ok()
            .and_then(NationId::try_new)
            .map(Some)
            .ok_or_else(|| {
                LegacySaveError::StateProjection(format!(
                    "province {index} {field} nation ID {value} is out of range"
                ))
            })
    };
    let region_class = match province.region_class {
        -1 => None,
        0..=23 => Some(province.region_class as u8),
        value => {
            return Err(LegacySaveError::StateProjection(format!(
                "province {index} region class {value} is out of range"
            )));
        }
    };
    let mut resource_development_by_type = ResourceTable::default();
    for (offset, amount) in province
        .resource_development_by_type
        .iter()
        .copied()
        .enumerate()
    {
        let resource = ResourceKind::from_index((ResourceKind::Food as usize + offset) as u8)
            .expect("province resource-development table spans food through arms");
        resource_development_by_type[resource] = amount;
    }
    if province.explored_by_nation_mask & 0x80 != 0 {
        return Err(LegacySaveError::StateProjection(format!(
            "province {index} exploration mask has unsupported upper bit set"
        )));
    }
    let explored_by_majors = MajorNationTable::from_fn(|nation| {
        province.explored_by_nation_mask & (1 << nation.get()) != 0
    });

    ProvinceState::new(
        optional_owner(province.owner_nation, "owner")?,
        optional_owner(province.former_owner_nation, "former-owner")?,
        province.development_stage,
        adjacency,
        adjacency_anchor_tiles,
        region_class,
        province.fort_level,
        optional_tile_id(i32::from(province.city_tile))?,
        province.last_turn_tick,
        optional_tile_id(i32::from(province.secondary_neighbor_tile))?,
        optional_tile_id(i32::from(province.primary_neighbor_tile))?,
        linked_tiles,
        resource_development_by_type,
        explored_by_majors,
        province.city_score,
        retail_boolean(
            province.navy_order_reachable,
            "province navy-order reachable flag",
        )?,
        province.resource_presence_mask,
        province.name.clone(),
    )
    .map_err(|error| {
        LegacySaveError::StateProjection(format!("province {index} is invalid: {error}"))
    })
}

pub(super) fn country_common(
    country: &LegacyCountryBase,
) -> Result<NationCommonState, LegacySaveError> {
    Ok(NationCommonState::from_parts(
        normalize_nation_display_name(&country.alternate_identity),
        country.status,
        country
            .owned_regions
            .iter()
            .copied()
            .map(owned_region_id_from_retail)
            .collect::<Result<Vec<_>, _>>()?,
        country.treasury,
        optional_tile_id(country.home_tile)?,
        NationTable::from_array(
            country
                .need_level_by_nation
                .map(|score| TradePolicyScore::new(i32::from(score))),
        ),
    ))
}
