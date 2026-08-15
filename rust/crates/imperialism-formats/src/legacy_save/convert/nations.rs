use super::*;
use imperialism_core::*;

/// Mirrors the live, language-table-loaded `NormalizeRuntimeCredentialNameToken`
/// pass used by the Diplomacy map on `TCountry::identitySharedString1`.
fn normalize_nation_display_name(raw: &str) -> String {
    let mut characters = raw.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    if first == '(' || first.is_ascii_uppercase() {
        raw.to_owned()
    } else {
        characters.as_str().to_owned()
    }
}

impl LegacyCountryBase {
    pub(super) fn military_unit_states(&self, nation: NationId) -> Vec<MilitaryUnitState> {
        self.military_units
            .iter()
            .map(|unit| {
                let unit_type = MilitaryUnitKind::from_index(unit.unit_type as u8)
                    .expect("retail military unit type");
                let targets = optional_province_array(unit.order_target_tiles);
                let target_mirrors = optional_province_array(unit.order_target_mirrors);
                let target = optional_province_id(unit.order_target);
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
                MilitaryUnitState::new(
                    MilitaryUnitId::from_serialized(unit.persistent_id),
                    nation,
                    unit_type,
                    optional_province_id(unit.stationed_province),
                    order,
                    nation_id_from_retail_i16(unit.owner_nation),
                    unit.roster_id,
                    unit.registered != 0,
                    unit.name.clone(),
                    unit.strength,
                    unit.era,
                    unit.experience,
                    unit.battle_flags,
                )
            })
            .collect()
    }
}

pub(super) fn country_common(country: &LegacyCountryBase) -> NationCommonState {
    let mut common = NationCommonState::from_parts(
        normalize_nation_display_name(&country.alternate_identity),
        country_status_from_retail(country.encoded_country_status),
        country
            .owned_regions
            .iter()
            .copied()
            .map(super::map::owned_region_id_from_retail)
            .collect(),
        country.treasury,
        optional_tile_id(country.home_tile),
        NationTable::from_array(
            country
                .need_level_by_nation
                .map(|score| TradePolicyScore::new(i32::from(score))),
        ),
    );
    common.unit_name_ordinal_by_type = country.unit_name_ordinal_by_type;
    common.unit_name_counter = country.unit_name_counter;
    common
}

fn country_dto(
    common: &NationCommonState,
    military: &[MilitaryUnitState],
    identity: String,
    nation_slot: i16,
) -> LegacyCountryBase {
    LegacyCountryBase {
        identity: identity.clone(),
        alternate_identity: identity,
        nation_slot,
        encoded_country_status: country_status_to_retail(common.status()),
        unit_name_ordinal_by_type: common.unit_name_ordinal_by_type,
        unit_name_counter: common.unit_name_counter,
        treasury: common.treasury,
        home_tile: option_i32(common.home_tile.map(TileId::get)),
        overlay_anchor_tile: -1,
        need_level_by_nation: nation_i16_table(&common.trade_policy_by_nation, |score| {
            score.get() as i16
        }),
        military_units: military
            .iter()
            .map(super::units::military_unit_dto)
            .collect(),
        owned_regions: common
            .owned_regions()
            .iter()
            .map(|province| i32::from(province.get()))
            .collect(),
    }
}

fn country_status_to_retail(status: CountryStatus) -> i16 {
    match status {
        CountryStatus::Independent => -1,
        CountryStatus::ProtectorateOf(nation) => 100 + i16::from(nation.get()),
        CountryStatus::ColonyOf(nation) => 200 + i16::from(nation.get()),
    }
}

pub(super) fn country_status_from_retail(value: i16) -> CountryStatus {
    match value {
        -1 => CountryStatus::Independent,
        100..=122 => CountryStatus::ProtectorateOf(NationId::new((value - 100) as u8)),
        200..=222 => CountryStatus::ColonyOf(NationId::new((value - 200) as u8)),
        _ => panic!("unrecovered encoded nation status {value}"),
    }
}

pub(super) fn major_nation_dto(
    nation: &MajorNation,
    major_id: MajorNationId,
    military: &[MilitaryUnitState],
    civilians: &[CivilianUnitState],
    missions: &[MissionState],
    pending: &NationPendingWork,
    topology: MapTopology,
) -> LegacyMajorNationState {
    let power = LegacyGreatPowerState {
        country: country_dto(
            &nation.common,
            military,
            nation.common.display_name.clone(),
            i16::from(major_id.get()),
        ),
        prefix: great_power_prefix_dto(&nation.economy, pending),
        ministers: ministers_dto(&nation.economy),
        city: Some(super::city::city_dto(&nation.city)),
        post_city: super::city::post_city_dto(&nation.economy, &nation.towns, civilians, topology),
    };
    match &nation.auto {
        None => LegacyMajorNationState::Other(Box::new(power)),
        Some(auto) => LegacyMajorNationState::Auto(Box::new(LegacyAutoGreatPowerState {
            great_power: power,
            auto_prefix: auto_prefix_dto(auto),
            missions: missions
                .iter()
                .map(|mission| super::military::mission_dto(mission, military))
                .collect(),
        })),
    }
}

pub(super) fn minor_nation_dto(
    nation: &MinorNation,
    minor_id: MinorNationId,
    military: &[MilitaryUnitState],
) -> LegacyMinorState {
    LegacyMinorState {
        country: country_dto(
            &nation.common,
            military,
            nation.common.display_name.clone(),
            i16::from(minor_id.get()),
        ),
        need_current_by_type: resource_i16(&nation.trade.current_supply),
        trade_offers_by_resource: resource_i16(&nation.trade.offers),
        grant_amounts_by_resource: resource_i16(&nation.trade.grant_deltas),
        diplomacy_thresholds: [
            nation.trade.thresholds.primary_manufactured_price,
            nation.trade.thresholds.secondary_manufactured_price,
            nation.trade.thresholds.general_offer_price,
            nation.trade.thresholds.random_offer_price,
            nation.trade.thresholds.coal_offer_price,
            nation.trade.thresholds.iron_offer_price,
            nation.trade.thresholds.oil_offer_price,
        ],
        diplomacy_policy_fields: [
            optional_commodity_i16(nation.trade.primary_manufactured_request),
            optional_commodity_i16(nation.trade.secondary_manufactured_request),
            nation.trade.primary_request_fulfilled,
            nation.trade.secondary_request_fulfilled,
        ],
        diplomacy_save_fields: nation.consortium_members.map(|id| i16::from(id.get())),
        diplomacy_save_extension: resource_i16(&nation.trade.independent_resource_counts),
    }
}

fn great_power_prefix_dto(
    economy: &GreatPowerState,
    pending: &NationPendingWork,
) -> LegacyGreatPowerPrefix {
    LegacyGreatPowerPrefix {
        diplomacy_eligible: u8::from(economy.diplomacy_eligible),
        capacities: [
            economy.capacities.available_merchant,
            economy.capacities.trade_offer,
            economy.capacities.transport,
            economy.capacities.reserved_transport,
        ],
        grant_total_cost: economy.grant_total_cost,
        unfilled_trade_offer_count: economy.unfilled_trade_offer_count,
        diplomacy_policy_by_nation: nation_i16_table(
            &economy.diplomacy_policy_by_nation,
            |policy| policy.map(DiplomacyPolicy::retail).unwrap_or(-1),
        ),
        diplomacy_grant_by_nation: nation_i16_table(&economy.diplomacy_grants_by_nation, |grant| {
            grant.map(super::diplomacy::grant_to_retail).unwrap_or(-1)
        }),
        need_current_by_type: resource_i16(&economy.need_current_by_type),
        need_target_by_type: resource_i16(&economy.need_target_by_type),
        relation_delta_current: resource_i16(&economy.relation_delta_current),
        purchased_items_by_resource: resource_i16(&economy.purchased_items_by_resource),
        item_potentials: resource_i16(&economy.item_potentials),
        unfilled_trade_turns_by_resource: resource_i16(&economy.unfilled_trade_turns_by_resource),
        transported_items_by_resource: resource_i16(&economy.transported_items_by_resource),
        remembered_trade_offers_by_resource: resource_i16(
            &economy.remembered_trade_offers_by_resource,
        ),
        budget_pool_base: economy.budget_pool_base,
        budget_pool_delta: economy.budget_pool_delta,
        aid_allocation_by_minor_nation: std::array::from_fn(|index| {
            let id = MinorNationId::new(MajorNationId::COUNT + index as u8);
            resource_i32(&economy.aid_allocation_by_minor_nation[id])
        }),
        pending_action_status: std::array::from_fn(|index| {
            pending_status_to_retail(
                economy.pending_actions[PendingActionKind::from_usize(index)].status(),
            )
        }),
        pending_action_payload_by_action: std::array::from_fn(|index| {
            economy.pending_actions[PendingActionKind::from_usize(index)]
                .payload()
                .unwrap_or(-1)
        }),
        turn_event_queue: super::diplomacy::notices_to_records(&pending.turn_events),
        proposal_queue: super::diplomacy::proposals_to_records(&pending.proposals),
        diplomacy_tracked_slots: std::array::from_fn(|index| {
            super::diplomacy::deal_book_records(
                &economy.deal_book[TradeCommodity::from_usize(index)],
            )
        }),
    }
}

fn ministers_dto(economy: &GreatPowerState) -> LegacyGreatPowerMinisters {
    let trade = &economy.foreign_trade;
    let interior = economy.interior_civilian.as_ref();
    let mut scalar_fields = [0_i16; 7];
    match trade.interior_bid {
        Some(bid) => {
            scalar_fields[0] = trade_commodity_i16(bid.commodity);
            scalar_fields[1] = bid.amount;
        }
        None => scalar_fields[0] = -10,
    }
    scalar_fields[2] = trade.capability_flag_14;
    scalar_fields[3] = trade.capability_flag_16;
    scalar_fields[4] = trade.phase_counter;
    scalar_fields[5] = trade.refresh_interval;
    scalar_fields[6] = match trade.requested_ship {
        ShipType::Trader => 1,
        _ => 2,
    };
    let mut order_scalars = [0_i16; 8];
    order_scalars[1] = match economy.pending_ship {
        None => 0,
        Some(ShipType::Trader) => 1,
        Some(ShipType::Indiaman) => 2,
        _ => 0,
    };
    order_scalars[3] = match interior.pending_recruitment() {
        None => -1,
        Some(kind) => kind.into_usize() as i16,
    };
    order_scalars[6] = option_i16(interior.railhead_target().map(TileId::get));
    let mut order_metrics = [0_i16; 61];
    let resources = resource_i16(interior.resource_order_metrics());
    order_metrics[..RESOURCE_KIND_COUNT].copy_from_slice(&resources);
    let demand = interior.city_order_demand();
    for (index, value) in demand.training().values().copied().enumerate() {
        order_metrics[23 + index] = value;
    }
    for (index, value) in demand.military_recruitment().values().copied().enumerate() {
        order_metrics[25 + index] = value;
    }
    for (index, value) in demand.civilian_recruitment().values().copied().enumerate() {
        order_metrics[34 + index] = value;
    }
    for (index, value) in demand.ships().values().copied().enumerate() {
        order_metrics[43 + index] = value;
    }
    order_metrics[51] = demand.transport_capacity();
    order_metrics[53..60].copy_from_slice(demand.expansions().as_array());
    order_metrics[60] = demand.population_growth();
    let pending_development = interior
        .pending_development_actions()
        .iter()
        .map(|action| match *action {
            PendingDevelopmentAction::LandUnit { unit_type } => unit_type.into_usize() as i32,
            PendingDevelopmentAction::Industry { slot } => i32::from(slot as u8) + 30,
        })
        .collect();
    LegacyGreatPowerMinisters {
        foreign: Some(LegacyForeignMinisterState {
            skill_index: economy.foreign_minister_skill_index,
            scalar_fields,
            purchase_priority_by_resource: enum_i16(&trade.purchase_priority),
            preferred_resource_slots: trade.preferred_resources.map(optional_commodity_i16),
            status_flag: 0,
            trade_partner_enabled: trade.trade_partner_enabled,
            development_grant_by_nation: *economy.development_grant_by_nation.as_array(),
            bill_order_flag: matches!(
                economy.foreign_minister_personality,
                ForeignMinisterPersonality::Bill
            )
            .then_some(0),
        }),
        interior: Some(LegacyInteriorMinisterState {
            skill_index: 0,
            scalar_prefix: [0; 4],
            trailing_table: [0; 7],
            order_scalars,
            order_metrics,
            deferred_labor_shortfall: interior.deferred_labor_shortfall(),
            order_short_table: *interior.production_deficit_by_slot().as_array(),
            order_type_tables: [
                resource_i16(interior.railhead_priority_by_resource()),
                resource_i16(interior.exterior_need_by_resource()),
                resource_i16(interior.historical_need_by_resource()),
            ],
            temporarily_reserved_ship_arms: interior.temporarily_reserved_ship_arms(),
            integer_lists: [Vec::new(), Vec::new(), pending_development],
            civilian_order_demand_by_resource: resource_i16(
                interior.civilian_order_demand_by_resource(),
            ),
        }),
        defense: Some(LegacyDefenseMinisterState {
            skill_index: economy.defense_minister_skill_index,
            scalar_fields: [0; 2],
            recruit_order_count_by_type: [0; 30],
            order_weight_by_type: [0; 30],
            thresholds: [0; 4],
        }),
    }
}

fn auto_prefix_dto(auto: &AutoGreatPowerState) -> LegacyAutoGreatPowerPrefix {
    let mut map_node_state_flags = [0_u8; super::super::PROVINCE_COUNT];
    for (index, flag) in map_node_state_flags.iter_mut().enumerate() {
        *flag = ai_target_to_retail(auto.province_targets[ProvinceId::new(index as u16)]);
    }
    let mut port_zone_state_flags = [0_u8; AI_ZONE_TARGET_CAPACITY];
    for (index, target) in auto.zone_targets.iter().enumerate() {
        if index < AI_ZONE_TARGET_CAPACITY {
            port_zone_state_flags[index] = ai_target_to_retail(*target);
        }
    }
    LegacyAutoGreatPowerPrefix {
        action_metric_by_quarter: enum_i16(&auto.trade.temporary_processed_stock),
        map_node_state_flags,
        port_zone_state_flags,
    }
}

pub(super) fn great_power_state(
    nation: &LegacyGreatPowerState,
    foreign_minister_personality: ForeignMinisterPersonality,
) -> GreatPowerState {
    let prefix = &nation.prefix;
    let post = &nation.post_city;
    let foreign_minister = nation
        .ministers
        .foreign
        .as_ref()
        .expect("retail great power has a foreign minister");
    let defense_minister = nation
        .ministers
        .defense
        .as_ref()
        .expect("retail great power has a defense minister");
    let interior_minister = nation
        .ministers
        .interior
        .as_ref()
        .expect("retail great power has an interior minister");
    GreatPowerState {
        diplomacy_eligible: prefix.diplomacy_eligible != 0,
        foreign_minister_personality,
        foreign_minister_skill_index: foreign_minister.skill_index,
        foreign_trade: foreign_trade_state(foreign_minister),
        development_grant_by_nation: NationTable::from_array(
            foreign_minister.development_grant_by_nation,
        ),
        defense_minister_skill_index: defense_minister.skill_index,
        capacities: NationCapacities::from_array(prefix.capacities),
        grant_total_cost: prefix.grant_total_cost,
        unfilled_trade_offer_count: prefix.unfilled_trade_offer_count,
        diplomacy_policy_by_nation: super::diplomacy::diplomacy_policies_from_retail_entries(
            prefix.diplomacy_policy_by_nation,
        ),
        diplomacy_grants_by_nation: super::diplomacy::diplomacy_grants_from_retail_entries(
            prefix.diplomacy_grant_by_nation,
        ),
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
        deal_book: super::diplomacy::deal_book_state(&prefix.diplomacy_tracked_slots),
        pending_ship: pending_ship(interior_minister),
        interior_civilian: Box::new(interior_civilian_state(interior_minister)),
        aid_allocation_by_minor_nation: MinorNationTable::from_array(
            prefix
                .aid_allocation_by_minor_nation
                .map(ResourceTable::from_array),
        ),
        budget_pool_base: prefix.budget_pool_base,
        budget_pool_delta: prefix.budget_pool_delta,
        special_resource_trade_balance: post.special_resource_trade_balance,
        // scenarioInitFlag is constructed as zero and is not part of the save stream.
        scenario_initialized: false,
        turn_finished: post.turn_finished_flag != 0,
        pending_actions: PendingActionTable::from_array(std::array::from_fn(|action| {
            pending_action_from_retail(
                prefix.pending_action_status[action],
                prefix.pending_action_payload_by_action[action],
            )
        })),
        candidate_nation_flags: NationTable::from_array(post.candidate_nation_flags),
        colony_boycott_flags: NationTable::from_array(post.colony_boycott_flags),
        diplomacy_budget_base: post.diplomacy_budget_base,
        escalation_counter: i16::from(post.escalation_counter),
        pending_commitment_cost: post.pending_commitment_cost,
        pressure_counter: i16::from(post.pressure_counter),
        army_movement_budget: post.army_movement_budget,
        aid_allocation_total: post.aid_allocation_total,
        military_expenses: post.military_expenses,
    }
}

fn interior_civilian_state(minister: &LegacyInteriorMinisterState) -> InteriorCivilianState {
    let pending_recruitment = match minister.order_scalars[3] {
        -1 => None,
        value => Some(
            CivilianUnitKind::from_index(value as u8)
                .expect("retail pending civilian recruitment kind"),
        ),
    };
    let resource_order_metrics =
        ResourceTable::from_array(std::array::from_fn(|index| minister.order_metrics[index]));
    let city_order_demand = AiCityOrderDemand::from_parts(
        TrainingOrderTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[23 + index]
        })),
        MilitaryRecruitOrderTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[25 + index]
        })),
        CivilianUnitTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[34 + index]
        })),
        ShipOrderTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[43 + index]
        })),
        minister.order_metrics[51],
        ExpansionOrderTable::from_array(std::array::from_fn(|index| {
            minister.order_metrics[53 + index]
        })),
        minister.order_metrics[60],
    );
    let pending_development_actions = minister.integer_lists[2]
        .iter()
        .map(|&value| match value {
            0..=29 => PendingDevelopmentAction::LandUnit {
                unit_type: MilitaryUnitKind::from_index(value as u8)
                    .expect("retail pending military development action"),
            },
            30..=43 => PendingDevelopmentAction::Industry {
                slot: CityFacilitySlot::from_index((value - 30) as u8)
                    .expect("retail pending industry development action"),
            },
            _ => panic!("unrecovered pending development action {value}"),
        })
        .collect();
    InteriorCivilianState::from_parts(
        pending_recruitment,
        optional_tile_id(i32::from(minister.order_scalars[6])),
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
    )
}

fn pending_action_from_retail(status: i8, payload: i16) -> PendingActionState {
    PendingActionState::new(
        PendingActionStatus::from_retail(status),
        (payload != -1).then_some(payload),
    )
}

fn pending_status_to_retail(status: PendingActionStatus) -> i8 {
    status.retail()
}

fn foreign_trade_state(minister: &LegacyForeignMinisterState) -> ForeignTradeState {
    let interior_bid =
        optional_trade_commodity_from_retail(minister.scalar_fields[0]).map(|commodity| {
            ForeignTradeBid {
                commodity,
                amount: minister.scalar_fields[1],
            }
        });
    let requested_ship = match minister.scalar_fields[6] {
        1 => ShipType::Trader,
        2 => ShipType::Indiaman,
        value => panic!("unrecovered foreign-minister ship order kind {value}"),
    };
    let preferred_resources = minister
        .preferred_resource_slots
        .map(optional_trade_commodity_from_retail);
    ForeignTradeState {
        interior_bid,
        phase_counter: minister.scalar_fields[4],
        refresh_interval: minister.scalar_fields[5],
        requested_ship,
        purchase_priority: TradeCommodityTable::from_array(minister.purchase_priority_by_resource),
        preferred_resources,
        capability_flag_14: minister.scalar_fields[2],
        capability_flag_16: minister.scalar_fields[3],
        trade_partner_enabled: minister.trade_partner_enabled,
    }
}

fn pending_ship(minister: &LegacyInteriorMinisterState) -> Option<ShipType> {
    match minister.order_scalars[1] {
        0 => None,
        1 => Some(ShipType::Trader),
        2 => Some(ShipType::Indiaman),
        value => panic!("unrecovered pending ship type {value}"),
    }
}

pub(super) fn minor_trade_state(nation: &LegacyMinorState) -> MinorTradeState {
    MinorTradeState {
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
        primary_manufactured_request: optional_trade_commodity_from_retail(
            nation.diplomacy_policy_fields[0],
        ),
        secondary_manufactured_request: optional_trade_commodity_from_retail(
            nation.diplomacy_policy_fields[1],
        ),
        primary_request_fulfilled: nation.diplomacy_policy_fields[2],
        secondary_request_fulfilled: nation.diplomacy_policy_fields[3],
        independent_resource_counts: ResourceTable::from_array(nation.diplomacy_save_extension),
    }
}

pub(super) fn foreign_minister_personality(
    nation: &LegacyMajorNationState,
    setup_policy_id: i16,
) -> ForeignMinisterPersonality {
    if !matches!(nation, LegacyMajorNationState::Auto(_)) {
        return ForeignMinisterPersonality::Base;
    }
    match setup_policy_id {
        0 => ForeignMinisterPersonality::Arms,
        1 => ForeignMinisterPersonality::Trader,
        2 => ForeignMinisterPersonality::Textile,
        3 => ForeignMinisterPersonality::Diplomat,
        4 => ForeignMinisterPersonality::Bill,
        5 => ForeignMinisterPersonality::Ted,
        _ => panic!("unrecovered AI foreign-minister setup policy {setup_policy_id}"),
    }
}

pub(super) fn foreign_policy_id(personality: ForeignMinisterPersonality) -> i16 {
    match personality {
        ForeignMinisterPersonality::Base | ForeignMinisterPersonality::Arms => 0,
        ForeignMinisterPersonality::Trader => 1,
        ForeignMinisterPersonality::Textile => 2,
        ForeignMinisterPersonality::Diplomat => 3,
        ForeignMinisterPersonality::Bill => 4,
        ForeignMinisterPersonality::Ted => 5,
    }
}

pub(super) fn ai_zone_targets(
    flags: &[u8; AI_ZONE_TARGET_CAPACITY],
    live_count: usize,
) -> Vec<AiTargetState> {
    flags[..live_count]
        .iter()
        .copied()
        .map(ai_target_state)
        .collect()
}

pub(super) fn ai_province_targets(flags: &[u8; PROVINCE_COUNT]) -> ProvinceTable<AiTargetState> {
    ProvinceTable::from_array(std::array::from_fn(|index| ai_target_state(flags[index])))
}

fn ai_target_state(value: u8) -> AiTargetState {
    match value {
        0 => AiTargetState::Unmarked,
        1 => AiTargetState::Candidate,
        2 => AiTargetState::MissionQueued,
        _ => panic!("unrecovered AI target state {value}"),
    }
}

fn ai_target_to_retail(target: AiTargetState) -> u8 {
    match target {
        AiTargetState::Unmarked => 0,
        AiTargetState::Candidate => 1,
        AiTargetState::MissionQueued => 2,
    }
}
