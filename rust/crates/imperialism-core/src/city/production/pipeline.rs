//! End-of-phase city production resolution.

use crate::*;
use super::*;

impl GameState {
    /// Resolves the city's retained production orders and starts its next
    /// production cycle. This is retail `TCity::EndCityPhase`; unit objects are
    /// committed after the city borrow is released.
    pub(crate) fn end_city_phase(&mut self, nation: MajorNationId) {
        const ITEM_OUTPUTS: [ManufacturedItem; 9] = ManufacturedItem::ALL;
        const CIVILIAN_KINDS: [CivilianUnitKind; 9] = [
            CivilianUnitKind::Miner,
            CivilianUnitKind::Prospector,
            CivilianUnitKind::Farmer,
            CivilianUnitKind::Forester,
            CivilianUnitKind::Engineer,
            CivilianUnitKind::Rancher,
            CivilianUnitKind::Fisherman,
            CivilianUnitKind::Developer,
            CivilianUnitKind::Driller,
        ];
        const EXPANSION_SLOTS: [ExpandableFacility; 7] = ExpandableFacility::ALL;

        let owned_region_count =
            self.nations
                .owned_region_count(nation.nation())
                .expect("city production requires a present major nation") as i32;
        let mut produced_civilians = CivilianUnitTable::default();
        {
            let MajorNation { economy, city, .. } = &mut self.nations.majors[nation];
            let mut orders = std::mem::take(&mut city.orders);

            city.phase_counter += 1;
            if matches!(economy.controller, MajorNationController::Computer) {
                for resource in all_resources() {
                    city.adjust_stock(resource, city.reserved_by_type[resource]);
                }
            }
            for resource in all_resources() {
                city.adjust_stock(resource, city.consumed_production_input_by_type[resource]);
                city.consumed_production_input_by_type[resource] = 0;
            }

            let previous_production_score = city.rolling_item_production_score;
            city.rolling_item_production_score = 0;
            produce_food_processing(&mut orders.food_processing, city);
            for output in ITEM_OUTPUTS {
                let state = orders.items[output.resource()]
                    .as_mut()
                    .expect("item order exists for every retail recipe");
                produce_item(
                    state,
                    city,
                    item_order_spec(output),
                );
            }
            produce_training(
                TrainingLevel::Medium,
                &mut orders.training[TrainingLevel::Medium],
                city,
                economy,
            );
            produce_training(
                TrainingLevel::High,
                &mut orders.training[TrainingLevel::High],
                city,
                economy,
            );
            city.rolling_item_production_score =
                previous_production_score * 9 / 10 + city.rolling_item_production_score * 10;

            for kind in CIVILIAN_KINDS {
                let progress = &mut orders.civilian_recruitment[kind];
                produced_civilians[kind] = progress.quantity;
                progress.quantity = 0;
            }

            let transport_spec = transport_capacity_order_spec();
            produce_capacity(
                &mut orders.transport_capacity,
                city,
                economy,
                CapacityTarget::Transport,
                transport_spec.primary,
                transport_spec.secondary,
                owned_region_count,
            );
            produce_power_plant(&orders.power_plant);
            for facility in EXPANSION_SLOTS {
                let spec = expansion_order_spec(facility);
                produce_expansion(
                    orders.expansions[facility.slot()]
                        .as_mut()
                        .expect("expansion order exists for every expandable slot"),
                    city,
                    economy,
                    ExpansionTarget::Production(facility.slot()),
                    spec.primary,
                    spec.secondary,
                    owned_region_count,
                );
            }
            produce_population_growth(
                &mut orders.population_growth,
                city,
                economy,
                owned_region_count,
            );

            if city.power_plant_upgrade_queued {
                city.power_plant_upgrade_queued = false;
                city.production_accum[CityFacilitySlot::PowerPlant] +=
                    999 - city.production_orders[CityFacilitySlot::PowerPlant];
                city.production_orders[CityFacilitySlot::PowerPlant] = 999;
            }
            for resource in all_resources() {
                if city.stockpile[resource] > 9_999 {
                    city.stockpile.set_nonnegative(resource, 9_999);
                }
            }

            city.power_available = 0;
            city.start_production_phase();
            restock_power_plant(&mut orders.power_plant, city);
            for output in ITEM_OUTPUTS {
                let state = orders.items[output.resource()]
                    .as_mut()
                    .expect("item order exists for every retail recipe");
                restock_item(
                    state,
                    city,
                    item_order_spec(output),
                );
            }
            city.production_accum[CityFacilitySlot::RegionalPopulation] =
                retail_region_capacity(economy, owned_region_count);
            city.production_accum[CityFacilitySlot::Transport] =
                city.production_orders[CityFacilitySlot::Transport];
            city.orders = orders;
        }

        for (kind, quantity) in produced_civilians {
            self.produce_civilian_recruits(nation, kind, quantity);
        }
    }

    /// Resolves the Armory and Shipyard orders after potential calculation.
    pub(crate) fn produce_city_units(&mut self, nation: MajorNationId) {
        const MILITARY_CATEGORIES: [MilitaryRecruitmentCategory; 8] = [
            MilitaryRecruitmentCategory::LightInfantry,
            MilitaryRecruitmentCategory::RegularInfantry,
            MilitaryRecruitmentCategory::HeavyInfantry,
            MilitaryRecruitmentCategory::LightCavalry,
            MilitaryRecruitmentCategory::HeavyCavalry,
            MilitaryRecruitmentCategory::LightArtillery,
            MilitaryRecruitmentCategory::HeavyArtillery,
            MilitaryRecruitmentCategory::Demolitionist,
        ];
        const CIVILIAN_KINDS: [CivilianUnitKind; 9] = [
            CivilianUnitKind::Miner,
            CivilianUnitKind::Prospector,
            CivilianUnitKind::Farmer,
            CivilianUnitKind::Forester,
            CivilianUnitKind::Engineer,
            CivilianUnitKind::Rancher,
            CivilianUnitKind::Fisherman,
            CivilianUnitKind::Developer,
            CivilianUnitKind::Driller,
        ];
        const SHIP_SLOTS: [ShipOrderSlot; 8] = [
            ShipOrderSlot::MerchantEarlyPrimary,
            ShipOrderSlot::MerchantEarlySecondary,
            ShipOrderSlot::MerchantAdvancedPrimary,
            ShipOrderSlot::MerchantAdvancedSecondary,
            ShipOrderSlot::WarshipEarlyPrimary,
            ShipOrderSlot::WarshipEarlySecondary,
            ShipOrderSlot::WarshipAdvancedPrimary,
            ShipOrderSlot::WarshipAdvancedSecondary,
        ];

        let mut military = Vec::new();
        let mut civilians = Vec::new();
        {
            let city = self.nations.city_mut(nation);
            for category in MILITARY_CATEGORIES {
                let order = &mut city.orders.military_recruitment[category];
                military.push((order.unit_kind, order.progress.quantity));
                order.progress.quantity = 0;
            }
            for kind in CIVILIAN_KINDS {
                let order = &mut city.orders.civilian_recruitment[kind];
                civilians.push((kind, order.quantity));
                order.quantity = 0;
            }
            for slot in SHIP_SLOTS {
                let order = &mut city.orders.ships[slot];
                let quantity = order.progress.quantity;
                if order.ship_type != ShipType::NoShip && quantity != 0 {
                    city.ship_order_count_by_type[order.ship_type] += quantity;
                    order.progress.quantity = 0;
                    order.progress.tracking_by_resource = ResourceTable::default();
                }
            }
        }

        for (unit_kind, quantity) in military {
            self.produce_military_recruits(nation, unit_kind, quantity);
        }
        for (unit_kind, quantity) in civilians {
            self.produce_civilian_recruits(nation, unit_kind, quantity);
        }
    }
}

pub(crate) fn apply_resource_cost(city: &mut CityState, cost: ResourceCost, quantity: i16) {
    let change = cost.per_unit() * quantity;
    city.adjust_stock(cost.resource, -change);
}

#[allow(dead_code)]
pub(crate) fn set_pending_action(owner: &mut GreatPowerState, action: PendingActionKind, payload: i16) {
    owner.pending_actions[action].queue(payload);
}
