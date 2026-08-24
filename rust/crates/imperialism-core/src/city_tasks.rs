//! Resumption of retail `TCityTask` and `TShipBuildingTask` records.

use crate::*;
use enum_map::Enum;

impl GameState {
    /// Retail `TTaskList::ProcessTasks`, preserving list order and processing tasks
    /// appended by an incomplete parent during the same pass.
    pub(crate) fn process_city_tasks(&mut self, nation: MajorNationId) {
        let mut tasks = std::mem::take(&mut self.nations.city_mut(nation).tasks);
        let mut ordinal = 0;
        while ordinal < tasks.len() {
            let complete = match tasks[ordinal].operation {
                CityTaskOperation::ProductionOrder => {
                    self.execute_city_production_task(nation, &mut tasks, ordinal)
                }
                CityTaskOperation::ShipConstruction { .. } => {
                    self.execute_ship_building_task(nation, &mut tasks, ordinal)
                }
            };
            if complete {
                tasks.remove(ordinal);
            } else {
                ordinal += 1;
            }
        }
        self.nations.city_mut(nation).tasks = tasks;
    }

    fn execute_city_production_task(
        &mut self,
        nation: MajorNationId,
        tasks: &mut Vec<CityTaskState>,
        ordinal: usize,
    ) -> bool {
        let slot = tasks[ordinal].order_slot;
        if (0..=6).contains(&slot) {
            let resource = ResourceKind::from_index(slot as u8).expect("basic resource slot");
            let transported =
                self.direct_transport(nation, resource, tasks[ordinal].requested_amount);
            tasks[ordinal].requested_amount -= transported;
            tasks[ordinal].remaining_attempts -= 1;
            return tasks[ordinal].requested_amount <= 0 || tasks[ordinal].remaining_attempts == 0;
        }

        let Some(order) = city_order_for_retail_slot(slot) else {
            return true;
        };
        let requested = tasks[ordinal].requested_amount;
        let mut limit = self.city_order_limit(nation, order);
        let mut headroom = limit.maximum - self.city_order_quantity(nation, order);
        if headroom < requested && limit.constraint == ProductionConstraint::Resources {
            for (resource, amount) in city_order_sheet(self, nation, order, requested) {
                self.direct_transport(nation, resource, amount);
            }
            limit = self.city_order_limit(nation, order);
            headroom = limit.maximum - self.city_order_quantity(nation, order);
        }

        if headroom >= requested {
            let quantity = self.city_order_quantity(nation, order) + requested;
            assert_eq!(
                self.set_city_order_quantity(nation, order, quantity),
                CityOrderUpdate::Applied
            );
            return true;
        }

        assert_eq!(
            self.set_city_order_quantity(nation, order, limit.maximum),
            CityOrderUpdate::Applied
        );
        tasks[ordinal].requested_amount -= headroom;
        match slot {
            8..=12 => self.incomplete_material_task(nation, order, tasks[ordinal].requested_amount),
            13..=16 => self.incomplete_goods_task(nation, tasks, ordinal, order),
            23..=24 => self.incomplete_training_task(nation, tasks, ordinal, order),
            25..=28 | 34..=38 => self.incomplete_land_unit_task(nation, tasks, ordinal, order),
            51 | 53..=59 => self.incomplete_capacity_task(nation, tasks, ordinal, order),
            _ => {}
        }
        tasks[ordinal].remaining_attempts -= 1;
        tasks[ordinal].remaining_attempts == 0
    }

    fn incomplete_training_task(
        &mut self,
        nation: MajorNationId,
        tasks: &mut Vec<CityTaskState>,
        ordinal: usize,
        order: CityOrderId,
    ) {
        let limit = self.city_order_limit(nation, order);
        if limit.constraint == ProductionConstraint::Resources {
            let amount = if tasks[ordinal].order_slot == 23 {
                tasks[ordinal].requested_amount
            } else {
                tasks[ordinal].requested_amount << 1
            };
            tasks.push(city_resource_task(ResourceKind::Paper, amount, 1));
            tasks[ordinal].already_queued = true;
        }
        if limit.constraint == ProductionConstraint::Treasury {
            self.nations.majors[&nation]
                .economy
                .foreign_trade
                .capability_flag_14 = 1;
        }
    }

    fn incomplete_capacity_task(
        &mut self,
        nation: MajorNationId,
        tasks: &mut Vec<CityTaskState>,
        ordinal: usize,
        order: CityOrderId,
    ) {
        let limit = self.city_order_limit(nation, order);
        if limit.constraint == ProductionConstraint::Resources && !tasks[ordinal].already_queued {
            let requested = tasks[ordinal].requested_amount;
            let city = self.nations.city(nation);
            let lumber = requested - city.stockpile[ResourceKind::Lumber];
            let steel = requested - city.stockpile[ResourceKind::Steel];
            let mut queued = false;
            if lumber > 0 {
                tasks.push(city_resource_task(ResourceKind::Lumber, lumber, 4));
                queued = true;
            }
            if steel > 0 {
                tasks.push(city_resource_task(ResourceKind::Steel, steel, 4));
                queued = true;
            }
            tasks[ordinal].already_queued = queued;
        }
        tasks[ordinal].remaining_attempts += 1;
    }

    fn incomplete_land_unit_task(
        &mut self,
        nation: MajorNationId,
        tasks: &mut Vec<CityTaskState>,
        ordinal: usize,
        order: CityOrderId,
    ) {
        let limit = self.city_order_limit(nation, order);
        if limit.constraint != ProductionConstraint::Resources || tasks[ordinal].already_queued {
            return;
        }
        let requested = tasks[ordinal].requested_amount;
        let mut queued = false;
        for (resource, amount) in city_order_sheet(self, nation, order, requested) {
            let deficit = amount - self.nations.city(nation).stockpile[resource];
            if deficit > 0 {
                tasks.push(city_resource_task(
                    resource,
                    deficit,
                    if resource == ResourceKind::Horses {
                        3
                    } else {
                        4
                    },
                ));
                queued = true;
            }
        }
        tasks[ordinal].already_queued = queued;
    }

    fn incomplete_material_task(
        &mut self,
        nation: MajorNationId,
        order: CityOrderId,
        requested: i16,
    ) {
        for (resource, amount) in city_order_sheet(self, nation, order, requested) {
            if let Some(commodity) = TradeCommodity::from_resource(resource) {
                self.nations.majors[&nation]
                    .economy
                    .foreign_trade
                    .purchase_priority[commodity] += amount;
            }
            self.nations
                .city_mut(nation)
                .transport_requests
                .push(CityTransportRequest {
                    resource,
                    requested_amount: amount,
                });
        }
    }

    fn incomplete_goods_task(
        &mut self,
        nation: MajorNationId,
        tasks: &mut Vec<CityTaskState>,
        ordinal: usize,
        order: CityOrderId,
    ) {
        let limit = self.city_order_limit(nation, order);
        if limit.constraint != ProductionConstraint::Resources || tasks[ordinal].already_queued {
            return;
        }
        let (resource, amount) =
            city_order_sheet(self, nation, order, tasks[ordinal].requested_amount)[0];
        tasks.push(city_resource_task(
            resource,
            amount,
            if resource == ResourceKind::Horses {
                3
            } else {
                4
            },
        ));
        tasks[ordinal].already_queued = true;
    }

    fn execute_ship_building_task(
        &mut self,
        nation: MajorNationId,
        tasks: &mut Vec<CityTaskState>,
        ordinal: usize,
    ) -> bool {
        let CityTaskOperation::ShipConstruction {
            ship_type,
            waiting_for_order_advance,
        } = tasks[ordinal].operation
        else {
            unreachable!()
        };
        let slot = ShipOrderSlot::MerchantEarlyPrimary;
        let current_type = self.nations.city(nation).orders.ships[slot].ship_type;
        if waiting_for_order_advance {
            if current_type != ship_type {
                return true;
            }
            tasks[ordinal].remaining_attempts += 1;
            return false;
        }

        let can_make = self
            .city_order_limit(nation, CityOrderId::Ship(slot))
            .maximum
            > self.city_order_quantity(nation, CityOrderId::Ship(slot));
        if can_make {
            if tasks[ordinal].remaining_attempts < 0 {
                tasks[ordinal].remaining_attempts = 1;
            }
            tasks[ordinal].remaining_attempts += 1;
            tasks[ordinal].operation = CityTaskOperation::ShipConstruction {
                ship_type,
                waiting_for_order_advance: true,
            };
            return false;
        }

        let costs = ship_order_costs(ship_type);
        let materials = self.nations.city(nation).orders.ships[slot].materials;
        let mut deficits = Vec::new();
        for (resource, required) in costs.iter() {
            let mut deficit = required - materials[resource];
            if deficit > 0 {
                let available = self.nations.city(nation).stockpile[resource].min(deficit);
                if available > 0 {
                    let city = self.nations.city_mut(nation);
                    city.stockpile.wrapping_add_and_verify(resource, -available);
                    city.orders.ships[slot].materials[resource] += available;
                    deficit -= available;
                }
            }
            if deficit > 0 {
                deficits.push((resource, deficit));
            }
        }
        if !tasks[ordinal].already_queued {
            for (resource, deficit) in deficits {
                tasks.push(city_resource_task(
                    resource,
                    deficit,
                    if resource == ResourceKind::Horses {
                        3
                    } else {
                        4
                    },
                ));
            }
            tasks[ordinal].remaining_attempts += 1;
            tasks[ordinal].already_queued = true;
            return false;
        }
        tasks[ordinal].remaining_attempts += 1;
        false
    }

    pub(crate) fn process_city_transport_requests(&mut self, nation: MajorNationId) {
        let requests = std::mem::take(&mut self.nations.city_mut(nation).transport_requests);
        let mut remaining = Vec::new();
        for mut request in requests {
            let transported =
                self.direct_transport(nation, request.resource, request.requested_amount);
            request.requested_amount -= transported;
            if request.requested_amount > 0
                && self.nations.majors[&nation].economy.capacities.transport
                    > self.nations.majors[&nation]
                        .economy
                        .capacities
                        .reserved_transport
            {
                remaining.push(request);
            }
        }
        self.nations.city_mut(nation).transport_requests = remaining;
    }
}

fn city_resource_task(
    resource: ResourceKind,
    amount: i16,
    remaining_attempts: i16,
) -> CityTaskState {
    CityTaskState {
        order_slot: i16::from(resource.retail()),
        remaining_attempts,
        requested_amount: amount,
        already_queued: false,
        operation: CityTaskOperation::ProductionOrder,
    }
}

fn city_order_for_retail_slot(slot: i16) -> Option<CityOrderId> {
    Some(match slot {
        7 => CityOrderId::FoodProcessing,
        8..=16 => CityOrderId::Item(ManufacturedItem::ALL[(slot - 8) as usize]),
        23 => CityOrderId::Training(TrainingLevel::Medium),
        24 => CityOrderId::Training(TrainingLevel::High),
        25..=31 => CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::from_usize(
            (slot - 25) as usize,
        )),
        32 => CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::Demolitionist),
        34..=42 => CityOrderId::CivilianRecruit(CivilianUnitKind::from_usize((slot - 34) as usize)),
        43..=50 => CityOrderId::Ship(ShipOrderSlot::from_usize((slot - 43) as usize)),
        51 => CityOrderId::TransportCapacity,
        52 => CityOrderId::PowerPlant,
        53..=59 => CityOrderId::Expansion(ExpandableFacility::ALL[(slot - 53) as usize]),
        60 => CityOrderId::PopulationGrowth,
        _ => return None,
    })
}

fn city_order_sheet(
    game: &GameState,
    nation: MajorNationId,
    order: CityOrderId,
    quantity: i16,
) -> Vec<(ResourceKind, i16)> {
    match order {
        CityOrderId::Item(item) => match item.inputs() {
            ItemInputs::Double(resource) => vec![(resource, quantity * 2)],
            ItemInputs::Both(primary, secondary) | ItemInputs::Either(primary, secondary) => {
                vec![(primary, quantity), (secondary, quantity)]
            }
        },
        CityOrderId::Training(TrainingLevel::Medium) => vec![(ResourceKind::Paper, quantity)],
        CityOrderId::Training(TrainingLevel::High) => vec![(ResourceKind::Paper, quantity * 2)],
        CityOrderId::CivilianRecruit(kind) => {
            recruitment_sheet(civilian_recruitment_spec(kind), quantity)
        }
        CityOrderId::MilitaryRecruit(category) => {
            let kind = game.nations.city(nation).orders.military_recruitment[category].unit_kind;
            recruitment_sheet(
                military_recruitment_spec(kind).expect("recruitable military task"),
                quantity,
            )
        }
        CityOrderId::Expansion(_) | CityOrderId::TransportCapacity => vec![
            (ResourceKind::Lumber, quantity),
            (ResourceKind::Steel, quantity),
        ],
        _ => Vec::new(),
    }
}

fn recruitment_sheet(spec: RecruitmentOrderSpec, quantity: i16) -> Vec<(ResourceKind, i16)> {
    let mut sheet = vec![(spec.primary.resource, spec.primary.per_unit() * quantity)];
    if let Some(secondary) = spec.secondary {
        sheet.push((secondary.resource, secondary.per_unit() * quantity));
    }
    sheet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    #[test]
    fn resource_task_retries_direct_transport_and_then_completes() {
        let mut game = game_state();
        let nation = MajorNationId::new(0);
        let economy = &mut game.nations.majors[&nation].economy;
        economy.capacities.transport = 2;
        economy.need_current_by_type[ResourceKind::Iron] = 4;
        game.nations
            .city_mut(nation)
            .tasks
            .push(city_resource_task(ResourceKind::Iron, 4, 4));

        game.process_city_tasks(nation);
        assert_eq!(game.nations.city(nation).stockpile[ResourceKind::Iron], 2);
        assert_eq!(game.nations.city(nation).tasks[0].requested_amount, 2);
        assert_eq!(game.nations.city(nation).tasks[0].remaining_attempts, 3);

        game.nations.majors[&nation].economy.capacities.transport = 4;
        game.process_city_tasks(nation);
        assert!(game.nations.city(nation).tasks.is_empty());
        assert_eq!(game.nations.city(nation).stockpile[ResourceKind::Iron], 4);
    }

    #[test]
    fn incomplete_goods_appends_and_executes_its_material_task_in_the_same_pass() {
        let mut game = game_state();
        let nation = MajorNationId::new(0);
        game.nations.city_mut(nation).production_accum[CityFacilitySlot::ClothingFactory] = 3;
        game.nations.city_mut(nation).tasks.push(CityTaskState {
            order_slot: 13,
            remaining_attempts: 4,
            requested_amount: 1,
            already_queued: false,
            operation: CityTaskOperation::ProductionOrder,
        });

        game.process_city_tasks(nation);

        let city = game.nations.city(nation);
        assert_eq!(city.tasks.len(), 2);
        assert!(city.tasks[0].already_queued);
        assert_eq!(
            city.tasks[1].order_slot,
            i16::from(ResourceKind::Fabric.retail())
        );
        assert_eq!(city.tasks[1].requested_amount, 2);
        assert_eq!(city.tasks[1].remaining_attempts, 3);
    }

    #[test]
    fn transport_request_is_removed_when_capacity_is_exhausted() {
        let mut game = game_state();
        let nation = MajorNationId::new(0);
        let economy = &mut game.nations.majors[&nation].economy;
        economy.capacities.transport = 1;
        economy.need_current_by_type[ResourceKind::Coal] = 4;
        game.nations.city_mut(nation).transport_requests = vec![CityTransportRequest {
            resource: ResourceKind::Coal,
            requested_amount: 3,
        }];

        game.process_city_transport_requests(nation);

        assert_eq!(game.nations.city(nation).stockpile[ResourceKind::Coal], 1);
        assert!(game.nations.city(nation).transport_requests.is_empty());
    }
}
