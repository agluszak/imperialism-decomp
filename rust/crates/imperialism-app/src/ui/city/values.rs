use super::*;

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(in crate::ui::city) fn sync_city_values(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<Entity, With<CityScreenNeedsSync>>,
    dialogs: Query<
        (Entity, &CityBuildingDialog, Option<&ArmorySelection>),
        With<CityDialogNeedsSync>,
    >,
    university_selections: Query<&UniversitySelection>,
    university_rows: Query<&UniversityRowChoice>,
    shipyard_selections: Query<&ShipyardSelection>,
    shipyard_rows: Query<&ShipyardRowChoice>,
    mut values: Query<
        (
            &CityValueBinding,
            Option<&RetailNumberTemplate>,
            Option<&UniversityWarningValue>,
            Option<&mut TextColor>,
            &mut Text,
            &mut Visibility,
        ),
        Without<CityExpansionIndicator>,
    >,
    amount_bars: Query<&CityIndustryAmountBar>,
    mut amount_nodes: Query<&mut Node>,
    mut indicators: Query<(&CityExpansionIndicator, &mut Visibility), Without<CityValueBinding>>,
    mut detail_images: Query<
        (
            Option<&UniversityPreview>,
            Option<&UniversityRequirementIcon>,
            Option<&ShipyardDetailPicture>,
            Option<&ShipyardMaterialPicture>,
            &mut ImageNode,
            &mut Visibility,
        ),
        (
            Without<Text>,
            Without<CityValueBinding>,
            Without<CityExpansionIndicator>,
            Or<(
                With<UniversityPreview>,
                With<UniversityRequirementIcon>,
                With<ShipyardDetailPicture>,
                With<ShipyardMaterialPicture>,
            )>,
        ),
    >,
    mut detail_texts: Query<
        (
            Option<&UniversityRequirementValue>,
            Option<&UniversityTierLabel>,
            Option<&ShipyardMaterialAmount>,
            Option<&ShipyardStatValue>,
            &mut Text,
            &mut TextColor,
            &mut Visibility,
        ),
        (
            Without<ImageNode>,
            Without<CityValueBinding>,
            Without<CityExpansionIndicator>,
            Or<(
                With<UniversityRequirementValue>,
                With<UniversityTierLabel>,
                With<ShipyardMaterialAmount>,
                With<ShipyardStatValue>,
            )>,
        ),
    >,
) {
    if screens.is_empty() && dialogs.is_empty() {
        return;
    }

    let screen_nation = MajorNationId::from_nation(session.0.turn().active_nation);
    let mut dialog_states = Vec::new();
    for (root, dialog, armory_selection) in &dialogs {
        let mut order_views = Vec::new();
        let bindings = dialog_orders(dialog.slot);
        assert!(
            !bindings.is_empty() || dialog.slot == CityFacilitySlot::Warehouse,
            "only the retail Warehouse dialog has no city orders"
        );
        if !matches!(
            dialog.slot,
            CityFacilitySlot::Armory | CityFacilitySlot::University | CityFacilitySlot::Shipyard
        ) {
            for binding in bindings {
                let view = session.0.city_order_status(dialog.nation, binding.order);
                order_views.push((binding.order, view));
            }
        }
        dialog_states.push((
            root,
            dialog.nation,
            order_views,
            armory_selection.map(|selection| selection.category),
        ));
    }

    for (binding, number_template, university_warning, mut text_color, mut text, mut visibility) in
        &mut values
    {
        let (nation, order_views, armory_selection): (
            MajorNationId,
            &[(CityOrderId, CityOrderStatus)],
            Option<MilitaryRecruitmentCategory>,
        ) = match binding.dialog {
            Some(root) => {
                let Some((_, nation, order_views, armory_selection)) = dialog_states
                    .iter()
                    .find(|(candidate, _, _, _)| *candidate == root)
                else {
                    continue;
                };
                (*nation, order_views, *armory_selection)
            }
            None => {
                let Some(nation) = screen_nation else {
                    continue;
                };
                (nation, &[], None)
            }
        };
        let major = session.0.nations().major(nation);
        let city = major.city();
        let labor = city.population.baseline_labor();
        let labor_available = city.population.strength();
        let armory_order =
            armory_selection.map(|category| &city.orders.military_recruitment[category]);
        let armory_spec = armory_order.map(|order| {
            military_recruitment_spec(order.unit_kind)
                .expect("armory row has a recruitable retail unit recipe")
        });
        let university_selection = binding
            .dialog
            .and_then(|root| university_selections.get(root).ok());
        let university_row = binding.dialog.and_then(|root| {
            let selection = university_selection?;
            university_rows
                .iter()
                .find(|row| row.dialog == root && row.kind == selection.kind)
        });
        let university_spec =
            university_selection.map(|selection| civilian_recruitment_spec(selection.kind));
        if let (Some(warning), Some(color)) = (university_warning, text_color.as_deref_mut()) {
            let Some(selection) = university_selection else {
                continue;
            };
            assert_eq!(
                binding.dialog,
                Some(warning.dialog),
                "University warning belongs to its dialog"
            );
            let spec = civilian_recruitment_spec(selection.kind);
            let insufficient = match warning.kind {
                UniversityWarningKind::Paper => {
                    city.stockpile[spec.primary.resource] < spec.primary.per_unit()
                }
                UniversityWarningKind::Workforce => {
                    let production = city.population.production_labor();
                    production.high.min(labor_available / 4) < 1
                }
                UniversityWarningKind::Treasury => {
                    major.common().treasury < i32::from(spec.cash_per_unit)
                }
            };
            color.0 = if insufficient {
                warning.warning_color
            } else {
                warning.normal_color
            };
        }
        let shipyard_selection = binding
            .dialog
            .and_then(|root| shipyard_selections.get(root).ok());
        let shipyard_row = binding.dialog.and_then(|root| {
            let selection = shipyard_selection?;
            shipyard_rows
                .iter()
                .find(|row| row.dialog == root && row.slot == selection.slot)
        });
        let value = match binding.value {
            CityValue::LaborLow => labor.low,
            CityValue::LaborMedium => labor.medium,
            CityValue::LaborHigh => labor.high,
            CityValue::LaborAvailable => labor_available,
            CityValue::PowerAvailable => city.power_available,
            CityValue::Stock(resource) => city.stockpile[resource],
            CityValue::WarehouseFishAndLivestock => {
                city.stockpile[ResourceKind::Fish] + city.stockpile[ResourceKind::Livestock]
            }
            CityValue::PredictedNeed(resource) => city.population.predicted_need(resource),
            CityValue::Treasury => {
                text.0 = format_currency(major.common().treasury);
                continue;
            }
            CityValue::OrderQuantity(order) => {
                let Some((_, view)) = order_views
                    .iter()
                    .find(|(candidate, _)| *candidate == order)
                else {
                    continue;
                };
                view.quantity
            }
            CityValue::ArmoryOrderQuantity(category) => {
                city.orders.military_recruitment[category].progress.quantity
            }
            CityValue::UniversityOrderQuantity(kind) => {
                city.orders.civilian_recruitment[kind].quantity
            }
            CityValue::ShipyardOrderQuantity(slot) => city.orders.ships[slot].progress.quantity,
            CityValue::LaborIndicator => {
                text.0 = "X".to_owned();
                *visibility = if labor_available >= 2 {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::StockIndicator(resource, minimum) => {
                text.0 = "X".to_owned();
                *visibility = if city.stockpile[resource] < minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::AvailableStockIndicator(resource, minimum) => {
                text.0 = "X".to_owned();
                *visibility = if city.stockpile[resource] >= minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::AvailableCombinedStockIndicator(first, second, minimum) => {
                text.0 = "X".to_owned();
                *visibility = if city.stockpile[first] + city.stockpile[second] >= minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::AvailableBudgetIndicator(minimum) => {
                text.0 = "X".to_owned();
                *visibility = if major
                    .economy()
                    .available_diplomacy_budget(major.common().treasury)
                    >= minimum
                {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::TrainingLaborIndicator(level) => {
                let production = city.population.production_labor();
                let available = match level {
                    TrainingLevel::Medium => production.low.min(labor_available),
                    TrainingLevel::High => production.medium.min(labor_available / 2),
                };
                text.0 = "X".to_owned();
                *visibility = if available != 0 {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
                continue;
            }
            CityValue::BuildingCapacity(slot) => city.production_orders[slot],
            CityValue::RegionalCapacity => city.building_type(
                CityFacilitySlot::RegionalPopulation,
                major.economy(),
                major.common().owned_region_count() as i32,
            ),
            CityValue::OwnedRegionCount => major.common().owned_region_count() as i16,
            CityValue::ArmoryUnitKind => {
                let Some(order) = armory_order else {
                    continue;
                };
                text.0 = format!("{:?}", order.unit_kind);
                continue;
            }
            CityValue::ArmoryWorkforceCost => 1,
            CityValue::ArmoryPrimaryCost => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                spec.primary.per_unit()
            }
            CityValue::ArmorySecondaryCost => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                let Some(secondary) = spec.secondary else {
                    text.0.clear();
                    *visibility = Visibility::Hidden;
                    continue;
                };
                *visibility = Visibility::Visible;
                secondary.per_unit()
            }
            CityValue::ArmoryCashCost => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                text.0 = format_currency(i32::from(spec.cash_per_unit));
                continue;
            }
            CityValue::ArmoryWorkforceAvailable => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                let production = city.population.production_labor();
                let (available, strength_divisor) = match spec.workforce {
                    SkillBand::Low => (production.low, 1),
                    SkillBand::Medium => (production.medium, 2),
                    SkillBand::High => (production.high, 4),
                };
                available.min(labor_available / strength_divisor)
            }
            CityValue::ArmoryPrimaryAvailable => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                city.stockpile[spec.primary.resource]
            }
            CityValue::ArmorySecondaryAvailable => {
                let Some(spec) = armory_spec else {
                    continue;
                };
                let Some(secondary) = spec.secondary else {
                    text.0.clear();
                    *visibility = Visibility::Hidden;
                    continue;
                };
                *visibility = Visibility::Visible;
                city.stockpile[secondary.resource]
            }
            CityValue::ArmoryTreasuryAvailable => {
                text.0 = format_currency(major.common().treasury);
                continue;
            }
            CityValue::UniversityUnitName => {
                let Some(row) = university_row else {
                    continue;
                };
                text.0.clone_from(&row.unit_name);
                continue;
            }
            CityValue::UniversityDescription => {
                let Some(row) = university_row else {
                    continue;
                };
                text.0.clone_from(&row.description);
                continue;
            }
            CityValue::UniversityWorkforceCost => 1,
            CityValue::UniversityPaperCost => {
                let Some(spec) = university_spec else {
                    continue;
                };
                spec.primary.per_unit()
            }
            CityValue::UniversityCashCost => {
                let Some(spec) = university_spec else {
                    continue;
                };
                text.0 = format_currency(i32::from(spec.cash_per_unit));
                continue;
            }
            CityValue::UniversityWorkforceAvailable => {
                let production = city.population.production_labor();
                production.high.min(labor_available / 4)
            }
            CityValue::UniversityPaperAvailable => {
                let Some(spec) = university_spec else {
                    continue;
                };
                city.stockpile[spec.primary.resource]
            }
            CityValue::ShipyardName => {
                let Some(row) = shipyard_row else {
                    continue;
                };
                text.0.clone_from(&row.ship_name);
                continue;
            }
            CityValue::ShipyardDescription => {
                let Some(row) = shipyard_row else {
                    continue;
                };
                text.0.clone_from(&row.description);
                continue;
            }
        };
        text.0 = if let Some(template) = number_template {
            format_retail_number(&template.0, value)
        } else {
            value.to_string()
        };
    }
    for (
        university_preview,
        university_requirement,
        shipyard_detail,
        shipyard_material,
        mut image,
        mut visibility,
    ) in &mut detail_images
    {
        if let Some(binding) = university_preview {
            let Ok(selection) = university_selections.get(binding.dialog) else {
                continue;
            };
            let Some(row) = university_rows
                .iter()
                .find(|row| row.dialog == binding.dialog && row.kind == selection.kind)
            else {
                continue;
            };
            image.image.clone_from(&row.preview);
            *visibility = Visibility::Visible;
        } else if let Some(binding) = university_requirement {
            let Ok(selection) = university_selections.get(binding.dialog) else {
                continue;
            };
            let resource = CIVILIAN_RESOURCE_SPECIALTIES[selection.kind][binding.row];
            if let Some(resource) = resource {
                let source_left = f32::from(resource as u8) * 20.0;
                image.rect = Some(Rect::new(source_left, 0.0, source_left + 20.0, 24.0));
                *visibility = Visibility::Visible;
            } else {
                *visibility = Visibility::Hidden;
            }
        } else if let Some(binding) = shipyard_detail {
            let Ok(selection) = shipyard_selections.get(binding.dialog) else {
                continue;
            };
            let Some(row) = shipyard_rows
                .iter()
                .find(|row| row.dialog == binding.dialog && row.slot == selection.slot)
            else {
                continue;
            };
            image.image.clone_from(&row.picture);
            *visibility = Visibility::Visible;
        } else if let Some(binding) = shipyard_material {
            let Ok(selection) = shipyard_selections.get(binding.dialog) else {
                continue;
            };
            let Some(row) = shipyard_rows
                .iter()
                .find(|row| row.dialog == binding.dialog && row.slot == selection.slot)
            else {
                continue;
            };
            if let Some(material) = row.materials.get(binding.index) {
                image.image.clone_from(&material.picture);
                *visibility = Visibility::Visible;
            } else {
                *visibility = Visibility::Hidden;
            }
        }
    }
    for (
        university_requirement,
        university_tier,
        shipyard_material,
        shipyard_stat,
        mut text,
        mut text_color,
        mut visibility,
    ) in &mut detail_texts
    {
        if let Some(binding) = university_requirement {
            let Ok(selection) = university_selections.get(binding.dialog) else {
                continue;
            };
            let Some((_, nation, _, _)) = dialog_states
                .iter()
                .find(|(root, _, _, _)| *root == binding.dialog)
            else {
                continue;
            };
            let specialties = CIVILIAN_RESOURCE_SPECIALTIES[selection.kind];
            let levels = &session.0.technology().city_capabilities_by_nation[*nation]
                .university
                .requirement_levels;
            let running_max = specialties[..=binding.row]
                .iter()
                .flatten()
                .map(|resource| levels[*resource])
                .max()
                .unwrap_or(0);
            if let Some(resource) = specialties[binding.row]
                && binding.level <= running_max
            {
                text.0 = resource_development_yield(resource, binding.level).to_string();
                *visibility = Visibility::Visible;
            } else {
                *visibility = Visibility::Hidden;
            }
        } else if let Some(binding) = university_tier {
            let Ok(selection) = university_selections.get(binding.dialog) else {
                continue;
            };
            let Some((_, nation, _, _)) = dialog_states
                .iter()
                .find(|(root, _, _, _)| *root == binding.dialog)
            else {
                continue;
            };
            let levels = &session.0.technology().city_capabilities_by_nation[*nation]
                .university
                .requirement_levels;
            let maximum = CIVILIAN_RESOURCE_SPECIALTIES[selection.kind]
                .iter()
                .flatten()
                .map(|resource| levels[*resource])
                .max()
                .unwrap_or(0);
            *visibility = if binding.level <= maximum {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        } else if let Some(binding) = shipyard_material {
            let Ok(selection) = shipyard_selections.get(binding.dialog) else {
                continue;
            };
            let Some(row) = shipyard_rows
                .iter()
                .find(|row| row.dialog == binding.dialog && row.slot == selection.slot)
            else {
                continue;
            };
            let Some(material) = row.materials.get(binding.index) else {
                *visibility = Visibility::Hidden;
                continue;
            };
            let Some((_, nation, _, _)) = dialog_states
                .iter()
                .find(|(root, _, _, _)| *root == binding.dialog)
            else {
                continue;
            };
            let stock = session.0.nations().major(*nation).city().stockpile[material.resource];
            text.0 = if binding.available {
                stock.to_string()
            } else {
                material.required.to_string()
            };
            text_color.0 = if binding.available && stock < material.required {
                binding.warning_color
            } else {
                binding.normal_color
            };
            *visibility = Visibility::Visible;
        } else if let Some(binding) = shipyard_stat {
            let Ok(selection) = shipyard_selections.get(binding.dialog) else {
                continue;
            };
            let Some(row) = shipyard_rows
                .iter()
                .find(|row| row.dialog == binding.dialog && row.slot == selection.slot)
            else {
                continue;
            };
            text.0 = row.stats[binding.index].to_string();
            *visibility = Visibility::Visible;
        }
    }
    for bar in &amount_bars {
        let Some((_, nation, order_views, _)) = dialog_states
            .iter()
            .find(|(root, _, _, _)| *root == bar.dialog)
        else {
            continue;
        };
        let Some((_, view)) = order_views.iter().find(|(order, _)| *order == bar.order) else {
            continue;
        };
        let capacity = session.0.nations().major(*nation).city().production_orders[bar.slot];
        let scale = |quantity: i16| {
            if capacity > 0 {
                (i32::from(quantity) * i32::from(INDUSTRY_BAR_WIDTH) / i32::from(capacity))
                    .clamp(0, i32::from(INDUSTRY_BAR_WIDTH)) as i16
            } else {
                0
            }
        };
        let current = scale(view.quantity);
        let maximum = scale(view.maximum);
        let Ok([mut fill, mut maximum_marker, mut quantity]) =
            amount_nodes.get_many_mut([bar.fill, bar.maximum, bar.quantity])
        else {
            continue;
        };
        fill.width = Val::Px(f32::from(current));
        maximum_marker.left = Val::Px(f32::from(maximum));
        quantity.left = Val::Px(INDUSTRY_BAR_X + f32::from(current) - 2.0);
        quantity.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
    }
    for (indicator, mut visibility) in &mut indicators {
        let Some((_, nation, _, _)) = dialog_states
            .iter()
            .find(|(root, _, _, _)| *root == indicator.dialog)
        else {
            continue;
        };
        let city = session.0.nations().major(*nation).city();
        *visibility = if city_is_expanding(city, indicator.slot) {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
    for root in &screens {
        commands.entity(root).remove::<CityScreenNeedsSync>();
    }
    for (root, _, _) in &dialogs {
        commands.entity(root).remove::<CityDialogNeedsSync>();
    }
}
