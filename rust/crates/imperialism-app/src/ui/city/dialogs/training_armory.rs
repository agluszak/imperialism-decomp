use super::*;
use crate::ui::retail::RetailPictureSwap;

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum TrainingIndicator {
    Paper { minimum: i16 },
    Money { minimum: i32 },
    UntrainedAvailable,
    TrainedAvailable,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum ArmoryDetail {
    UnitName,
    WorkforceCost,
    PrimaryCost,
    SecondaryCost,
    CashCost,
    WorkforceAvailable,
    PrimaryAvailable,
    SecondaryAvailable,
    Treasury,
    Firepower,
    ActionPoints,
    Range,
    Static,
    Description,
}

#[derive(Component)]
pub(in crate::ui::city) struct ArmoryPlacard;

const ARMORY_FIREPOWER: [i16; 30] = [
    5, 5, 10, 12, 7, 15, 10, 16, 7, 10, 15, 17, 10, 20, 17, 30, 10, 15, 22, 25, 22, 45, 25, 50, 0,
    0, 0, 0, 0, 0,
];
const ARMORY_ACTION_POINTS: [i16; 30] = [
    4, 6, 4, 4, 11, 9, 5, 3, 4, 6, 4, 4, 11, 9, 6, 3, 5, 7, 5, 4, 11, 9, 8, 3, 4, 4, 5, 9, 9, 9,
];
const ARMORY_RANGE: [i16; 30] = [
    5, 5, 5, 5, 3, 3, 9, 11, 8, 8, 8, 8, 5, 5, 12, 14, 10, 10, 10, 10, 10, 12, 15, 17, 5, 8, 10, 0,
    0, 0,
];
const ARMORY_STATIC: [bool; 30] = [
    true, true, true, true, false, false, false, false, true, true, true, true, false, false,
    false, false, true, true, true, true, true, false, false, false, true, true, true, false,
    false, false,
];

const ARMORY_TITLE_TEXT_STYLE: RetailTextStylePreset = RetailTextStylePreset {
    font_family: 1,
    face_flags: 0,
    point_size: 24,
    alignment: 1,
};
const ARMORY_UNIT_TEXT_STYLE: RetailTextStylePreset = RetailTextStylePreset {
    font_family: 1,
    face_flags: 0,
    point_size: 12,
    alignment: 1,
};
const ARMORY_DETAIL_TEXT_STYLE: RetailTextStylePreset = RetailTextStylePreset {
    font_family: 3,
    face_flags: 0,
    point_size: 10,
    alignment: 0,
};

const fn armory_picture_variant(unit: MilitaryUnitKind) -> i16 {
    match unit {
        MilitaryUnitKind::Sappers => 8,
        MilitaryUnitKind::CombatEngineers => 0x10,
        MilitaryUnitKind::Saboteurs => 0x18,
        _ => unit as i16,
    }
}

const fn armory_row_picture(unit: MilitaryUnitKind) -> PictureId {
    PictureId::new(0x1d60 + 2 * armory_picture_variant(unit))
}

pub(in crate::ui::city) fn configure_training_dialog(
    commands: &mut Commands,
    assets: &RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::TradeSchool);
    bind_training_dialog(commands, root, tree, building_name);
}

pub(in crate::ui::city) fn bind_training_dialog(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    building_name: String,
) {
    bind_city_dialog_root(commands, root, tree, CityFacilitySlot::TradeSchool);
    let name = tree.find(root, fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(text));
    }
    for binding in TRAINING_ORDERS {
        bind_city_order_row(
            commands,
            root,
            tree,
            binding,
            fourcc!("left"),
            fourcc!("rght"),
            fourcc!("move"),
            1,
            None,
        );
    }
    let paper_one = tree.find(root, fourcc!("pap1"));
    let paper_two = tree.find(root, fourcc!("pap2"));
    let money_one = tree.find(root, fourcc!("mon1"));
    let money_two = tree.find(root, fourcc!("mon2"));
    let untrained_available = tree.find(root, fourcc!("untV"));
    let trained_available = tree.find(root, fourcc!("traV"));
    commands
        .entity(paper_one)
        .insert((Text::new("X"), TrainingIndicator::Paper { minimum: 1 }));
    commands
        .entity(paper_two)
        .insert((Text::new("X"), TrainingIndicator::Paper { minimum: 2 }));
    commands
        .entity(money_one)
        .insert((Text::new("X"), TrainingIndicator::Money { minimum: 100 }));
    commands
        .entity(money_two)
        .insert((Text::new("X"), TrainingIndicator::Money { minimum: 1_000 }));
    commands
        .entity(untrained_available)
        .insert((Text::new("X"), TrainingIndicator::UntrainedAvailable));
    commands
        .entity(trained_available)
        .insert((Text::new("X"), TrainingIndicator::TrainedAvailable));
}

pub(in crate::ui::city) fn configure_armory_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("City active nation is a major nation");
    let city = &state.nations().major(nation).city;
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    let (title_font, _, title_line_height, _) = assets
        .text_style(ARMORY_TITLE_TEXT_STYLE)
        .expect("retail Armory title text style");
    let (unit_font, _, unit_line_height, _) = assets
        .text_style(ARMORY_UNIT_TEXT_STYLE)
        .expect("retail Armory unit text style");
    let (detail_font, _, detail_line_height, _) = assets
        .text_style(ARMORY_DETAIL_TEXT_STYLE)
        .expect("retail Armory detail text style");
    let title = assets
        .string(0x271c, 0x20)
        .expect("retail English Armory title");
    bind_city_dialog_root(commands, root, tree, CityFacilitySlot::Armory);
    let title_control = tree.find(root, fourcc!("titl"));
    commands.entity(title_control).insert((
        Text::new(title),
        title_font,
        title_line_height,
        TextColor(normal_color),
    ));
    for row in ARMORY_ROWS {
        let bound = bind_city_order_row(
            commands,
            root,
            tree,
            row.binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
            Some(root),
        );
        let button = tree.find(root, row.button_tag);
        let category = row.military_category();
        let unit = city.orders.military_recruitment[category].unit_kind;
        let idle = assets
            .picture(armory_row_picture(unit))
            .expect("retail Armory row picture");
        let active = assets
            .picture(PictureId::new(armory_row_picture(unit).get() + 1))
            .expect("retail Armory selected row picture");
        let mut button = commands.entity(button);
        button.insert((
            CityRowChoice {
                order: row.binding.order,
                selection: root,
            },
            ImageNode::new(idle.clone()),
            RetailPictureSwap { idle, active },
        ));
        commands.entity(bound.quantity).insert(InteractionDisabled);
    }
    for (tag, detail) in [
        (fourcc!("unit"), ArmoryDetail::UnitName),
        (fourcc!("cos0"), ArmoryDetail::WorkforceCost),
        (fourcc!("cos1"), ArmoryDetail::PrimaryCost),
        (fourcc!("cos2"), ArmoryDetail::SecondaryCost),
        (fourcc!("cos3"), ArmoryDetail::CashCost),
        (fourcc!("ava0"), ArmoryDetail::WorkforceAvailable),
        (fourcc!("ava1"), ArmoryDetail::PrimaryAvailable),
        (fourcc!("ava2"), ArmoryDetail::SecondaryAvailable),
        (fourcc!("ava3"), ArmoryDetail::Treasury),
        (fourcc!("sta0"), ArmoryDetail::Firepower),
        (fourcc!("sta1"), ArmoryDetail::ActionPoints),
        (fourcc!("sta2"), ArmoryDetail::Range),
        (fourcc!("sta3"), ArmoryDetail::Static),
        (fourcc!("desc"), ArmoryDetail::Description),
    ] {
        let entity = tree.find(root, tag);
        let (font, line_height) = if tag == fourcc!("unit") {
            (unit_font.clone(), unit_line_height)
        } else {
            (detail_font.clone(), detail_line_height)
        };
        commands.entity(entity).insert((
            Text::new(""),
            font,
            line_height,
            TextColor(normal_color),
            detail,
        ));
    }
    for (tag, string_index) in [
        (fourcc!("cost"), 0x1e),
        (fourcc!("avai"), 0x1f),
        (fourcc!("lab0"), 1),
        (fourcc!("lab1"), 2),
        (fourcc!("lab2"), 3),
        (fourcc!("lab3"), 4),
    ] {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert((
            Text::new(
                assets
                    .string(0x271c, string_index)
                    .expect("retail Armory label"),
            ),
            detail_font.clone(),
            detail_line_height,
            TextColor(normal_color),
        ));
    }
    let placard = tree.find(root, fourcc!("plaq"));
    commands.entity(placard).insert(ArmoryPlacard);
    commands.entity(root).insert(CityRowSelection {
        order: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightInfantry),
        normal_color,
        warning_color,
    });
}

pub(in crate::ui::city) fn sync_training_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<TrainingIndicator>>,
    mut indicators: Query<(&TrainingIndicator, &mut Visibility)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let production = city.population.production_labor();
    let strength = city.population.strength();
    let budget = major
        .economy
        .available_diplomacy_budget(major.common.treasury);
    for (indicator, mut visibility) in &mut indicators {
        let visible = match *indicator {
            TrainingIndicator::Paper { minimum } => city.stockpile[ResourceKind::Paper] >= minimum,
            TrainingIndicator::Money { minimum } => budget >= minimum,
            TrainingIndicator::UntrainedAvailable => production.low.min(strength) != 0,
            TrainingIndicator::TrainedAvailable => production.medium.min(strength / 2) != 0,
        };
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

pub(in crate::ui::city) fn sync_armory_details(
    session: Res<GameSession>,
    selections: Query<Ref<CityRowSelection>>,
    mut assets: RetailUiAssets,
    mut texts: Query<(&ArmoryDetail, &mut Text, &mut TextColor)>,
    mut visibilities: Query<(&ArmoryDetail, &mut Visibility)>,
    mut placards: Query<&mut ImageNode, With<ArmoryPlacard>>,
) {
    let Some(selection) = selections
        .iter()
        .find(|selection| matches!(selection.order, CityOrderId::MilitaryRecruit(_)))
    else {
        return;
    };
    let CityOrderId::MilitaryRecruit(category) = selection.order else {
        return;
    };
    if !session.is_changed() && !selection.is_changed() && !selection.is_added() {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let order = &city.orders.military_recruitment[category];
    let spec = military_recruitment_spec(order.unit_kind)
        .expect("Armory row has a recruitable retail unit recipe");
    let production = city.population.production_labor();
    let strength = city.population.strength();
    let (workforce, strength_divisor) = match spec.workforce {
        SkillBand::Low => (production.low, 1),
        SkillBand::Medium => (production.medium, 2),
        SkillBand::High => (production.high, 4),
    };
    let secondary = spec.secondary;
    let unit_index = order.unit_kind as usize;
    let unit_name = assets
        .string(0x2717, order.unit_kind as i16 + 1)
        .expect("retail military unit name");
    let description = assets
        .string(0x2750, order.unit_kind as i16 + 1)
        .expect("retail military unit description");
    let static_text = assets
        .string(
            0x271c,
            if ARMORY_STATIC[unit_index] {
                0x22
            } else {
                0x21
            },
        )
        .expect("retail Armory yes/no string");
    let workforce_available = workforce.min(strength / strength_divisor);
    let primary_available = city.stockpile[spec.primary.resource];
    let secondary_available = secondary.map(|item| city.stockpile[item.resource]);
    for (detail, mut text, mut color) in &mut texts {
        text.0 = match detail {
            ArmoryDetail::UnitName => unit_name.clone(),
            ArmoryDetail::WorkforceCost => 1.to_string(),
            ArmoryDetail::PrimaryCost => spec.primary.per_unit().to_string(),
            ArmoryDetail::SecondaryCost => secondary
                .map(|item| item.per_unit().to_string())
                .unwrap_or_default(),
            ArmoryDetail::CashCost => format_currency(i32::from(spec.cash_per_unit)),
            ArmoryDetail::WorkforceAvailable => workforce_available.to_string(),
            ArmoryDetail::PrimaryAvailable => primary_available.to_string(),
            ArmoryDetail::SecondaryAvailable => secondary
                .map(|_| {
                    secondary_available
                        .expect("secondary item has availability")
                        .to_string()
                })
                .unwrap_or_default(),
            ArmoryDetail::Treasury => format_currency(major.common.treasury),
            ArmoryDetail::Firepower => ARMORY_FIREPOWER[unit_index].to_string(),
            ArmoryDetail::ActionPoints => ARMORY_ACTION_POINTS[unit_index].to_string(),
            ArmoryDetail::Range => ARMORY_RANGE[unit_index].to_string(),
            ArmoryDetail::Static => static_text.clone(),
            ArmoryDetail::Description => description.clone(),
        };
        let warning = match detail {
            ArmoryDetail::WorkforceAvailable => workforce_available == 0,
            ArmoryDetail::PrimaryAvailable => primary_available < spec.primary.per_unit(),
            // Retail compares both material columns against the primary input amount.
            ArmoryDetail::SecondaryAvailable => {
                secondary_available.is_some_and(|available| available < spec.primary.per_unit())
            }
            ArmoryDetail::Treasury => major.common.treasury < i32::from(spec.cash_per_unit),
            _ => false,
        };
        color.0 = city_stock_color(warning, &selection);
    }
    placards
        .single_mut()
        .expect("Armory dialog has one unit placard")
        .image = assets
        .picture(PictureId::new(0x1d9c + order.unit_kind as i16))
        .expect("retail Armory unit placard");
    let secondary_visible = if secondary.is_some() {
        Visibility::Visible
    } else {
        Visibility::Hidden
    };
    for (detail, mut visibility) in &mut visibilities {
        if matches!(
            detail,
            ArmoryDetail::SecondaryCost | ArmoryDetail::SecondaryAvailable
        ) {
            *visibility = secondary_visible;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::beginning_of_game;

    #[test]
    fn armory_uses_the_recovered_windows_font_families() {
        assert_eq!(
            resolve_retail_text_style(ARMORY_TITLE_TEXT_STYLE)
                .unwrap()
                .face,
            RetailFontFace::BelweBold
        );
        assert_eq!(
            resolve_retail_text_style(ARMORY_UNIT_TEXT_STYLE)
                .unwrap()
                .face,
            RetailFontFace::BelweBold
        );
        assert_eq!(
            resolve_retail_text_style(ARMORY_DETAIL_TEXT_STYLE)
                .unwrap()
                .face,
            RetailFontFace::BookAntiquaRegular
        );
    }

    #[test]
    fn beginning_armory_rows_use_the_retail_unit_picture_sequence() {
        let state = beginning_of_game();
        let nation = MajorNationId::from_nation(state.turn().selected_nation).unwrap();
        let city = &state.nations().major(nation).city;
        let pictures: Vec<_> = (0..enum_map::enum_len::<MilitaryRecruitmentCategory>())
            .map(MilitaryRecruitmentCategory::from_usize)
            .map(|category| {
                armory_row_picture(city.orders.military_recruitment[category].unit_kind).get()
            })
            .collect();

        assert_eq!(pictures, [7522, 7524, 7526, 7528, 7530, 7532, 7534, 7536]);
        assert_eq!(
            armory_row_picture(MilitaryUnitKind::CombatEngineers).get(),
            7552
        );
        assert_eq!(armory_row_picture(MilitaryUnitKind::Saboteurs).get(), 7568);
    }
}
