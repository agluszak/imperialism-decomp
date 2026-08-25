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
    ui: &generated::Citydlog9209,
) {
    let building_name = city_building_name(assets, CityFacilitySlot::TradeSchool);
    bind_training_dialog(commands, ui, building_name);
}

pub(in crate::ui::city) fn bind_training_dialog(
    commands: &mut Commands,
    ui: &generated::Citydlog9209,
    building_name: String,
) {
    commands.entity(ui.name).insert(Text::new(building_name));
    commands.entity(ui.cos1).insert(Text::new("$100"));
    commands.entity(ui.cos2).insert(Text::new("$1,000"));
    for (order, row, decrease, increase, quantity) in [
        (
            CityOrderId::Training(TrainingLevel::Medium),
            ui.trai,
            ui.trai_left,
            ui.trai_rght,
            ui.trai_move_,
        ),
        (
            CityOrderId::Training(TrainingLevel::High),
            ui.prof,
            ui.prof_left,
            ui.prof_rght,
            ui.prof_move_,
        ),
    ] {
        bind_city_order_row(commands, order, row, decrease, increase, quantity, 1, None);
    }
    commands
        .entity(ui.pap1)
        .insert((Text::new("X"), TrainingIndicator::Paper { minimum: 1 }));
    commands
        .entity(ui.pap2)
        .insert((Text::new("X"), TrainingIndicator::Paper { minimum: 2 }));
    commands
        .entity(ui.mon1)
        .insert((Text::new("X"), TrainingIndicator::Money { minimum: 100 }));
    commands
        .entity(ui.mon2)
        .insert((Text::new("X"), TrainingIndicator::Money { minimum: 1_000 }));
    commands
        .entity(ui.untv)
        .insert((Text::new("X"), TrainingIndicator::UntrainedAvailable));
    commands
        .entity(ui.trav)
        .insert((Text::new("X"), TrainingIndicator::TrainedAvailable));
}

pub(in crate::ui::city) fn configure_armory_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    ui: &generated::Armory9208,
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
    commands.entity(ui.titl).insert((
        Text::new(title),
        title_font,
        title_line_height,
        TextColor(normal_color),
    ));
    let rows = [
        (
            MilitaryRecruitmentCategory::LightInfantry,
            ui.clu0,
            ui.clu0_minu,
            ui.clu0_plus,
            ui.num0_numb,
            ui.civ0,
        ),
        (
            MilitaryRecruitmentCategory::RegularInfantry,
            ui.clu1,
            ui.clu1_minu,
            ui.clu1_plus,
            ui.num1_numb,
            ui.civ1,
        ),
        (
            MilitaryRecruitmentCategory::HeavyInfantry,
            ui.clu2,
            ui.clu2_minu,
            ui.clu2_plus,
            ui.num2_numb,
            ui.civ2,
        ),
        (
            MilitaryRecruitmentCategory::LightCavalry,
            ui.clu3,
            ui.clu3_minu,
            ui.clu3_plus,
            ui.num3_numb,
            ui.civ3,
        ),
        (
            MilitaryRecruitmentCategory::HeavyCavalry,
            ui.clu4,
            ui.clu4_minu,
            ui.clu4_plus,
            ui.num4_numb,
            ui.civ4,
        ),
        (
            MilitaryRecruitmentCategory::LightArtillery,
            ui.clu5,
            ui.clu5_minu,
            ui.clu5_plus,
            ui.num5_numb,
            ui.civ5,
        ),
        (
            MilitaryRecruitmentCategory::HeavyArtillery,
            ui.clu6,
            ui.clu6_minu,
            ui.clu6_plus,
            ui.num6_numb,
            ui.civ6,
        ),
        (
            MilitaryRecruitmentCategory::Demolitionist,
            ui.clu7,
            ui.clu7_minu,
            ui.clu7_plus,
            ui.num7_numb,
            ui.civ7,
        ),
    ];
    for (category, row, decrease, increase, quantity, button) in rows {
        let order = CityOrderId::MilitaryRecruit(category);
        let bound = bind_city_order_row(
            commands,
            order,
            row,
            decrease,
            increase,
            quantity,
            1,
            Some(ui.root),
        );
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
                order,
                selection: ui.root,
            },
            ImageNode::new(idle.clone()),
            RetailPictureSwap { idle, active },
        ));
        button.observe(on_city_row_selected);
        commands.entity(bound.quantity).insert(InteractionDisabled);
    }
    for (entity, detail, is_unit) in [
        (ui.unit, ArmoryDetail::UnitName, true),
        (ui.cos0, ArmoryDetail::WorkforceCost, false),
        (ui.cos1, ArmoryDetail::PrimaryCost, false),
        (ui.cos2, ArmoryDetail::SecondaryCost, false),
        (ui.cos3, ArmoryDetail::CashCost, false),
        (ui.ava0, ArmoryDetail::WorkforceAvailable, false),
        (ui.ava1, ArmoryDetail::PrimaryAvailable, false),
        (ui.ava2, ArmoryDetail::SecondaryAvailable, false),
        (ui.ava3, ArmoryDetail::Treasury, false),
        (ui.sta0, ArmoryDetail::Firepower, false),
        (ui.sta1, ArmoryDetail::ActionPoints, false),
        (ui.sta2, ArmoryDetail::Range, false),
        (ui.sta3, ArmoryDetail::Static, false),
        (ui.desc, ArmoryDetail::Description, false),
    ] {
        let (font, line_height) = if is_unit {
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
    for (entity, string_index) in [
        (ui.cost, 0x1e),
        (ui.avai, 0x1f),
        (ui.lab0, 1),
        (ui.lab1, 2),
        (ui.lab2, 3),
        (ui.lab3, 4),
    ] {
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
    commands.entity(ui.plaq).insert(ArmoryPlacard);
    commands.entity(ui.root).insert(CityRowSelection {
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
    let unit_index = usize::from(order.unit_kind.retail());
    let unit_name = assets
        .string(0x2717, i16::from(order.unit_kind.retail()) + 1)
        .expect("retail military unit name");
    let description = assets
        .string(0x2750, i16::from(order.unit_kind.retail()) + 1)
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
        .picture(PictureId::new(0x1d9c + i16::from(order.unit_kind.retail())))
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
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
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
