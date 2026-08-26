use super::*;
use crate::ui::retail::RetailPictureSwap;

#[derive(Component)]
pub(in crate::ui::city) struct TrainingView {
    quantities: [Entity; TRAINING_ORDERS.len()],
    paper_one: Entity,
    paper_two: Entity,
    money_one: Entity,
    money_two: Entity,
    untrained_available: Entity,
    trained_available: Entity,
}

/// Root view of the Armory dialog: the selected recruitment category and
/// the fixed row buttons and detail controls.
#[derive(Component)]
pub(in crate::ui::city) struct ArmoryView {
    selected: MilitaryRecruitmentCategory,
    rows: [Entity; ARMORY_ROWS.len()],
    quantities: [Entity; ARMORY_ROWS.len()],
    unit: Entity,
    costs: [Entity; 4],
    available: [Entity; 4],
    stats: [Entity; 4],
    description: Entity,
    placard: Entity,
}

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
    let name = tree.find(root, fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(text));
    }
    let quantities = TRAINING_ORDERS
        .map(|binding| bind_industry_order_row(commands, root, tree, binding, 1).quantity);
    let paper_one = tree.find(root, fourcc!("pap1"));
    let paper_two = tree.find(root, fourcc!("pap2"));
    let money_one = tree.find(root, fourcc!("mon1"));
    let money_two = tree.find(root, fourcc!("mon2"));
    let untrained_available = tree.find(root, fourcc!("untV"));
    let trained_available = tree.find(root, fourcc!("traV"));
    commands.entity(root).insert(TrainingView {
        quantities,
        paper_one,
        paper_two,
        money_one,
        money_two,
        untrained_available,
        trained_available,
    });
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
    let title_control = tree.find(root, fourcc!("titl"));
    commands.entity(title_control).insert((
        Text::new(title),
        title_font,
        title_line_height,
        TextColor(normal_color),
    ));
    let rows_and_quantities: [(Entity, Entity); ARMORY_ROWS.len()] = std::array::from_fn(|index| {
        let row = ARMORY_ROWS[index];
        let bound = bind_recruitment_order_row(commands, root, tree, row.binding);
        let category = row.military_category();
        for tag in [fourcc!("minu"), fourcc!("plus")] {
            commands.entity(tree.find(bound.row, tag)).observe(
                move |_: On<Activate>, mut views: Query<&mut ArmoryView>| {
                    if let Ok(mut view) = views.get_mut(root) {
                        view.selected = category;
                    }
                },
            );
        }
        let button = tree.find(root, row.button_tag);
        let unit = city.orders.military_recruitment[category].unit_kind;
        let idle = assets
            .picture(armory_row_picture(unit))
            .expect("retail Armory row picture");
        let active = assets
            .picture(PictureId::new(armory_row_picture(unit).get() + 1))
            .expect("retail Armory selected row picture");
        commands.entity(button).insert((
            ImageNode::new(idle.clone()),
            RetailPictureSwap { idle, active },
        ));
        commands.entity(button).observe(
            move |change: On<ValueChange<bool>>, mut views: Query<&mut ArmoryView>| {
                if change.value
                    && let Ok(mut view) = views.get_mut(root)
                {
                    view.selected = category;
                }
            },
        );
        commands.entity(bound.quantity).insert(InteractionDisabled);
        (button, bound.quantity)
    });
    let rows: [Entity; ARMORY_ROWS.len()] = rows_and_quantities.map(|(button, _)| button);
    let quantities: [Entity; ARMORY_ROWS.len()] = rows_and_quantities.map(|(_, quantity)| quantity);
    let mut bind_detail = |tag, font, line_height| {
        let entity = tree.find(root, tag);
        commands
            .entity(entity)
            .insert((Text::new(""), font, line_height, TextColor(normal_color)));
        entity
    };
    let unit = bind_detail(fourcc!("unit"), unit_font, unit_line_height);
    let costs = [
        fourcc!("cos0"),
        fourcc!("cos1"),
        fourcc!("cos2"),
        fourcc!("cos3"),
    ]
    .map(|tag| bind_detail(tag, detail_font.clone(), detail_line_height));
    let available = [
        fourcc!("ava0"),
        fourcc!("ava1"),
        fourcc!("ava2"),
        fourcc!("ava3"),
    ]
    .map(|tag| bind_detail(tag, detail_font.clone(), detail_line_height));
    let stats = [
        fourcc!("sta0"),
        fourcc!("sta1"),
        fourcc!("sta2"),
        fourcc!("sta3"),
    ]
    .map(|tag| bind_detail(tag, detail_font.clone(), detail_line_height));
    let description = bind_detail(fourcc!("desc"), detail_font.clone(), detail_line_height);
    let placard = tree.find(root, fourcc!("plaq"));
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
    commands.entity(root).insert(ArmoryView {
        selected: MilitaryRecruitmentCategory::LightInfantry,
        rows,
        quantities,
        unit,
        costs,
        available,
        stats,
        description,
        placard,
    });
}

pub(in crate::ui::city) fn render_training_dialog(
    session: Res<GameSession>,
    views: Query<Ref<TrainingView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
) {
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let production = city.population.production_labor();
    let strength = city.population.strength();
    let budget = major
        .economy
        .available_diplomacy_budget(major.common.treasury);
    for view in &views {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        for (binding, quantity) in TRAINING_ORDERS.iter().zip(&view.quantities) {
            texts
                .get_mut(*quantity)
                .expect("bound training order quantity")
                .0 = session
                .game
                .city_order_quantity(nation, binding.order)
                .to_string();
        }
        let mut set = |entity, visible| {
            commands.entity(entity).insert(if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            });
        };
        set(view.paper_one, city.stockpile[ResourceKind::Paper] >= 1);
        set(view.paper_two, city.stockpile[ResourceKind::Paper] >= 2);
        set(view.money_one, budget >= 100);
        set(view.money_two, budget >= 1_000);
        set(view.untrained_available, production.low.min(strength) != 0);
        set(
            view.trained_available,
            production.medium.min(strength / 2) != 0,
        );
    }
}

pub(in crate::ui::city) fn render_armory_dialog(
    session: Res<GameSession>,
    views: Query<Ref<ArmoryView>>,
    mut assets: RetailUiAssets,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut text_colors: Query<&mut TextColor>,
    mut visibilities: Query<&mut Visibility>,
    mut placards: Query<&mut ImageNode>,
    checked: Query<Has<Checked>>,
) {
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    for view in &views {
        if !session.is_changed() && !view.is_added() && !view.is_changed() {
            continue;
        }
        let nation = session.active_major_nation();
        for ((row, button), quantity) in ARMORY_ROWS.iter().zip(&view.rows).zip(&view.quantities) {
            sync_recruitment_row(
                &mut commands,
                &checked,
                &mut texts,
                *button,
                row.military_category() == view.selected,
                *quantity,
                session
                    .game
                    .city_order_quantity(nation, row.binding.order)
                    .to_string(),
            );
        }
        let major = session.game.nations().major(nation);
        let city = &major.city;
        let order = &city.orders.military_recruitment[view.selected];
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
        let values = [
            unit_name.clone(),
            1.to_string(),
            spec.primary.per_unit().to_string(),
            secondary
                .map(|item| item.per_unit().to_string())
                .unwrap_or_default(),
            format_currency(i32::from(spec.cash_per_unit)),
            workforce_available.to_string(),
            primary_available.to_string(),
            secondary
                .map(|_| {
                    secondary_available
                        .expect("secondary item has availability")
                        .to_string()
                })
                .unwrap_or_default(),
            format_currency(major.common.treasury),
            ARMORY_FIREPOWER[unit_index].to_string(),
            ARMORY_ACTION_POINTS[unit_index].to_string(),
            ARMORY_RANGE[unit_index].to_string(),
            static_text,
            description.clone(),
        ];
        texts
            .get_mut(view.unit)
            .expect("bound Armory unit name")
            .0
            .clone_from(&values[0]);
        for (entity, value) in view
            .costs
            .iter()
            .chain(&view.available)
            .chain(&view.stats)
            .zip(&values[1..])
        {
            texts
                .get_mut(*entity)
                .expect("bound Armory detail")
                .0
                .clone_from(value);
        }
        texts
            .get_mut(view.description)
            .expect("bound Armory description")
            .0
            .clone_from(&values[13]);
        let warnings = [
            false,
            workforce_available == 0,
            primary_available < spec.primary.per_unit(),
            // Retail compares both material columns against the primary input amount.
            secondary_available.is_some_and(|available| available < spec.primary.per_unit()),
            major.common.treasury < i32::from(spec.cash_per_unit),
        ];
        for (entity, warning) in view.available.iter().zip(&warnings[1..]) {
            text_colors
                .get_mut(*entity)
                .expect("bound Armory availability")
                .0 = if *warning {
                warning_color
            } else {
                normal_color
            };
        }
        placards
            .get_mut(view.placard)
            .expect("Armory dialog has one unit placard")
            .image = assets
            .picture(PictureId::new(0x1d9c + i16::from(order.unit_kind.retail())))
            .expect("retail Armory unit placard");
        let secondary_visible = if secondary.is_some() {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        for entity in [view.costs[2], view.available[2]] {
            *visibilities
                .get_mut(entity)
                .expect("bound Armory secondary detail") = secondary_visible;
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
