use super::*;
use crate::ui::retail::RetailPictureSwap;

pub(in crate::ui::city) struct TrainingUi {
    quantities: TrainingOrderTable<Entity>,
    paper_one: Entity,
    paper_two: Entity,
    money_one: Entity,
    money_two: Entity,
    untrained_available: Entity,
    trained_available: Entity,
}

pub(in crate::ui::city) struct ArmoryUi {
    pub(in crate::ui::city) selected: MilitaryRecruitmentCategory,
    rows: MilitaryRecruitOrderTable<SelectionRow>,
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

const fn armory_row_pictures(unit: MilitaryUnitKind) -> [PictureId; 2] {
    let base = PictureId::new(0x1d60).offset(2 * armory_picture_variant(unit));
    [base, base.offset(1)]
}

pub(in crate::ui::city) fn bind_training(
    commands: &mut Commands,
    assets: &RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) -> TrainingUi {
    let building_name = city_building_name(assets, CityFacilitySlot::TradeSchool);
    let name = tree.find(root, fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    for (tag, text) in [(fourcc!("cos1"), "$100"), (fourcc!("cos2"), "$1,000")] {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(text));
    }
    let quantities =
        TrainingOrderTable::from_array(generated::TRAINING_ORDER_TAGS).map(|level, tag| {
            bind_industry_order_row(commands, root, tree, CityOrderId::Training(level), tag, 1)
                .quantity
        });
    TrainingUi {
        quantities,
        paper_one: tree.find(root, fourcc!("pap1")),
        paper_two: tree.find(root, fourcc!("pap2")),
        money_one: tree.find(root, fourcc!("mon1")),
        money_two: tree.find(root, fourcc!("mon2")),
        untrained_available: tree.find(root, fourcc!("untV")),
        trained_available: tree.find(root, fourcc!("traV")),
    }
}

pub(in crate::ui::city) fn bind_armory(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) -> ArmoryUi {
    let nation = MajorNationId::from_nation(state.turn().active_nation).expect("major nation");
    let city = &state.nations().major(nation).city;
    let normal_color = assets.palette_color(0xd2);
    let (title_font, _, title_line_height, _) = assets
        .text_style(ARMORY_TITLE_TEXT_STYLE)
        .expect("title style");
    let (unit_font, _, unit_line_height, _) = assets
        .text_style(ARMORY_UNIT_TEXT_STYLE)
        .expect("unit style");
    let (detail_font, _, detail_line_height, _) = assets
        .text_style(ARMORY_DETAIL_TEXT_STYLE)
        .expect("detail style");
    let title = assets.ui_string(0x271c, 0x20);
    commands.entity(tree.find(root, fourcc!("titl"))).insert((
        Text::new(title),
        title_font,
        title_line_height,
        TextColor(normal_color),
    ));
    let rows = MilitaryRecruitOrderTable::from_array(generated::ARMORY_ROW_CONTROLS).map(
        |category, (order_tag, button_tag)| {
            let bound = bind_recruitment_order_row(
                commands,
                root,
                tree,
                CityOrderId::MilitaryRecruit(category),
                order_tag,
            );
            let button = tree.find(root, button_tag);
            let unit = city.orders.military_recruitment[category].unit_kind;
            let [idle_id, selected_id] = armory_row_pictures(unit);
            let idle = assets.picture(idle_id);
            let selected = assets.picture(selected_id);
            commands.entity(button).insert((
                ImageNode::new(idle.clone()),
                RetailPictureSwap {
                    idle,
                    active: selected,
                },
            ));
            bind_row_selection(commands, tree, root, bound.row, button, move |view| {
                if let CityDialogView::Armory(a) = view {
                    a.selected = category;
                }
            });
            commands.entity(bound.quantity).insert(InteractionDisabled);
            SelectionRow(button, bound.quantity)
        },
    );
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
                assets.ui_string(0x271c, string_index),
            ),
            detail_font.clone(),
            detail_line_height,
            TextColor(normal_color),
        ));
    }
    ArmoryUi {
        selected: MilitaryRecruitmentCategory::LightInfantry,
        rows,
        unit,
        costs,
        available,
        stats,
        description,
        placard,
    }
}

pub(in crate::ui::city) fn render_training(
    view: &TrainingUi,
    session: &GameSession,
    nation: MajorNationId,
    ui: &mut CityUi,
) {
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let production = city.population.production_labor();
    let strength = city.population.strength();
    let budget = major
        .economy
        .available_diplomacy_budget(major.common.treasury);
    for (level, quantity) in &view.quantities {
        ui.text(
            *quantity,
            session
                .game
                .city_order_quantity(nation, CityOrderId::Training(level))
                .to_string(),
        );
    }
    ui.visible(view.paper_one, city.stockpile[ResourceKind::Paper] >= 1);
    ui.visible(view.paper_two, city.stockpile[ResourceKind::Paper] >= 2);
    ui.visible(view.money_one, budget >= 100);
    ui.visible(view.money_two, budget >= 1_000);
    ui.visible(view.untrained_available, production.low.min(strength) != 0);
    ui.visible(
        view.trained_available,
        production.medium.min(strength / 2) != 0,
    );
}

pub(in crate::ui::city) fn render_armory(
    view: &ArmoryUi,
    session: &GameSession,
    assets: &mut RetailUiAssets,
    ui: &mut CityUi,
) {
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    let nation = session.active_major_nation();
    for (category, row) in &view.rows {
        sync_recruitment_row(
            ui,
            *row,
            category == view.selected,
            session
                .game
                .city_order_quantity(nation, CityOrderId::MilitaryRecruit(category))
                .to_string(),
        );
    }
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let order = &city.orders.military_recruitment[view.selected];
    let spec = military_recruitment_spec(order.unit_kind).expect("recruit recipe");
    let production = city.population.production_labor();
    let strength = city.population.strength();
    let (workforce, strength_divisor) = match spec.workforce {
        SkillBand::Low => (production.low, 1),
        SkillBand::Medium => (production.medium, 2),
        SkillBand::High => (production.high, 4),
    };
    let secondary = spec.secondary;
    let unit_index = usize::from(order.unit_kind.retail());
    let unit_name = assets.string(order.unit_kind.name_string());
    let description = assets.string(order.unit_kind.description_string());
    let static_text = assets.ui_string(0x271c, if ARMORY_STATIC[unit_index] {
                0x22
            } else {
                0x21
            });
    let workforce_available = workforce.min(strength / strength_divisor);
    let primary_available = city.stockpile[spec.primary.resource];
    let secondary_available = secondary.map(|item| city.stockpile[item.resource]);
    let values = [
        unit_name,
        1.to_string(),
        spec.primary.per_unit().to_string(),
        secondary
            .map(|item| item.per_unit().to_string())
            .unwrap_or_default(),
        format_currency(i32::from(spec.cash_per_unit)),
        workforce_available.to_string(),
        primary_available.to_string(),
        secondary_available
            .map(|v| v.to_string())
            .unwrap_or_default(),
        format_currency(major.common.treasury),
        ARMORY_FIREPOWER[unit_index].to_string(),
        ARMORY_ACTION_POINTS[unit_index].to_string(),
        ARMORY_RANGE[unit_index].to_string(),
        static_text,
        description,
    ];
    ui.text(view.unit, values[0].clone());
    for (entity, value) in view
        .costs
        .iter()
        .chain(&view.available)
        .chain(&view.stats)
        .zip(&values[1..])
    {
        ui.text(*entity, value.clone());
    }
    ui.text(view.description, values[13].clone());
    let warnings = [
        workforce_available == 0,
        primary_available < spec.primary.per_unit(),
        secondary_available.is_some_and(|available| available < spec.primary.per_unit()),
        major.common.treasury < i32::from(spec.cash_per_unit),
    ];
    for (entity, warning) in view.available.iter().zip(&warnings) {
        ui.color(
            *entity,
            if *warning {
                warning_color
            } else {
                normal_color
            },
        );
    }
    ui.image(
        view.placard,
        assets.picture(order.unit_kind.armory_placard_picture()),
    );
    ui.visible(view.costs[2], secondary.is_some());
    ui.visible(view.available[2], secondary.is_some());
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
                armory_row_pictures(city.orders.military_recruitment[category].unit_kind)[0].get()
            })
            .collect();

        assert_eq!(pictures, [7522, 7524, 7526, 7528, 7530, 7532, 7534, 7536]);
        assert_eq!(
            armory_row_pictures(MilitaryUnitKind::CombatEngineers)[0].get(),
            7552
        );
        assert_eq!(
            armory_row_pictures(MilitaryUnitKind::Saboteurs)[0].get(),
            7568
        );
    }
}
