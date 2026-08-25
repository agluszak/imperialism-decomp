use super::*;
use crate::ui::retail::RetailPictureSwap;

#[derive(Component)]
pub(in crate::ui::city) struct TrainingView {
    rows: Vec<(CityOrderId, CityOrderRow)>,
    paper_one: Entity,
    paper_two: Entity,
    money_one: Entity,
    money_two: Entity,
    untrained_available: Entity,
    trained_available: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct ArmoryView {
    pub(in crate::ui::city) selected: CityOrderId,
    normal_color: Color,
    warning_color: Color,
    rows: Vec<(CityOrderId, CityOrderRow)>,
    unit_name: Entity,
    workforce_cost: Entity,
    primary_cost: Entity,
    secondary_cost: Entity,
    cash_cost: Entity,
    workforce_available: Entity,
    primary_available: Entity,
    secondary_available: Entity,
    treasury: Entity,
    firepower: Entity,
    action_points: Entity,
    range: Entity,
    static_text: Entity,
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
    let mut rows = Vec::new();
    for binding in TRAINING_ORDERS {
        rows.push((
            binding.order,
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
            ),
        ));
    }
    let paper_one = tree.find(root, fourcc!("pap1"));
    let paper_two = tree.find(root, fourcc!("pap2"));
    let money_one = tree.find(root, fourcc!("mon1"));
    let money_two = tree.find(root, fourcc!("mon2"));
    let untrained_available = tree.find(root, fourcc!("untV"));
    let trained_available = tree.find(root, fourcc!("traV"));
    for entity in [
        paper_one,
        paper_two,
        money_one,
        money_two,
        untrained_available,
        trained_available,
    ] {
        commands.entity(entity).insert(Text::new("X"));
    }
    commands.entity(root).insert(TrainingView {
        rows,
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
    let title_control = tree.find(root, fourcc!("titl"));
    commands.entity(title_control).insert((
        Text::new(title),
        title_font,
        title_line_height,
        TextColor(normal_color),
    ));
    let mut rows = Vec::new();
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
        button.observe(on_city_row_selected);
        commands.entity(bound.quantity).insert(InteractionDisabled);
        rows.push((row.binding.order, bound));
    }
    let bind_detail = |commands: &mut Commands, tag, font: TextFont, line_height| {
        let entity = tree.find(root, tag);
        commands
            .entity(entity)
            .insert((Text::new(""), font, line_height, TextColor(normal_color)));
        entity
    };
    let unit_name = bind_detail(commands, fourcc!("unit"), unit_font, unit_line_height);
    let workforce_cost = bind_detail(
        commands,
        fourcc!("cos0"),
        detail_font.clone(),
        detail_line_height,
    );
    let primary_cost = bind_detail(
        commands,
        fourcc!("cos1"),
        detail_font.clone(),
        detail_line_height,
    );
    let secondary_cost = bind_detail(
        commands,
        fourcc!("cos2"),
        detail_font.clone(),
        detail_line_height,
    );
    let cash_cost = bind_detail(
        commands,
        fourcc!("cos3"),
        detail_font.clone(),
        detail_line_height,
    );
    let workforce_available = bind_detail(
        commands,
        fourcc!("ava0"),
        detail_font.clone(),
        detail_line_height,
    );
    let primary_available = bind_detail(
        commands,
        fourcc!("ava1"),
        detail_font.clone(),
        detail_line_height,
    );
    let secondary_available = bind_detail(
        commands,
        fourcc!("ava2"),
        detail_font.clone(),
        detail_line_height,
    );
    let treasury = bind_detail(
        commands,
        fourcc!("ava3"),
        detail_font.clone(),
        detail_line_height,
    );
    let firepower = bind_detail(
        commands,
        fourcc!("sta0"),
        detail_font.clone(),
        detail_line_height,
    );
    let action_points = bind_detail(
        commands,
        fourcc!("sta1"),
        detail_font.clone(),
        detail_line_height,
    );
    let range = bind_detail(
        commands,
        fourcc!("sta2"),
        detail_font.clone(),
        detail_line_height,
    );
    let static_text = bind_detail(
        commands,
        fourcc!("sta3"),
        detail_font.clone(),
        detail_line_height,
    );
    let description = bind_detail(
        commands,
        fourcc!("desc"),
        detail_font.clone(),
        detail_line_height,
    );
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
    commands.entity(root).insert(ArmoryView {
        selected: CityOrderId::MilitaryRecruit(MilitaryRecruitmentCategory::LightInfantry),
        normal_color,
        warning_color,
        rows,
        unit_name,
        workforce_cost,
        primary_cost,
        secondary_cost,
        cash_cost,
        workforce_available,
        primary_available,
        secondary_available,
        treasury,
        firepower,
        action_points,
        range,
        static_text,
        description,
        placard,
    });
}

pub(in crate::ui::city) fn sync_training_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<TrainingView>>,
    views: Query<&TrainingView>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
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
    for view in &views {
        project_city_order_rows(
            &session,
            &mut texts,
            &view.rows,
            "training order quantity remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.paper_one,
            city.stockpile[ResourceKind::Paper] >= 1,
            "training paper warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.paper_two,
            city.stockpile[ResourceKind::Paper] >= 2,
            "training paper warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.money_one,
            budget >= 100,
            "training money warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.money_two,
            budget >= 1_000,
            "training money warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.untrained_available,
            production.low.min(strength) != 0,
            "training untrained warning remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.trained_available,
            production.medium.min(strength / 2) != 0,
            "training trained warning remains bound",
        );
    }
}

pub(in crate::ui::city) fn sync_armory_details(
    session: Res<GameSession>,
    views: Query<Ref<ArmoryView>>,
    mut assets: RetailUiAssets,
    mut texts: Query<&mut Text>,
    mut colors: Query<&mut TextColor>,
    mut visibilities: Query<&mut Visibility>,
    mut pictures: Query<&mut ImageNode>,
) {
    for view in &views {
        if !session.is_changed() && !view.is_changed() && !view.is_added() {
            continue;
        }
        let CityOrderId::MilitaryRecruit(category) = view.selected else {
            continue;
        };
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
        project_city_order_rows(
            &session,
            &mut texts,
            &view.rows,
            "armory order quantity remains bound",
        );
        let color = |warning| city_stock_color(warning, view.warning_color, view.normal_color);
        set_bound_text(
            &mut texts,
            view.unit_name,
            unit_name,
            "armory unit name remains bound",
        );
        set_bound_text(
            &mut texts,
            view.workforce_cost,
            1.to_string(),
            "armory workforce cost remains bound",
        );
        set_bound_text(
            &mut texts,
            view.primary_cost,
            spec.primary.per_unit().to_string(),
            "armory primary cost remains bound",
        );
        set_bound_text(
            &mut texts,
            view.secondary_cost,
            secondary
                .map(|item| item.per_unit().to_string())
                .unwrap_or_default(),
            "armory secondary cost remains bound",
        );
        set_bound_text(
            &mut texts,
            view.cash_cost,
            format_currency(i32::from(spec.cash_per_unit)),
            "armory cash cost remains bound",
        );
        set_bound_text(
            &mut texts,
            view.workforce_available,
            workforce_available.to_string(),
            "armory workforce available remains bound",
        );
        set_bound_text(
            &mut texts,
            view.primary_available,
            primary_available.to_string(),
            "armory primary available remains bound",
        );
        set_bound_text(
            &mut texts,
            view.secondary_available,
            secondary
                .map(|_| {
                    secondary_available
                        .expect("secondary item has availability")
                        .to_string()
                })
                .unwrap_or_default(),
            "armory secondary available remains bound",
        );
        set_bound_text(
            &mut texts,
            view.treasury,
            format_currency(major.common.treasury),
            "armory treasury remains bound",
        );
        set_bound_text(
            &mut texts,
            view.firepower,
            ARMORY_FIREPOWER[unit_index].to_string(),
            "armory firepower remains bound",
        );
        set_bound_text(
            &mut texts,
            view.action_points,
            ARMORY_ACTION_POINTS[unit_index].to_string(),
            "armory action points remain bound",
        );
        set_bound_text(
            &mut texts,
            view.range,
            ARMORY_RANGE[unit_index].to_string(),
            "armory range remains bound",
        );
        set_bound_text(
            &mut texts,
            view.static_text,
            static_text,
            "armory static flag remains bound",
        );
        set_bound_text(
            &mut texts,
            view.description,
            description,
            "armory description remains bound",
        );
        set_bound_text_color(
            &mut colors,
            view.workforce_available,
            color(workforce_available == 0),
            "armory workforce available remains bound",
        );
        set_bound_text_color(
            &mut colors,
            view.primary_available,
            color(primary_available < spec.primary.per_unit()),
            "armory primary available remains bound",
        );
        // Retail compares both material columns against the primary input amount.
        set_bound_text_color(
            &mut colors,
            view.secondary_available,
            color(secondary_available.is_some_and(|available| available < spec.primary.per_unit())),
            "armory secondary available remains bound",
        );
        set_bound_text_color(
            &mut colors,
            view.treasury,
            color(major.common.treasury < i32::from(spec.cash_per_unit)),
            "armory treasury remains bound",
        );
        pictures
            .get_mut(view.placard)
            .expect("armory placard remains bound")
            .image = assets
            .picture(PictureId::new(0x1d9c + i16::from(order.unit_kind.retail())))
            .expect("retail Armory unit placard");
        let secondary_visible = secondary.is_some();
        set_bound_visible(
            &mut visibilities,
            view.secondary_cost,
            secondary_visible,
            "armory secondary cost remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.secondary_available,
            secondary_visible,
            "armory secondary available remains bound",
        );
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
