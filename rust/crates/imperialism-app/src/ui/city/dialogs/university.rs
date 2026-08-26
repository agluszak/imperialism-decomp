use super::*;

/// One University row's button and quantity marker.
struct UniversityRowView {
    button: Entity,
    quantity: Entity,
}

/// Root view of the University dialog.
#[derive(Component)]
pub(in crate::ui::city) struct UniversityView {
    selected: CivilianUnitKind,
    rows: [UniversityRowView; UNIVERSITY_ROWS.len()],
    unit: Entity,
    description: Entity,
    costs: [Entity; 3],
    available: [Entity; 3],
    tier_labels: [Entity; 3],
    preview: Entity,
    icons: [Entity; 4],
    yields: [[Entity; 3]; 4],
}

pub(in crate::ui::city) const fn university_preview_picture(kind: CivilianUnitKind) -> i16 {
    match kind {
        CivilianUnitKind::Miner => 402,
        CivilianUnitKind::Prospector => 403,
        CivilianUnitKind::Farmer => 401,
        CivilianUnitKind::Forester => 406,
        CivilianUnitKind::Engineer => 400,
        CivilianUnitKind::Rancher => 407,
        CivilianUnitKind::Fisherman => 405,
        CivilianUnitKind::Developer => 404,
        CivilianUnitKind::Driller => 408,
    }
}

fn spawn_detail_child(
    commands: &mut Commands,
    parent: Entity,
    left: f32,
    top: f32,
    width: f32,
    height: f32,
    bundle: impl Bundle,
) -> Entity {
    commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: px(left),
                top: px(top),
                width: px(width),
                height: px(height),
                ..default()
            },
            bundle,
            Pickable::IGNORE,
            ChildOf(parent),
        ))
        .id()
}

pub(in crate::ui::city) fn configure_university_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("City active nation is a major nation");
    let available = state.technology().city_capabilities_by_nation[nation]
        .university
        .available;
    let rows = UNIVERSITY_ROWS.map(|row| {
        let kind = row.civilian_kind();
        let bound = bind_city_order_row(
            commands,
            root,
            tree,
            row.binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
        );
        for tag in [fourcc!("minu"), fourcc!("plus")] {
            commands.entity(tree.find(bound.row, tag)).observe(
                move |_: On<Activate>, mut views: Query<&mut UniversityView>| {
                    if let Ok(mut view) = views.get_mut(root) {
                        view.selected = kind;
                    }
                },
            );
        }
        let button = tree.find(root, row.button_tag);
        let row_available = available[kind];
        bound.set_available(commands, row_available);
        let mut button_commands = commands.entity(button);
        button_commands.insert(if row_available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
        button_commands.observe(
            move |change: On<ValueChange<bool>>, mut views: Query<&mut UniversityView>| {
                if change.value
                    && let Ok(mut view) = views.get_mut(root)
                {
                    view.selected = kind;
                }
            },
        );
        if row_available {
            button_commands.remove::<InteractionDisabled>();
        } else {
            button_commands.insert(InteractionDisabled);
        }
        commands.entity(bound.quantity).insert(InteractionDisabled);
        UniversityRowView {
            button,
            quantity: bound.quantity,
        }
    });
    let dlog = tree.find(root, fourcc!("DLOG"));
    commands.entity(dlog).insert(ImageNode::new(
        assets
            .picture(PictureId::new(9900))
            .expect("retail University dialog picture must load"),
    ));
    let resource_icons = assets
        .picture(PictureId::new(750))
        .expect("retail University resource icons must load");
    let (yield_font, yield_layout, yield_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        })
        .expect("retail University yield text style");
    let yield_cell = match yield_line_height {
        bevy::text::LineHeight::Px(pixels) => pixels,
        _ => 10.0,
    };
    let preview = spawn_detail_child(
        commands,
        dlog,
        0x7c as f32,
        0x5c as f32,
        0.0,
        0.0,
        ImageNode::new(
            assets
                .picture(PictureId::new(university_preview_picture(
                    CivilianUnitKind::Miner,
                )))
                .expect("retail University preview picture must load"),
        ),
    );
    let icons = std::array::from_fn(|row_index| {
        let icon = spawn_detail_child(
            commands,
            dlog,
            25.0,
            274.0 + row_index as f32 * 25.0,
            20.0,
            24.0,
            ImageNode::new(resource_icons.clone()),
        );
        commands.entity(icon).insert(Visibility::Hidden);
        icon
    });
    let yields = std::array::from_fn(|row_index| {
        std::array::from_fn(|level| {
            let slot = spawn_detail_child(
                commands,
                dlog,
                level as f32 * 40.0 + 39.0,
                289.0 + row_index as f32 * 25.0 - yield_cell,
                40.0,
                yield_cell,
                (
                    Text::new(""),
                    yield_font.clone(),
                    yield_layout,
                    yield_line_height,
                    TextColor(assets.palette_color(0xd2)),
                ),
            );
            commands.entity(slot).insert(Visibility::Hidden);
            slot
        })
    });
    let mut bind_text = |tag| {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(""));
        entity
    };
    let unit = bind_text(fourcc!("unit"));
    let description = bind_text(fourcc!("desc"));
    let costs = [
        bind_text(fourcc!("cexp")),
        bind_text(fourcc!("cpap")),
        bind_text(fourcc!("cash")),
    ];
    let available = [
        bind_text(fourcc!("aexp")),
        bind_text(fourcc!("apap")),
        bind_text(fourcc!("trea")),
    ];
    let tier_labels = [
        tree.find(root, fourcc!("fix2")),
        tree.find(root, fourcc!("fix3")),
        tree.find(root, fourcc!("fix4")),
    ];
    for entity in &tier_labels {
        commands.entity(*entity).insert(Visibility::Hidden);
    }
    commands.entity(root).insert(UniversityView {
        selected: CivilianUnitKind::Miner,
        rows,
        unit,
        description,
        costs,
        available,
        tier_labels,
        preview,
        icons,
        yields,
    });
}

pub(in crate::ui::city) fn render_university_dialog(
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
    views: Query<Ref<UniversityView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut text_colors: Query<&mut TextColor>,
    mut visibilities: Query<&mut Visibility>,
    mut images: Query<&mut ImageNode>,
    checked: Query<Has<Checked>>,
) {
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    for view in &views {
        if !session.is_changed() && !view.is_added() && !view.is_changed() {
            continue;
        }
        let nation = session.active_major_nation();
        for (row, view_row) in UNIVERSITY_ROWS.iter().zip(&view.rows) {
            let selected = row.civilian_kind() == view.selected;
            let is_checked = checked.get(view_row.button).unwrap_or(false);
            if selected && !is_checked {
                commands.entity(view_row.button).insert(Checked);
            } else if !selected && is_checked {
                commands.entity(view_row.button).remove::<Checked>();
            }
            texts
                .get_mut(view_row.quantity)
                .expect("bound University order quantity")
                .0 = session
                .game
                .city_order_quantity(nation, row.binding.order)
                .to_string();
        }
        let kind = view.selected;
        let major = session.game.nations().major(nation);
        let city = &major.city;
        let spec = civilian_recruitment_spec(kind);
        let production = city.population.production_labor();
        let workforce_available = production.high.min(city.population.strength() / 4);
        let specialties = CIVILIAN_RESOURCE_SPECIALTIES[kind];
        let levels = &session.game.technology().city_capabilities_by_nation[nation]
            .university
            .requirement_levels;
        let maximum = specialties
            .iter()
            .flatten()
            .map(|resource| levels[*resource])
            .max()
            .unwrap_or(UniversityRequirementLevel::None);
        let unit_name = assets
            .string(0x2718, i16::from(kind.retail()) + 1)
            .expect("retail civilian name");
        let description = assets
            .string(0x2751, i16::from(kind.retail()) + 1)
            .expect("retail civilian description");
        texts
            .get_mut(view.unit)
            .expect("bound University unit name")
            .0
            .clone_from(&unit_name);
        texts
            .get_mut(view.description)
            .expect("bound University description")
            .0
            .clone_from(&description);
        let values = [
            1.to_string(),
            spec.primary.per_unit().to_string(),
            format_currency(i32::from(spec.cash_per_unit)),
            workforce_available.to_string(),
            city.stockpile[spec.primary.resource].to_string(),
            format_currency(major.common.treasury),
        ];
        for (entity, value) in view.costs.iter().chain(&view.available).zip(&values) {
            texts
                .get_mut(*entity)
                .expect("bound University detail")
                .0
                .clone_from(value);
        }
        let insufficiencies = [
            workforce_available < 1,
            city.stockpile[spec.primary.resource] < spec.primary.per_unit(),
            major.common.treasury < i32::from(spec.cash_per_unit),
        ];
        for (entity, insufficient) in view.available.iter().zip(&insufficiencies) {
            text_colors
                .get_mut(*entity)
                .expect("bound University availability")
                .0 = if *insufficient {
                warning_color
            } else {
                normal_color
            };
        }
        for (entity, index) in view.tier_labels.iter().zip(0..3) {
            *visibilities
                .get_mut(*entity)
                .expect("bound University tier label") = if (index as u8) < maximum.retail() {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
        images
            .get_mut(view.preview)
            .expect("bound University preview")
            .image = assets
            .picture(PictureId::new(university_preview_picture(kind)))
            .expect("retail University preview picture must load");
        let mut running_max = UniversityRequirementLevel::None;
        for (row_index, resource) in specialties.into_iter().enumerate() {
            let Some(resource) = resource else {
                *visibilities
                    .get_mut(view.icons[row_index])
                    .expect("bound University specialty icon") = Visibility::Hidden;
                for level in 0..3 {
                    *visibilities
                        .get_mut(view.yields[row_index][level])
                        .expect("bound University yield") = Visibility::Hidden;
                }
                continue;
            };
            let source_left = i32::from(resource.retail()) * 20;
            images
                .get_mut(view.icons[row_index])
                .expect("bound University specialty icon")
                .rect = Some(Rect::new(
                source_left as f32,
                0.0,
                (source_left + 20) as f32,
                24.0,
            ));
            *visibilities
                .get_mut(view.icons[row_index])
                .expect("bound University specialty icon") = Visibility::Visible;
            running_max = running_max.max(levels[resource]);
            let shown = running_max.retail();
            for level in 0..3 {
                let slot = view.yields[row_index][level];
                if (level as u8) < shown {
                    *visibilities.get_mut(slot).expect("bound University yield") =
                        Visibility::Visible;
                    texts.get_mut(slot).expect("bound University yield").0 =
                        resource_development_yield(resource, level as u8 + 1).to_string();
                } else {
                    *visibilities.get_mut(slot).expect("bound University yield") =
                        Visibility::Hidden;
                }
            }
        }
    }
}
