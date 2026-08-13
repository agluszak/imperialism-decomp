use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct UniversityRowChoice {
    pub(in crate::ui::city) kind: CivilianUnitKind,
}

pub(in crate::ui::city) struct UniversityRowText {
    pub(in crate::ui::city) unit_name: String,
    pub(in crate::ui::city) description: String,
    pub(in crate::ui::city) preview: Handle<Image>,
}

pub(in crate::ui::city) struct UniversityDialogData {
    pub(in crate::ui::city) available: CivilianUnitTable<bool>,
    pub(in crate::ui::city) rows: [UniversityRowText; UNIVERSITY_ORDERS.len()],
    pub(in crate::ui::city) resource_icons: Handle<Image>,
    pub(in crate::ui::city) tier_labels: [String; 3],
    pub(in crate::ui::city) title_font: TextFont,
    pub(in crate::ui::city) title_line_height: LineHeight,
    pub(in crate::ui::city) unit_font: TextFont,
    pub(in crate::ui::city) unit_line_height: LineHeight,
    pub(in crate::ui::city) detail_font: TextFont,
    pub(in crate::ui::city) detail_line_height: LineHeight,
    pub(in crate::ui::city) normal_color: Color,
    pub(in crate::ui::city) warning_color: Color,
}

#[derive(Clone, Copy)]
struct UniversityRequirementControls {
    icon: Entity,
    values: [Entity; 3],
}

struct UniversityRow {
    unit_name: String,
    description: String,
    preview: Handle<Image>,
    button: Entity,
    quantity: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct UniversityView {
    pub(in crate::ui::city) kind: CivilianUnitKind,
    rows: CivilianUnitTable<Option<UniversityRow>>,
    unit_name: Entity,
    description: Entity,
    labor_cost: Entity,
    material_cost: Entity,
    cash_cost: Entity,
    labor_available: Entity,
    material_available: Entity,
    treasury: Entity,
    preview: Entity,
    requirements: [UniversityRequirementControls; 4],
    tier_labels: [Entity; 3],
    normal_color: Color,
    warning_color: Color,
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

pub(in crate::ui::city) fn configure_university_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    state: &GameState,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("City active nation is a major nation");
    let (detail_font, _, detail_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        })
        .expect("retail University detail text style");
    let (title_font, _, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 24,
            alignment: 1,
        })
        .expect("retail University title fallback text style");
    let (unit_font, _, unit_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail University unit-name fallback text style");
    let data = UniversityDialogData {
        available: state.technology().city_capabilities_by_nation[nation]
            .university
            .available,
        rows: UNIVERSITY_ORDERS.map(|binding| {
            let CityOrderId::CivilianRecruit(kind) = binding.order else {
                unreachable!("University binding has a civilian recruitment order");
            };
            UniversityRowText {
                unit_name: assets
                    .string(0x2718, i16::from(kind as u8) + 1)
                    .expect("retail civilian name"),
                description: assets
                    .string(0x2751, i16::from(kind as u8))
                    .expect("retail civilian description"),
                preview: transparent_picture(
                    assets,
                    PictureId::new(university_preview_picture(kind)),
                ),
            }
        }),
        resource_icons: transparent_picture(assets, PictureId::new(750)),
        tier_labels: std::array::from_fn(|level| {
            assets
                .string(0x2723, 0x0e + level as i16)
                .expect("retail University tier label")
        }),
        title_font,
        title_line_height,
        unit_font,
        unit_line_height,
        detail_font,
        detail_line_height,
        normal_color: assets.palette_color(0xd2),
        warning_color: assets.palette_color(0xcb),
    };
    bind_university_dialog(commands, root, children, tags, data);
}

pub(in crate::ui::city) fn bind_university_dialog(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    data: UniversityDialogData,
) {
    let UniversityDialogData {
        available,
        rows,
        resource_icons,
        tier_labels: tier_label_texts,
        title_font,
        title_line_height,
        unit_font,
        unit_line_height,
        detail_font,
        detail_line_height,
        normal_color,
        warning_color,
    } = data;
    bind_city_dialog_root(commands, root, children, tags, CityFacilitySlot::University);
    let mut rows_by_kind = CivilianUnitTable::default();
    for (binding, row_text) in UNIVERSITY_ORDERS.iter().zip(rows) {
        let CityOrderId::CivilianRecruit(kind) = binding.order else {
            unreachable!("University binding has a civilian recruitment order");
        };
        let button = find_descendant(root, university_button_tag(kind), children, tags);
        let row = find_descendant(root, binding.tag, children, tags);
        let minus = find_descendant(row, fourcc!("minu"), children, tags);
        let plus = find_descendant(row, fourcc!("plus"), children, tags);
        let quantity = find_descendant(row, fourcc!("numb"), children, tags);
        commands.entity(minus).insert(CityOrderAdjust {
            order: binding.order,
            delta: -1,
        });
        commands.entity(plus).insert(CityOrderAdjust {
            order: binding.order,
            delta: 1,
        });
        let row_available = available[kind];
        let visibility = if row_available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        {
            let mut button_commands = commands.entity(button);
            button_commands.insert((UniversityRowChoice { kind }, visibility));
            if row_available {
                button_commands.remove::<InteractionDisabled>();
            } else {
                button_commands.insert(InteractionDisabled);
            }
        }
        commands.entity(row).insert(visibility);
        for control in [minus, plus] {
            if row_available {
                commands.entity(control).remove::<InteractionDisabled>();
            } else {
                commands.entity(control).insert(InteractionDisabled);
            }
        }
        commands.entity(quantity).insert((
            Text::new(""),
            InteractionDisabled,
            detail_font.clone(),
            detail_line_height,
            TextColor(normal_color),
        ));
        rows_by_kind[kind] = Some(UniversityRow {
            unit_name: row_text.unit_name,
            description: row_text.description,
            preview: row_text.preview,
            button,
            quantity,
        });
    }
    let dlog = find_descendant(root, fourcc!("DLOG"), children, tags);
    let preview = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(124.0),
                top: Val::Px(92.0),
                width: Val::Px(64.0),
                height: Val::Px(64.0),
                ..default()
            },
            ImageNode::default(),
            Pickable::IGNORE,
            ZIndex(1),
            ChildOf(dlog),
            Name::new("university-civilian-preview"),
        ))
        .id();
    let requirements = std::array::from_fn(|row| {
        let icon = commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(25.0),
                    top: Val::Px(274.0 + row as f32 * 25.0),
                    width: Val::Px(20.0),
                    height: Val::Px(28.0),
                    ..default()
                },
                ImageNode {
                    image: resource_icons.clone(),
                    rect: Some(Rect::new(0.0, 0.0, 20.0, 24.0)),
                    ..default()
                },
                Visibility::Hidden,
                Pickable::IGNORE,
                ZIndex(1),
                ChildOf(dlog),
                Name::new(format!("university-requirement-icon-{row}")),
            ))
            .id();
        let values = std::array::from_fn(|level| {
            let level = level as u8 + 1;
            commands
                .spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        left: Val::Px(79.0 + f32::from(level - 1) * 40.0),
                        top: Val::Px(279.0 + row as f32 * 25.0),
                        width: Val::Px(24.0),
                        height: Val::Px(16.0),
                        ..default()
                    },
                    Text::new(""),
                    detail_font.clone(),
                    detail_line_height,
                    TextLayout::justify(Justify::Left),
                    TextColor(normal_color),
                    Visibility::Hidden,
                    Pickable::IGNORE,
                    ZIndex(1),
                    ChildOf(dlog),
                    Name::new(format!("university-requirement-{row}-{level}")),
                ))
                .id()
        });
        UniversityRequirementControls { icon, values }
    });
    let tier_labels = [
        find_descendant(root, fourcc!("fix2"), children, tags),
        find_descendant(root, fourcc!("fix3"), children, tags),
        find_descendant(root, fourcc!("fix4"), children, tags),
    ];
    for (entity, text) in tier_labels.into_iter().zip(tier_label_texts) {
        commands.entity(entity).insert((
            Text::new(text),
            detail_font.clone(),
            detail_line_height,
            TextLayout::justify(Justify::Center),
            TextColor(normal_color),
            Visibility::Hidden,
        ));
    }
    let style_text = |commands: &mut Commands, tag, font: TextFont, line_height: LineHeight| {
        let entity = find_descendant(root, tag, children, tags);
        commands
            .entity(entity)
            .insert((Text::new(""), font, line_height, TextColor(normal_color)));
        entity
    };
    let unit_name = style_text(commands, fourcc!("unit"), unit_font, unit_line_height);
    let [
        description,
        labor_cost,
        material_cost,
        cash_cost,
        labor_available,
        material_available,
        treasury,
    ] = [
        fourcc!("desc"),
        fourcc!("cexp"),
        fourcc!("cpap"),
        fourcc!("cash"),
        fourcc!("aexp"),
        fourcc!("apap"),
        fourcc!("trea"),
    ]
    .map(|tag| style_text(commands, tag, detail_font.clone(), detail_line_height));
    let title = find_descendant(root, fourcc!("titl"), children, tags);
    commands
        .entity(title)
        .insert((title_font, title_line_height, TextColor(normal_color)));
    for tag in [fourcc!("fix0"), fourcc!("fix1")] {
        let fixed = find_descendant(root, tag, children, tags);
        commands.entity(fixed).insert((
            detail_font.clone(),
            detail_line_height,
            TextColor(normal_color),
        ));
    }
    commands.entity(root).insert(UniversityView {
        kind: CivilianUnitKind::Miner,
        rows: rows_by_kind,
        unit_name,
        description,
        labor_cost,
        material_cost,
        cash_cost,
        labor_available,
        material_available,
        treasury,
        preview,
        requirements,
        tier_labels,
        normal_color,
        warning_color,
    });
}

pub(in crate::ui::city) fn on_university_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<&UniversityRowChoice>,
    mut views: Query<&mut UniversityView>,
) {
    if !change.value {
        return;
    }
    let Ok(row) = rows.get(change.source) else {
        return;
    };
    views
        .single_mut()
        .expect("University row has one open University dialog")
        .kind = row.kind;
}

pub(in crate::ui::city) fn on_university_order_selected(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    mut views: Query<&mut UniversityView>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let CityOrderId::CivilianRecruit(kind) = action.order else {
        return;
    };
    views
        .single_mut()
        .expect("University order has one open University dialog")
        .kind = kind;
}

pub(in crate::ui::city) fn sync_university_dialog(
    mut commands: Commands,
    session: Res<GameSession>,
    dialogs: Query<Ref<UniversityView>>,
    mut texts: Query<&mut Text>,
    mut text_colors: Query<&mut TextColor>,
    mut images: Query<&mut ImageNode>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    for view in &dialogs {
        if !session.is_changed() && !view.is_changed() {
            continue;
        }
        let major = session.0.nations().major(nation);
        let city = &major.city;
        for binding in UNIVERSITY_ORDERS {
            let CityOrderId::CivilianRecruit(kind) = binding.order else {
                unreachable!("University control has a civilian recruitment order");
            };
            let row = view.rows[kind]
                .as_ref()
                .expect("University order has a retained row");
            texts
                .get_mut(row.quantity)
                .expect("University order quantity has text")
                .0 = city.orders.civilian_recruitment[kind].quantity.to_string();
            if kind == view.kind {
                commands.entity(row.button).insert(Checked);
            } else {
                commands.entity(row.button).remove::<Checked>();
            }
        }
        let row = view.rows[view.kind]
            .as_ref()
            .expect("University selection has a bound retail row");
        texts
            .get_mut(view.unit_name)
            .expect("University unit name has text")
            .0
            .clone_from(&row.unit_name);
        texts
            .get_mut(view.description)
            .expect("University description has text")
            .0
            .clone_from(&row.description);
        images
            .get_mut(view.preview)
            .expect("University preview has an image")
            .image
            .clone_from(&row.preview);

        let spec = civilian_recruitment_spec(view.kind);
        let production = city.population.production_labor();
        let workforce_available = production.high.min(city.population.strength() / 4);
        for (entity, value) in [
            (view.labor_cost, 1),
            (view.material_cost, spec.primary.per_unit()),
            (view.labor_available, workforce_available),
            (
                view.material_available,
                city.stockpile[spec.primary.resource],
            ),
        ] {
            texts
                .get_mut(entity)
                .expect("University numeric control has text")
                .0 = value.to_string();
        }
        texts
            .get_mut(view.cash_cost)
            .expect("University cash cost has text")
            .0 = format_currency(i32::from(spec.cash_per_unit));
        texts
            .get_mut(view.treasury)
            .expect("University treasury has text")
            .0 = format_currency(major.common.treasury);
        for (entity, insufficient) in [
            (
                view.material_available,
                city.stockpile[spec.primary.resource] < spec.primary.per_unit(),
            ),
            (view.labor_available, workforce_available < 1),
            (
                view.treasury,
                major.common.treasury < i32::from(spec.cash_per_unit),
            ),
        ] {
            text_colors
                .get_mut(entity)
                .expect("University available value has a text color")
                .0 = if insufficient {
                view.warning_color
            } else {
                view.normal_color
            };
        }

        let specialties = CIVILIAN_RESOURCE_SPECIALTIES[view.kind];
        let levels = &session.0.technology().city_capabilities_by_nation[nation]
            .university
            .requirement_levels;
        for (row_index, requirement) in view.requirements.iter().enumerate() {
            let resource = specialties[row_index];
            if let Some(resource) = resource {
                let source_left = f32::from(resource as u8) * 20.0;
                images
                    .get_mut(requirement.icon)
                    .expect("University requirement icon has an image")
                    .rect = Some(Rect::new(source_left, 0.0, source_left + 20.0, 24.0));
            }
            *visibilities
                .get_mut(requirement.icon)
                .expect("University requirement icon has visibility") = if resource.is_some() {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };

            let running_max = specialties[..=row_index]
                .iter()
                .flatten()
                .map(|resource| levels[*resource])
                .max()
                .unwrap_or(0);
            for (level_index, entity) in requirement.values.iter().copied().enumerate() {
                let level = level_index as u8 + 1;
                let visible = resource.is_some() && level <= running_max;
                if let Some(resource) = resource
                    && visible
                {
                    texts
                        .get_mut(entity)
                        .expect("University requirement value has text")
                        .0 = resource_development_yield(resource, level).to_string();
                }
                *visibilities
                    .get_mut(entity)
                    .expect("University requirement value has visibility") = if visible {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
            }
        }
        let maximum = specialties
            .iter()
            .flatten()
            .map(|resource| levels[*resource])
            .max()
            .unwrap_or(0);
        for (index, entity) in view.tier_labels.into_iter().enumerate() {
            *visibilities
                .get_mut(entity)
                .expect("University tier label has visibility") = if (index as u8) < maximum {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}
