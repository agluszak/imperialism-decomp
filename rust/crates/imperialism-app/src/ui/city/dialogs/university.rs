use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct UniversitySelection {
    pub(in crate::ui::city) kind: CivilianUnitKind,
}

#[derive(Component)]
pub(in crate::ui::city) struct UniversityRowChoice {
    pub(in crate::ui::city) kind: CivilianUnitKind,
    pub(in crate::ui::city) unit_name: String,
    pub(in crate::ui::city) description: String,
    pub(in crate::ui::city) preview: Handle<Image>,
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
    pub(in crate::ui::city) unit_font: TextFont,
    pub(in crate::ui::city) detail_font: TextFont,
    pub(in crate::ui::city) normal_color: Color,
    pub(in crate::ui::city) warning_color: Color,
}

#[derive(Clone, Copy)]
struct UniversityRequirementControls {
    icon: Entity,
    values: [Entity; 3],
}

#[derive(Component)]
pub(in crate::ui::city) struct UniversityDialogControls {
    preview: Entity,
    requirements: [UniversityRequirementControls; 4],
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

pub(in crate::ui::city) fn university_dialog_data(
    ui: &mut UiSpawner,
    state: &GameState,
    nation: MajorNationId,
) -> UniversityDialogData {
    let (detail_font, _, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        })
        .expect("retail University detail text style");
    let (title_font, _, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 24,
            alignment: 1,
        })
        .expect("retail University title fallback text style");
    let (unit_font, _, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail University unit-name fallback text style");
    UniversityDialogData {
        available: state.technology().city_capabilities_by_nation[nation]
            .university
            .available,
        rows: UNIVERSITY_ORDERS.map(|binding| {
            let CityOrderId::CivilianRecruit(kind) = binding.order else {
                unreachable!("University binding has a civilian recruitment order");
            };
            UniversityRowText {
                unit_name: ui
                    .string(0x2718, i16::from(kind as u8) + 1)
                    .expect("retail civilian name"),
                description: ui
                    .string(0x2751, i16::from(kind as u8))
                    .expect("retail civilian description"),
                preview: transparent_picture(ui, PictureId::new(university_preview_picture(kind))),
            }
        }),
        resource_icons: transparent_picture(ui, PictureId::new(750)),
        tier_labels: std::array::from_fn(|level| {
            ui.string(0x2723, 0x0e + level as i16)
                .expect("retail University tier label")
        }),
        title_font,
        unit_font,
        detail_font,
        normal_color: ui.palette_color(0xd2),
        warning_color: ui.palette_color(0xcb),
    }
}

pub(in crate::ui::city) fn bind_university_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    data: UniversityDialogData,
) {
    let UniversityDialogData {
        available,
        rows,
        resource_icons,
        tier_labels: tier_label_texts,
        title_font,
        unit_font,
        detail_font,
        normal_color,
        warning_color,
    } = data;
    let root = bind_city_dialog_root(commands, spawned, CityFacilitySlot::University);
    commands.entity(root).insert(UniversitySelection {
        kind: CivilianUnitKind::Miner,
    });
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        &UNIVERSITY_ORDERS,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    );
    for (binding, row_text) in UNIVERSITY_ORDERS.iter().zip(rows) {
        let CityOrderId::CivilianRecruit(kind) = binding.order else {
            unreachable!("University binding has a civilian recruitment order");
        };
        let button = spawned.unique(university_button_tag(kind));
        let row = spawned.unique(binding.tag);
        let minus = spawned.under(catalog, binding.tag, fourcc!("minu"));
        let plus = spawned.under(catalog, binding.tag, fourcc!("plus"));
        let quantity = spawned.under(catalog, binding.tag, fourcc!("numb"));
        let row_available = available[kind];
        let visibility = if row_available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        {
            let mut button_commands = commands.entity(button);
            button_commands.insert((
                UniversityRowChoice {
                    kind,
                    unit_name: row_text.unit_name,
                    description: row_text.description,
                    preview: row_text.preview,
                },
                visibility,
            ));
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
            InteractionDisabled,
            detail_font.clone(),
            TextColor(normal_color),
        ));
    }
    let dlog = spawned.unique(fourcc!("DLOG"));
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
    for (index, text) in tier_label_texts.into_iter().enumerate() {
        let tag = [fourcc!("fix2"), fourcc!("fix3"), fourcc!("fix4")][index];
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new(text),
            detail_font.clone(),
            TextLayout::justify(Justify::Center),
            TextColor(normal_color),
            Visibility::Hidden,
        ));
    }
    let style_text = |commands: &mut Commands, tag, font: TextFont| {
        let entity = spawned.unique(tag);
        commands
            .entity(entity)
            .insert((Text::new(""), font, TextColor(normal_color)));
    };
    style_text(commands, fourcc!("unit"), unit_font);
    for tag in [
        fourcc!("desc"),
        fourcc!("cexp"),
        fourcc!("cpap"),
        fourcc!("cash"),
        fourcc!("aexp"),
        fourcc!("apap"),
        fourcc!("trea"),
    ] {
        style_text(commands, tag, detail_font.clone());
    }
    let title = spawned.unique(fourcc!("titl"));
    commands
        .entity(title)
        .insert((title_font, TextColor(normal_color)));
    for tag in [fourcc!("fix0"), fourcc!("fix1")] {
        let fixed = spawned.unique(tag);
        commands
            .entity(fixed)
            .insert((detail_font.clone(), TextColor(normal_color)));
    }
    commands.entity(root).insert(UniversityDialogControls {
        preview,
        requirements,
        normal_color,
        warning_color,
    });
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn sync_university_dialog(
    mut commands: Commands,
    session: Res<GameSession>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(
        &SpawnedView,
        &UniversityDialogControls,
        Ref<UniversitySelection>,
    )>,
    rows: Query<(&UniversityRowChoice, Has<Checked>)>,
    mut texts: Query<&mut Text>,
    mut text_colors: Query<&mut TextColor>,
    mut images: Query<&mut ImageNode>,
    mut visibilities: Query<&mut Visibility>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City screen requires an active major nation");
    for (spawned, controls, selection) in &dialogs {
        if !session.is_changed() && !selection.is_changed() {
            continue;
        }
        let major = session.0.nations().major(nation);
        let city = &major.city;
        for binding in UNIVERSITY_ORDERS {
            let CityOrderId::CivilianRecruit(kind) = binding.order else {
                unreachable!("University control has a civilian recruitment order");
            };
            texts
                .get_mut(spawned.under(&catalog, binding.tag, fourcc!("numb")))
                .expect("University order quantity has text")
                .0 = city.orders.civilian_recruitment[kind].quantity.to_string();
        }

        for binding in UNIVERSITY_ORDERS {
            let CityOrderId::CivilianRecruit(kind) = binding.order else {
                unreachable!("University binding has a civilian recruitment order");
            };
            let button = spawned.unique(university_button_tag(kind));
            let (_, checked) = rows
                .get(button)
                .expect("University button has its retail row data");
            if checked != (kind == selection.kind) {
                if checked {
                    commands.entity(button).remove::<Checked>();
                } else {
                    commands.entity(button).insert(Checked);
                }
            }
        }
        let (row, _) = rows
            .get(spawned.unique(university_button_tag(selection.kind)))
            .expect("University selection has a bound retail row");
        texts
            .get_mut(spawned.unique(fourcc!("unit")))
            .expect("University unit name has text")
            .0
            .clone_from(&row.unit_name);
        texts
            .get_mut(spawned.unique(fourcc!("desc")))
            .expect("University description has text")
            .0
            .clone_from(&row.description);
        images
            .get_mut(controls.preview)
            .expect("University preview has an image")
            .image
            .clone_from(&row.preview);

        let spec = civilian_recruitment_spec(selection.kind);
        let production = city.population.production_labor();
        let workforce_available = production.high.min(city.population.strength() / 4);
        for (tag, value) in [
            (fourcc!("cexp"), 1),
            (fourcc!("cpap"), spec.primary.per_unit()),
            (fourcc!("aexp"), workforce_available),
            (fourcc!("apap"), city.stockpile[spec.primary.resource]),
        ] {
            texts
                .get_mut(spawned.unique(tag))
                .expect("University numeric control has text")
                .0 = value.to_string();
        }
        texts
            .get_mut(spawned.unique(fourcc!("cash")))
            .expect("University cash cost has text")
            .0 = format_currency(i32::from(spec.cash_per_unit));
        texts
            .get_mut(spawned.unique(fourcc!("trea")))
            .expect("University treasury has text")
            .0 = format_currency(major.common.treasury);
        for (tag, insufficient) in [
            (
                fourcc!("apap"),
                city.stockpile[spec.primary.resource] < spec.primary.per_unit(),
            ),
            (fourcc!("aexp"), workforce_available < 1),
            (
                fourcc!("trea"),
                major.common.treasury < i32::from(spec.cash_per_unit),
            ),
        ] {
            text_colors
                .get_mut(spawned.unique(tag))
                .expect("University available value has a text color")
                .0 = if insufficient {
                controls.warning_color
            } else {
                controls.normal_color
            };
        }

        let specialties = CIVILIAN_RESOURCE_SPECIALTIES[selection.kind];
        let levels = &session.0.technology().city_capabilities_by_nation[nation]
            .university
            .requirement_levels;
        for (row_index, requirement) in controls.requirements.iter().enumerate() {
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
        for (index, tag) in [fourcc!("fix2"), fourcc!("fix3"), fourcc!("fix4")]
            .into_iter()
            .enumerate()
        {
            *visibilities
                .get_mut(spawned.unique(tag))
                .expect("University tier label has visibility") = if (index as u8) < maximum {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        }
    }
}
