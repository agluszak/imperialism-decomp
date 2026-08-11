use super::*;

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
    orders: Vec<CityOrderControl>,
    unit_name: Entity,
    description: Entity,
    workforce_cost: Entity,
    paper_cost: Entity,
    cash_cost: Entity,
    workforce_available: Entity,
    paper_available: Entity,
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

pub(in crate::ui::city) fn bind_university_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
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
    let root = bind_city_dialog_root(commands, spawned, nation, CityFacilitySlot::University);
    commands.entity(root).insert(UniversitySelection {
        kind: CivilianUnitKind::Miner,
    });
    let orders = bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        &UNIVERSITY_ORDERS,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    );
    let initial_preview = rows[0].preview.clone();
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
                    dialog: root,
                    kind,
                    unit_name: row_text.unit_name,
                    description: row_text.description,
                    preview: row_text.preview,
                },
                visibility,
            ));
            if kind == CivilianUnitKind::Miner {
                button_commands.insert(Checked);
            } else {
                button_commands.remove::<Checked>();
            }
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
            ImageNode::new(initial_preview),
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
    let tier_labels = std::array::from_fn(|index| {
        let tag = [fourcc!("fix2"), fourcc!("fix3"), fourcc!("fix4")][index];
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new(tier_label_texts[index].clone()),
            detail_font.clone(),
            TextLayout::justify(Justify::Center),
            TextColor(normal_color),
            Visibility::Hidden,
        ));
        entity
    });
    let bind_text = |commands: &mut Commands, tag, font: TextFont| {
        let entity = spawned.unique(tag);
        commands
            .entity(entity)
            .insert((Text::new(""), font, TextColor(normal_color)));
        entity
    };
    let unit_name = bind_text(commands, fourcc!("unit"), unit_font);
    let description = bind_text(commands, fourcc!("desc"), detail_font.clone());
    let workforce_cost = bind_text(commands, fourcc!("cexp"), detail_font.clone());
    let paper_cost = bind_text(commands, fourcc!("cpap"), detail_font.clone());
    let cash_cost = bind_text(commands, fourcc!("cash"), detail_font.clone());
    let workforce_available = bind_text(commands, fourcc!("aexp"), detail_font.clone());
    let paper_available = bind_text(commands, fourcc!("apap"), detail_font.clone());
    let treasury = bind_text(commands, fourcc!("trea"), detail_font.clone());
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
        orders,
        unit_name,
        description,
        workforce_cost,
        paper_cost,
        cash_cost,
        workforce_available,
        paper_available,
        treasury,
        preview,
        requirements,
        tier_labels,
        normal_color,
        warning_color,
    });
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn sync_university_dialog(
    session: Res<GameSession>,
    dialogs: Query<(
        Entity,
        &UniversityDialogControls,
        Ref<CityBuildingDialog>,
        Ref<UniversitySelection>,
    )>,
    rows: Query<&UniversityRowChoice>,
    mut texts: Query<&mut Text>,
    mut text_colors: Query<&mut TextColor>,
    mut images: Query<&mut ImageNode>,
    mut visibilities: Query<&mut Visibility>,
) {
    for (root, controls, dialog, selection) in &dialogs {
        if !session.is_changed()
            && !dialog.is_added()
            && !selection.is_added()
            && !selection.is_changed()
        {
            continue;
        }
        let major = session.0.nations().major(dialog.nation);
        let city = &major.city;
        for control in &controls.orders {
            let CityOrderId::CivilianRecruit(kind) = control.order else {
                unreachable!("University control has a civilian recruitment order");
            };
            texts
                .get_mut(control.quantity)
                .expect("University order quantity has text")
                .0 = city.orders.civilian_recruitment[kind].quantity.to_string();
        }

        let row = rows
            .iter()
            .find(|row| row.dialog == root && row.kind == selection.kind)
            .expect("University selection has a bound retail row");
        texts
            .get_mut(controls.unit_name)
            .expect("University unit name has text")
            .0
            .clone_from(&row.unit_name);
        texts
            .get_mut(controls.description)
            .expect("University description has text")
            .0
            .clone_from(&row.description);
        images
            .get_mut(controls.preview)
            .expect("University preview has an image")
            .image
            .clone_from(&row.preview);
        *visibilities
            .get_mut(controls.preview)
            .expect("University preview has visibility") = Visibility::Visible;

        let spec = civilian_recruitment_spec(selection.kind);
        let production = city.population.production_labor();
        let workforce_available = production.high.min(city.population.strength() / 4);
        for (entity, value) in [
            (controls.workforce_cost, 1),
            (controls.paper_cost, spec.primary.per_unit()),
            (controls.workforce_available, workforce_available),
            (
                controls.paper_available,
                city.stockpile[spec.primary.resource],
            ),
        ] {
            texts
                .get_mut(entity)
                .expect("University numeric control has text")
                .0 = value.to_string();
        }
        texts
            .get_mut(controls.cash_cost)
            .expect("University cash cost has text")
            .0 = format_currency(i32::from(spec.cash_per_unit));
        texts
            .get_mut(controls.treasury)
            .expect("University treasury has text")
            .0 = format_currency(major.common.treasury);
        for (entity, insufficient) in [
            (
                controls.paper_available,
                city.stockpile[spec.primary.resource] < spec.primary.per_unit(),
            ),
            (controls.workforce_available, workforce_available < 1),
            (
                controls.treasury,
                major.common.treasury < i32::from(spec.cash_per_unit),
            ),
        ] {
            text_colors
                .get_mut(entity)
                .expect("University available value has a text color")
                .0 = if insufficient {
                controls.warning_color
            } else {
                controls.normal_color
            };
        }

        let specialties = CIVILIAN_RESOURCE_SPECIALTIES[selection.kind];
        let levels = &session.0.technology().city_capabilities_by_nation[dialog.nation]
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
        for (index, entity) in controls.tier_labels.iter().copied().enumerate() {
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
