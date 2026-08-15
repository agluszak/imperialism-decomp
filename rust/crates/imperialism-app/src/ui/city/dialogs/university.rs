use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct UniversityRowAssets {
    unit_name: String,
    description: String,
    preview: Handle<Image>,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum UniversityDisplay {
    UnitName,
    Description,
    LaborCost,
    MaterialCost,
    CashCost,
    LaborAvailable,
    MaterialAvailable,
    Treasury,
    Preview,
    RequirementIcon(usize),
    RequirementValue { row: usize, level: u8 },
    TierLabel(usize),
}

pub(in crate::ui::city) struct UniversityRowText {
    pub(in crate::ui::city) unit_name: String,
    pub(in crate::ui::city) description: String,
    pub(in crate::ui::city) preview: Handle<Image>,
}

pub(in crate::ui::city) struct UniversityDialogData {
    pub(in crate::ui::city) available: CivilianUnitTable<bool>,
    pub(in crate::ui::city) rows: [UniversityRowText; UNIVERSITY_ROWS.len()],
    pub(in crate::ui::city) resource_icons: Handle<Image>,
    pub(in crate::ui::city) tier_labels: [String; 3],
    pub(in crate::ui::city) detail_font: TextFont,
    pub(in crate::ui::city) detail_line_height: LineHeight,
    pub(in crate::ui::city) normal_color: Color,
    pub(in crate::ui::city) warning_color: Color,
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
    tree: &RetailTree,
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
    let data = UniversityDialogData {
        available: state.technology().city_capabilities_by_nation[nation]
            .university
            .available,
        rows: UNIVERSITY_ROWS.map(|row| {
            UniversityRowText {
                // Retail `TUniversityView::SetUnit` pre-increments the 0-based
                // recruitment category once and reuses that 1-based index for
                // both `0x2718` (name) and `0x2751` (description).
                unit_name: assets
                    .string(0x2718, i16::from(row.kind as u8) + 1)
                    .expect("retail civilian name"),
                description: assets
                    .string(0x2751, i16::from(row.kind as u8) + 1)
                    .expect("retail civilian description"),
                preview: assets
                    .transparent_picture(PictureId::new(university_preview_picture(row.kind)), 0x10)
                    .expect("retail University preview picture must load"),
            }
        }),
        resource_icons: assets
            .transparent_picture(PictureId::new(750), 0x10)
            .expect("retail University resource icons must load"),
        tier_labels: std::array::from_fn(|level| {
            assets
                .string(0x2723, 0x0e + level as i16)
                .expect("retail University tier label")
        }),
        detail_font,
        detail_line_height,
        normal_color: assets.palette_color(0xd2),
        warning_color: assets.palette_color(0xcb),
    };
    bind_university_dialog(commands, root, tree, data);
}

pub(in crate::ui::city) fn bind_university_dialog(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    data: UniversityDialogData,
) {
    let UniversityDialogData {
        available,
        rows,
        resource_icons,
        tier_labels: tier_label_texts,
        detail_font,
        detail_line_height,
        normal_color,
        warning_color,
    } = data;
    bind_city_dialog_root(commands, root, tree, CityFacilitySlot::University);
    for (spec, row_text) in UNIVERSITY_ROWS.iter().zip(rows) {
        let kind = spec.kind;
        let binding = spec.binding();
        let button = tree.find(root, spec.button_tag);
        let row = tree.find(root, spec.order_tag);
        let minus = tree.find(row, fourcc!("minu"));
        let plus = tree.find(row, fourcc!("plus"));
        let quantity = tree.find(row, fourcc!("numb"));
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
            button_commands.insert((
                CityRowChoice(CityOrderId::CivilianRecruit(kind)),
                UniversityRowAssets {
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
            Text::new(""),
            CityOrderQuantity(binding.order),
            InteractionDisabled,
            TextColor(normal_color),
        ));
    }
    let dlog = tree.find(root, fourcc!("DLOG"));
    commands.spawn((
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
        UniversityDisplay::Preview,
        Name::new("university-civilian-preview"),
    ));
    for row in 0..4 {
        commands.spawn((
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
            UniversityDisplay::RequirementIcon(row),
            Name::new(format!("university-requirement-icon-{row}")),
        ));
        for level in 1_u8..=3 {
            commands.spawn((
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
                UniversityDisplay::RequirementValue { row, level },
                Name::new(format!("university-requirement-{row}-{level}")),
            ));
        }
    }
    let tier_labels = [
        tree.find(root, fourcc!("fix2")),
        tree.find(root, fourcc!("fix3")),
        tree.find(root, fourcc!("fix4")),
    ];
    for (index, (entity, text)) in tier_labels.into_iter().zip(tier_label_texts).enumerate() {
        commands.entity(entity).insert((
            Text::new(text),
            TextColor(normal_color),
            Visibility::Hidden,
            UniversityDisplay::TierLabel(index),
        ));
    }
    for (tag, display) in [
        (fourcc!("unit"), UniversityDisplay::UnitName),
        (fourcc!("desc"), UniversityDisplay::Description),
        (fourcc!("cexp"), UniversityDisplay::LaborCost),
        (fourcc!("cpap"), UniversityDisplay::MaterialCost),
        (fourcc!("cash"), UniversityDisplay::CashCost),
        (fourcc!("aexp"), UniversityDisplay::LaborAvailable),
        (fourcc!("apap"), UniversityDisplay::MaterialAvailable),
        (fourcc!("trea"), UniversityDisplay::Treasury),
    ] {
        commands.entity(tree.find(root, tag)).insert((
            Text::new(""),
            TextColor(normal_color),
            display,
        ));
    }
    commands
        .entity(tree.find(root, fourcc!("titl")))
        .insert(TextColor(normal_color));
    for tag in [fourcc!("fix0"), fourcc!("fix1")] {
        commands
            .entity(tree.find(root, tag))
            .insert(TextColor(normal_color));
    }
    commands.entity(root).insert(CityRowSelection {
        order: CityOrderId::CivilianRecruit(CivilianUnitKind::Miner),
        normal_color,
        warning_color,
    });
}

pub(in crate::ui::city) fn sync_university_details(
    session: Res<GameSession>,
    selections: Query<Ref<CityRowSelection>>,
    rows: Query<(&CityRowChoice, &UniversityRowAssets)>,
    mut texts: Query<(&UniversityDisplay, &mut Text), Without<ImageNode>>,
    mut text_colors: Query<(&UniversityDisplay, &mut TextColor), Without<ImageNode>>,
    mut images: Query<(&UniversityDisplay, &mut ImageNode)>,
    mut visibilities: Query<(&UniversityDisplay, &mut Visibility)>,
) {
    let Some(selection) = selections.iter().next() else {
        return;
    };
    let CityOrderId::CivilianRecruit(kind) = selection.order else {
        return;
    };
    if !session.is_changed() && !selection.is_changed() && !selection.is_added() {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let city = &major.city;
    let row = rows
        .iter()
        .find(|(choice, _)| choice.0 == selection.order)
        .map(|(_, assets)| assets)
        .expect("University selection has a bound retail row");
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
        .unwrap_or(0);

    for (display, mut text) in &mut texts {
        match *display {
            UniversityDisplay::UnitName => text.0.clone_from(&row.unit_name),
            UniversityDisplay::Description => text.0.clone_from(&row.description),
            UniversityDisplay::LaborCost => text.0 = 1.to_string(),
            UniversityDisplay::MaterialCost => text.0 = spec.primary.per_unit().to_string(),
            UniversityDisplay::CashCost => text.0 = format_currency(i32::from(spec.cash_per_unit)),
            UniversityDisplay::LaborAvailable => text.0 = workforce_available.to_string(),
            UniversityDisplay::MaterialAvailable => {
                text.0 = city.stockpile[spec.primary.resource].to_string()
            }
            UniversityDisplay::Treasury => text.0 = format_currency(major.common.treasury),
            UniversityDisplay::RequirementValue { row, level } => {
                let resource = specialties[row];
                let running_max = specialties[..=row]
                    .iter()
                    .flatten()
                    .map(|resource| levels[*resource])
                    .max()
                    .unwrap_or(0);
                let visible = resource.is_some() && level <= running_max;
                if let Some(resource) = resource
                    && visible
                {
                    text.0 = resource_development_yield(resource, level).to_string();
                }
            }
            _ => {}
        }
    }
    for (display, mut color) in &mut text_colors {
        let insufficient = match display {
            UniversityDisplay::MaterialAvailable => {
                city.stockpile[spec.primary.resource] < spec.primary.per_unit()
            }
            UniversityDisplay::LaborAvailable => workforce_available < 1,
            UniversityDisplay::Treasury => major.common.treasury < i32::from(spec.cash_per_unit),
            _ => continue,
        };
        color.0 = city_stock_color(insufficient, &selection);
    }
    for (display, mut image) in &mut images {
        match *display {
            UniversityDisplay::Preview => image.image.clone_from(&row.preview),
            UniversityDisplay::RequirementIcon(row) => {
                if let Some(resource) = specialties[row] {
                    let source_left = f32::from(resource as u8) * 20.0;
                    image.rect = Some(Rect::new(source_left, 0.0, source_left + 20.0, 24.0));
                }
            }
            _ => {}
        }
    }
    for (display, mut visibility) in &mut visibilities {
        *visibility = match *display {
            UniversityDisplay::RequirementIcon(row) => {
                if specialties[row].is_some() {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                }
            }
            UniversityDisplay::RequirementValue { row, level } => {
                let resource = specialties[row];
                let running_max = specialties[..=row]
                    .iter()
                    .flatten()
                    .map(|resource| levels[*resource])
                    .max()
                    .unwrap_or(0);
                if resource.is_some() && level <= running_max {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                }
            }
            UniversityDisplay::TierLabel(index) => {
                if (index as u8) < maximum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                }
            }
            _ => continue,
        };
    }
}
