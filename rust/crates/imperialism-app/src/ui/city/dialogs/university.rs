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
        tier_labels,
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
    bind_city_order_controls(
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
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::UniversityOrderQuantity(kind),
            },
        ));
    }
    let dlog = spawned.unique(fourcc!("DLOG"));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(124.0),
            top: Val::Px(92.0),
            width: Val::Px(64.0),
            height: Val::Px(64.0),
            ..default()
        },
        ImageNode::new(initial_preview),
        UniversityPreview { dialog: root },
        Pickable::IGNORE,
        ZIndex(1),
        ChildOf(dlog),
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
            UniversityRequirementIcon { dialog: root, row },
            Visibility::Hidden,
            Pickable::IGNORE,
            ZIndex(1),
            ChildOf(dlog),
            Name::new(format!("university-requirement-icon-{row}")),
        ));
        for level in 1..=3_u8 {
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
                TextLayout::justify(Justify::Left),
                TextColor(normal_color),
                UniversityRequirementValue {
                    dialog: root,
                    row,
                    level,
                },
                Visibility::Hidden,
                Pickable::IGNORE,
                ZIndex(1),
                ChildOf(dlog),
                Name::new(format!("university-requirement-{row}-{level}")),
            ));
        }
    }
    for (index, tag) in [fourcc!("fix2"), fourcc!("fix3"), fourcc!("fix4")]
        .into_iter()
        .enumerate()
    {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new(tier_labels[index].clone()),
            detail_font.clone(),
            TextLayout::justify(Justify::Center),
            TextColor(normal_color),
            UniversityTierLabel {
                dialog: root,
                level: index as u8 + 1,
            },
            Visibility::Hidden,
        ));
    }
    for (tag, value, font) in [
        (fourcc!("unit"), CityValue::UniversityUnitName, unit_font),
        (
            fourcc!("desc"),
            CityValue::UniversityDescription,
            detail_font.clone(),
        ),
        (
            fourcc!("cexp"),
            CityValue::UniversityWorkforceCost,
            detail_font.clone(),
        ),
        (
            fourcc!("cpap"),
            CityValue::UniversityPaperCost,
            detail_font.clone(),
        ),
        (
            fourcc!("cash"),
            CityValue::UniversityCashCost,
            detail_font.clone(),
        ),
        (
            fourcc!("aexp"),
            CityValue::UniversityWorkforceAvailable,
            detail_font.clone(),
        ),
        (
            fourcc!("apap"),
            CityValue::UniversityPaperAvailable,
            detail_font.clone(),
        ),
        (fourcc!("trea"), CityValue::Treasury, detail_font.clone()),
    ] {
        let entity = spawned.unique(tag);
        let mut entity_commands = commands.entity(entity);
        entity_commands.insert((
            Text::new(""),
            font,
            TextColor(normal_color),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
        let warning_kind = match tag {
            tag if tag == fourcc!("apap") => Some(UniversityWarningKind::Paper),
            tag if tag == fourcc!("aexp") => Some(UniversityWarningKind::Workforce),
            tag if tag == fourcc!("trea") => Some(UniversityWarningKind::Treasury),
            _ => None,
        };
        if let Some(kind) = warning_kind {
            entity_commands.insert(UniversityWarningValue {
                dialog: root,
                kind,
                normal_color,
                warning_color,
            });
        }
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
}
