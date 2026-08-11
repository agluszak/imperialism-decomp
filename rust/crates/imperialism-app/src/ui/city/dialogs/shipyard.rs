use super::*;

pub(in crate::ui::city) struct ShipyardMaterialData {
    pub(in crate::ui::city) resource: ResourceKind,
    pub(in crate::ui::city) required: i16,
    pub(in crate::ui::city) picture: Handle<Image>,
}

pub(in crate::ui::city) struct ShipyardRowData {
    pub(in crate::ui::city) ship_type: ShipType,
    pub(in crate::ui::city) ship_name: String,
    pub(in crate::ui::city) description: String,
    pub(in crate::ui::city) picture: Handle<Image>,
    pub(in crate::ui::city) materials: Vec<ShipyardMaterialData>,
    pub(in crate::ui::city) stats: [i16; 6],
}

pub(in crate::ui::city) struct ShipyardDialogData {
    pub(in crate::ui::city) rows: [Option<ShipyardRowData>; SHIP_ORDERS.len()],
    pub(in crate::ui::city) queue_icons: Handle<Image>,
    pub(in crate::ui::city) stat_labels: [String; 6],
    pub(in crate::ui::city) title_font: TextFont,
    pub(in crate::ui::city) name_font: TextFont,
    pub(in crate::ui::city) detail_font: TextFont,
    pub(in crate::ui::city) normal_color: Color,
    pub(in crate::ui::city) warning_color: Color,
}

pub(in crate::ui::city) fn bind_shipyard_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    data: ShipyardDialogData,
) {
    let ShipyardDialogData {
        rows,
        queue_icons,
        stat_labels,
        title_font,
        name_font,
        detail_font,
        normal_color,
        warning_color,
    } = data;
    assert!(
        rows[0].is_some(),
        "retail Shipyard row zero always has a current ship"
    );
    let root = bind_city_dialog_root(commands, spawned, nation, CityFacilitySlot::Shipyard);
    commands.entity(root).insert(ShipyardSelection {
        slot: ShipOrderSlot::MerchantEarlyPrimary,
    });
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        &SHIP_ORDERS,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    );
    for (index, (binding, row_data)) in SHIP_ORDERS.iter().zip(rows).enumerate() {
        let CityOrderId::Ship(slot) = binding.order else {
            unreachable!("Shipyard binding has a ship order");
        };
        let button = spawned.unique(shipyard_button_tag(slot));
        let row = spawned.unique(binding.tag);
        let minus = spawned.under(catalog, binding.tag, fourcc!("minu"));
        let plus = spawned.under(catalog, binding.tag, fourcc!("plus"));
        let quantity = spawned.under(catalog, binding.tag, fourcc!("numb"));
        let visibility = if row_data.is_some() {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        commands.entity(button).insert(visibility);
        if slot == ShipOrderSlot::MerchantEarlyPrimary {
            commands.entity(button).insert(Checked);
        } else {
            commands.entity(button).remove::<Checked>();
        }
        if let Some(row_data) = row_data {
            let source_left = f32::from(row_data.ship_type as u8 - 1) * 80.0;
            commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(SHIPYARD_OVERLAY_LEFT[index]),
                    top: Val::Px(12.0),
                    width: Val::Px(80.0),
                    height: Val::Px(45.0),
                    ..default()
                },
                ImageNode {
                    image: queue_icons.clone(),
                    rect: Some(Rect::new(source_left, 0.0, source_left + 80.0, 45.0)),
                    ..default()
                },
                Pickable::IGNORE,
                ZIndex(1),
                ChildOf(button),
                Name::new(format!("shipyard-queue-icon-{index}")),
            ));
            commands.entity(button).insert(ShipyardRowChoice {
                dialog: root,
                slot,
                ship_name: row_data.ship_name,
                description: row_data.description,
                picture: row_data.picture,
                materials: row_data.materials,
                stats: row_data.stats,
            });
            commands.entity(button).remove::<InteractionDisabled>();
        } else {
            commands.entity(button).insert(InteractionDisabled);
        }
        commands.entity(row).insert(visibility);
        for control in [minus, plus] {
            if visibility == Visibility::Visible {
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
                value: CityValue::ShipyardOrderQuantity(slot),
            },
        ));
    }
    for (tag, value, font) in [
        (fourcc!("snam"), CityValue::ShipyardName, name_font),
        (
            fourcc!("desc"),
            CityValue::ShipyardDescription,
            detail_font.clone(),
        ),
    ] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new(""),
            font,
            TextColor(normal_color),
            CityValueBinding {
                dialog: Some(root),
                value,
            },
        ));
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
    let picture = spawned.unique(fourcc!("spic"));
    commands
        .entity(picture)
        .insert(ShipyardDetailPicture { dialog: root });

    let dlog = spawned.unique(fourcc!("DLOG"));
    for index in 0..4 {
        let left = 26.0 + index as f32 * 40.0;
        for top in [152.0, 204.0] {
            commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(left),
                    top: Val::Px(top),
                    width: Val::Px(32.0),
                    height: Val::Px(24.0),
                    ..default()
                },
                ImageNode::default(),
                ShipyardMaterialPicture {
                    dialog: root,
                    index,
                },
                Visibility::Hidden,
                Pickable::IGNORE,
                ZIndex(1),
                ChildOf(dlog),
                Name::new(format!("shipyard-material-icon-{index}-{top}")),
            ));
        }
        for (available, top) in [(false, 168.0), (true, 220.0)] {
            commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(58.0 + index as f32 * 40.0),
                    top: Val::Px(top),
                    width: Val::Px(24.0),
                    height: Val::Px(16.0),
                    ..default()
                },
                Text::new(""),
                detail_font.clone(),
                TextLayout::justify(Justify::Left),
                TextColor(normal_color),
                ShipyardMaterialAmount {
                    dialog: root,
                    index,
                    available,
                    normal_color,
                    warning_color,
                },
                Visibility::Hidden,
                Pickable::IGNORE,
                ZIndex(1),
                ChildOf(dlog),
                Name::new(format!("shipyard-material-value-{index}-{available}")),
            ));
        }
    }
    for (index, ((left, baseline), label)) in SHIPYARD_STAT_ORIGINS
        .into_iter()
        .zip(stat_labels)
        .enumerate()
    {
        for (value, text, x, width) in [
            (false, label, left, 60.0),
            (true, String::new(), left + 60.0, 28.0),
        ] {
            let mut entity = commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(x),
                    top: Val::Px(baseline - 10.0),
                    width: Val::Px(width),
                    height: Val::Px(14.0),
                    ..default()
                },
                Text::new(text),
                detail_font.clone(),
                TextLayout::justify(Justify::Left),
                TextColor(normal_color),
                Pickable::IGNORE,
                ZIndex(1),
                ChildOf(dlog),
                Name::new(format!("shipyard-stat-{index}-{value}")),
            ));
            if value {
                entity.insert(ShipyardStatValue {
                    dialog: root,
                    index,
                });
            }
        }
    }
}
