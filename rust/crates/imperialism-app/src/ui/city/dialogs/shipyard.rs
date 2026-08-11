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

#[derive(Clone, Copy)]
struct ShipyardMaterialControls {
    pictures: [Entity; 2],
    required: Entity,
    available: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct ShipyardDialogControls {
    orders: Vec<CityOrderControl>,
    name: Entity,
    description: Entity,
    picture: Entity,
    materials: [ShipyardMaterialControls; 4],
    stats: [Entity; 6],
    normal_color: Color,
    warning_color: Color,
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
    let orders = bind_city_order_controls(
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
        ));
    }
    let bind_text = |commands: &mut Commands, tag, font: TextFont| {
        let entity = spawned.unique(tag);
        commands
            .entity(entity)
            .insert((Text::new(""), font, TextColor(normal_color)));
        entity
    };
    let name = bind_text(commands, fourcc!("snam"), name_font);
    let description = bind_text(commands, fourcc!("desc"), detail_font.clone());
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

    let dlog = spawned.unique(fourcc!("DLOG"));
    let materials = std::array::from_fn(|index| {
        let left = 26.0 + index as f32 * 40.0;
        let pictures = [152.0, 204.0].map(|top| {
            commands
                .spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        left: Val::Px(left),
                        top: Val::Px(top),
                        width: Val::Px(32.0),
                        height: Val::Px(24.0),
                        ..default()
                    },
                    ImageNode::default(),
                    Visibility::Hidden,
                    Pickable::IGNORE,
                    ZIndex(1),
                    ChildOf(dlog),
                    Name::new(format!("shipyard-material-icon-{index}-{top}")),
                ))
                .id()
        });
        let [required, available] = [(false, 168.0), (true, 220.0)].map(|(available, top)| {
            commands
                .spawn((
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
                    Visibility::Hidden,
                    Pickable::IGNORE,
                    ZIndex(1),
                    ChildOf(dlog),
                    Name::new(format!("shipyard-material-value-{index}-{available}")),
                ))
                .id()
        });
        ShipyardMaterialControls {
            pictures,
            required,
            available,
        }
    });
    let stats = std::array::from_fn(|index| {
        let (left, baseline) = SHIPYARD_STAT_ORIGINS[index];
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(left),
                top: Val::Px(baseline - 10.0),
                width: Val::Px(60.0),
                height: Val::Px(14.0),
                ..default()
            },
            Text::new(stat_labels[index].clone()),
            detail_font.clone(),
            TextLayout::justify(Justify::Left),
            TextColor(normal_color),
            Pickable::IGNORE,
            ZIndex(1),
            ChildOf(dlog),
            Name::new(format!("shipyard-stat-{index}-false")),
        ));
        commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(left + 60.0),
                    top: Val::Px(baseline - 10.0),
                    width: Val::Px(28.0),
                    height: Val::Px(14.0),
                    ..default()
                },
                Text::new(""),
                detail_font.clone(),
                TextLayout::justify(Justify::Left),
                TextColor(normal_color),
                Pickable::IGNORE,
                ZIndex(1),
                ChildOf(dlog),
                Name::new(format!("shipyard-stat-{index}-true")),
            ))
            .id()
    });
    commands.entity(root).insert(ShipyardDialogControls {
        orders,
        name,
        description,
        picture,
        materials,
        stats,
        normal_color,
        warning_color,
    });
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn sync_shipyard_dialog(
    session: Res<GameSession>,
    dialogs: Query<(
        Entity,
        &ShipyardDialogControls,
        Ref<CityBuildingDialog>,
        Ref<ShipyardSelection>,
    )>,
    rows: Query<&ShipyardRowChoice>,
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
            let CityOrderId::Ship(slot) = control.order else {
                unreachable!("Shipyard control has a ship order");
            };
            texts
                .get_mut(control.quantity)
                .expect("Shipyard order quantity has text")
                .0 = city.orders.ships[slot].progress.quantity.to_string();
        }

        let row = rows
            .iter()
            .find(|row| row.dialog == root && row.slot == selection.slot)
            .expect("Shipyard selection has a bound retail row");
        texts
            .get_mut(controls.name)
            .expect("Shipyard name has text")
            .0
            .clone_from(&row.ship_name);
        texts
            .get_mut(controls.description)
            .expect("Shipyard description has text")
            .0
            .clone_from(&row.description);
        images
            .get_mut(controls.picture)
            .expect("Shipyard detail picture has an image")
            .image
            .clone_from(&row.picture);
        *visibilities
            .get_mut(controls.picture)
            .expect("Shipyard detail picture has visibility") = Visibility::Visible;

        for (index, material_controls) in controls.materials.iter().enumerate() {
            let material = row.materials.get(index);
            for entity in material_controls.pictures {
                if let Some(material) = material {
                    images
                        .get_mut(entity)
                        .expect("Shipyard material picture has an image")
                        .image
                        .clone_from(&material.picture);
                }
                *visibilities
                    .get_mut(entity)
                    .expect("Shipyard material picture has visibility") = if material.is_some() {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
            }
            for entity in [material_controls.required, material_controls.available] {
                *visibilities
                    .get_mut(entity)
                    .expect("Shipyard material amount has visibility") = if material.is_some() {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
            }
            let Some(material) = material else {
                continue;
            };
            let stock = city.stockpile[material.resource];
            texts
                .get_mut(material_controls.required)
                .expect("Shipyard required material has text")
                .0 = material.required.to_string();
            texts
                .get_mut(material_controls.available)
                .expect("Shipyard available material has text")
                .0 = stock.to_string();
            text_colors
                .get_mut(material_controls.required)
                .expect("Shipyard required material has a text color")
                .0 = controls.normal_color;
            text_colors
                .get_mut(material_controls.available)
                .expect("Shipyard available material has a text color")
                .0 = if stock < material.required {
                controls.warning_color
            } else {
                controls.normal_color
            };
        }
        for (index, entity) in controls.stats.iter().copied().enumerate() {
            texts.get_mut(entity).expect("Shipyard stat has text").0 = row.stats[index].to_string();
            *visibilities
                .get_mut(entity)
                .expect("Shipyard stat has visibility") = Visibility::Visible;
        }
    }
}
