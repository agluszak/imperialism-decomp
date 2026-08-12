use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct ShipyardRowChoice {
    pub(in crate::ui::city) slot: ShipOrderSlot,
}

struct ShipyardRowData {
    ship_type: ShipType,
    ship_name: String,
    description: String,
    picture: Handle<Image>,
    materials: Vec<ShipyardMaterialData>,
    stats: [i16; 6],
}

struct ShipyardMaterialData {
    resource: ResourceKind,
    required: i16,
    picture: Handle<Image>,
}

#[derive(Clone, Copy)]
struct ShipyardMaterialControls {
    pictures: [Entity; 2],
    required: Entity,
    available: Entity,
}

struct ShipyardRow {
    details: Option<ShipyardRowData>,
    button: Entity,
    quantity: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct ShipyardView {
    pub(in crate::ui::city) slot: ShipOrderSlot,
    rows: ShipOrderTable<ShipyardRow>,
    ship_name: Entity,
    description: Entity,
    picture: Entity,
    materials: [ShipyardMaterialControls; 4],
    stats: [Entity; 6],
    normal_color: Color,
    warning_color: Color,
}

pub(in crate::ui::city) fn configure_shipyard_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    state: &GameState,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("City active nation is a major nation");
    let city = &state.nations().major(nation).city;
    let material_pictures = SHIPYARD_MATERIALS
        .map(|resource| transparent_picture(ui, PictureId::new(700 + resource as i16)));
    let (detail_font, _, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        })
        .expect("retail Shipyard detail text style");
    let (title_font, _, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 24,
            alignment: 1,
        })
        .expect("retail Shipyard title text style");
    let (name_font, _, _) = ui
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail Shipyard name text style");
    let prepared_rows = std::array::from_fn(|index| {
        let binding = &SHIP_ORDERS[index];
        let CityOrderId::Ship(slot) = binding.order else {
            unreachable!("Shipyard binding has a ship order");
        };
        let ship_type = city.orders.ships[slot].ship_type;
        if ship_type == ShipType::NoShip {
            return (index, slot, None);
        }
        let costs = ship_order_costs(ship_type);
        (
            index,
            slot,
            Some(ShipyardRowData {
                ship_type,
                ship_name: ui
                    .string(0x2716, ship_type as i16 + 1)
                    .expect("retail ship name"),
                description: ui
                    .string(0x2752, ship_type as i16)
                    .expect("retail ship description"),
                picture: ui
                    .picture(PictureId::new(9834 + ship_type as i16))
                    .expect("retail Shipyard detail picture"),
                materials: SHIPYARD_MATERIALS
                    .iter()
                    .zip(&material_pictures)
                    .filter_map(|(&resource, picture)| {
                        let required = costs[resource];
                        (required != 0).then(|| ShipyardMaterialData {
                            resource,
                            required,
                            picture: picture.clone(),
                        })
                    })
                    .collect(),
                stats: ship_display_stats(ship_type),
            }),
        )
    });
    let queue_icons = transparent_picture(ui, PictureId::new(9807));
    let stat_labels: [String; 6] =
        std::array::from_fn(|index| city_string(ui, 0x2736, 0x10 + index as i16));
    let normal_color = ui.palette_color(0xd2);
    let warning_color = ui.palette_color(0xcb);
    let commands = &mut ui.commands;
    let root = bind_city_dialog_root(commands, spawned, CityFacilitySlot::Shipyard);
    let rows = ShipOrderTable::from_array(prepared_rows.map(|(index, slot, details)| {
        let binding = &SHIP_ORDERS[index];
        let button = spawned.unique(shipyard_button_tag(slot));
        let row = spawned.unique(binding.tag);
        let minus = spawned.under(catalog, binding.tag, fourcc!("minu"));
        let plus = spawned.under(catalog, binding.tag, fourcc!("plus"));
        let quantity = spawned.under(catalog, binding.tag, fourcc!("numb"));
        commands.entity(minus).insert(CityOrderAdjust {
            order: binding.order,
            delta: -1,
        });
        commands.entity(plus).insert(CityOrderAdjust {
            order: binding.order,
            delta: 1,
        });
        let visibility = if details.is_some() {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        commands.entity(button).insert(visibility);
        if let Some(row_data) = details.as_ref() {
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
            commands.entity(button).insert(ShipyardRowChoice { slot });
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
            Text::new(""),
            InteractionDisabled,
            detail_font.clone(),
            TextColor(normal_color),
        ));
        ShipyardRow {
            details,
            button,
            quantity,
        }
    }));
    let style_text = |commands: &mut Commands, tag, font: TextFont| {
        let entity = spawned.unique(tag);
        commands
            .entity(entity)
            .insert((Text::new(""), font, TextColor(normal_color)));
        entity
    };
    let ship_name = style_text(commands, fourcc!("snam"), name_font);
    let description = style_text(commands, fourcc!("desc"), detail_font.clone());
    let picture = spawned.unique(fourcc!("spic"));
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
    commands.entity(root).insert(ShipyardView {
        slot: ShipOrderSlot::MerchantEarlyPrimary,
        rows,
        ship_name,
        description,
        picture,
        materials,
        stats,
        normal_color,
        warning_color,
    });
}

pub(in crate::ui::city) fn on_shipyard_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<&ShipyardRowChoice>,
    mut views: Query<&mut ShipyardView>,
) {
    if !change.value {
        return;
    }
    let Ok(row) = rows.get(change.source) else {
        return;
    };
    views
        .single_mut()
        .expect("Shipyard row has one open Shipyard dialog")
        .slot = row.slot;
}

pub(in crate::ui::city) fn on_shipyard_order_selected(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    mut views: Query<&mut ShipyardView>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let CityOrderId::Ship(slot) = action.order else {
        return;
    };
    views
        .single_mut()
        .expect("Shipyard order has one open Shipyard dialog")
        .slot = slot;
}

pub(in crate::ui::city) fn sync_shipyard_dialog(
    mut commands: Commands,
    session: Res<GameSession>,
    dialogs: Query<Ref<ShipyardView>>,
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
        for binding in SHIP_ORDERS {
            let CityOrderId::Ship(slot) = binding.order else {
                unreachable!("Shipyard control has a ship order");
            };
            let row = &view.rows[slot];
            texts
                .get_mut(row.quantity)
                .expect("Shipyard order quantity has text")
                .0 = city.orders.ships[slot].progress.quantity.to_string();
            if slot == view.slot {
                commands.entity(row.button).insert(Checked);
            } else {
                commands.entity(row.button).remove::<Checked>();
            }
        }
        let row = view.rows[view.slot]
            .details
            .as_ref()
            .expect("Shipyard selection has a bound retail row");
        texts
            .get_mut(view.ship_name)
            .expect("Shipyard name has text")
            .0
            .clone_from(&row.ship_name);
        texts
            .get_mut(view.description)
            .expect("Shipyard description has text")
            .0
            .clone_from(&row.description);
        images
            .get_mut(view.picture)
            .expect("Shipyard detail picture has an image")
            .image
            .clone_from(&row.picture);

        for (index, material_controls) in view.materials.iter().enumerate() {
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
                .get_mut(material_controls.available)
                .expect("Shipyard available material has a text color")
                .0 = if stock < material.required {
                view.warning_color
            } else {
                view.normal_color
            };
        }
        for (index, entity) in view.stats.iter().copied().enumerate() {
            texts.get_mut(entity).expect("Shipyard stat has text").0 = row.stats[index].to_string();
        }
    }
}
