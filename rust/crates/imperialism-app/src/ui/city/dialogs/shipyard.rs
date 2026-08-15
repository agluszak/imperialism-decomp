use super::*;

#[derive(Component)]
pub(in crate::ui::city) struct ShipyardRowAssets {
    details: Option<ShipyardRowData>,
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

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum ShipyardDisplay {
    ShipName,
    Description,
    Picture,
    MaterialIcon { index: usize },
    MaterialRequired { index: usize },
    MaterialAvailable { index: usize },
    Stat { index: usize },
}

pub(in crate::ui::city) fn configure_shipyard_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    state: &GameState,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("City active nation is a major nation");
    let city = &state.nations().major(nation).city;
    let material_pictures = SHIPYARD_MATERIALS.map(|resource| {
        assets
            .transparent_picture(PictureId::new(700 + resource as i16), 0x10)
            .expect("retail Shipyard material picture must load")
    });
    let (detail_font, _, detail_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        })
        .expect("retail Shipyard detail text style");
    let (title_font, _, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 24,
            alignment: 1,
        })
        .expect("retail Shipyard title text style");
    let (name_font, _, name_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail Shipyard name text style");
    let prepared_rows: [_; 8] = SHIPYARD_ROWS.map(|spec| {
        let ship_type = city.orders.ships[spec.slot()].ship_type;
        if ship_type == ShipType::NoShip {
            return (spec, None);
        }
        let costs = ship_order_costs(ship_type);
        (
            spec,
            Some(ShipyardRowData {
                ship_type,
                ship_name: assets
                    .string(0x2716, ship_type as i16 + 1)
                    .expect("retail ship name"),
                description: assets
                    .string(0x2752, ship_type as i16)
                    .expect("retail ship description"),
                picture: assets
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
    let queue_icons = assets
        .transparent_picture(PictureId::new(9807), 0x10)
        .expect("retail Shipyard queue icons must load");
    let stat_labels: [String; 6] =
        std::array::from_fn(|index| city_string(assets, 0x2736, 0x10 + index as i16));
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    bind_city_dialog_root(commands, root, children, tags, CityFacilitySlot::Shipyard);
    for (spec, details) in prepared_rows {
        let slot = spec.slot();
        let button = find_descendant(root, spec.button_tag, children, tags);
        let bound = bind_city_order_row(
            commands,
            root,
            children,
            tags,
            spec.binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
        );
        let available = details.is_some();
        bound.set_available(commands, available);
        commands.entity(button).insert(if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
        if let Some(row_data) = details.as_ref() {
            let source_left = f32::from(row_data.ship_type as u8 - 1) * 80.0;
            commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(spec.overlay_left),
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
                Name::new(format!("shipyard-queue-icon-{}", slot as u8)),
            ));
            commands.entity(button).remove::<InteractionDisabled>();
        } else {
            commands.entity(button).insert(InteractionDisabled);
        }
        commands.entity(button).insert((
            CityRowChoice(spec.binding.order),
            ShipyardRowAssets { details },
        ));
        commands.entity(bound.quantity).insert((
            InteractionDisabled,
            detail_font.clone(),
            detail_line_height,
            TextColor(normal_color),
        ));
    }
    let style_text = |commands: &mut Commands,
                      tag,
                      font: TextFont,
                      line_height: LineHeight,
                      display: ShipyardDisplay| {
        let entity = find_descendant(root, tag, children, tags);
        commands.entity(entity).insert((
            Text::new(""),
            font,
            line_height,
            TextColor(normal_color),
            display,
        ));
    };
    style_text(
        commands,
        fourcc!("snam"),
        name_font,
        name_line_height,
        ShipyardDisplay::ShipName,
    );
    style_text(
        commands,
        fourcc!("desc"),
        detail_font.clone(),
        detail_line_height,
        ShipyardDisplay::Description,
    );
    let picture = find_descendant(root, fourcc!("spic"), children, tags);
    commands.entity(picture).insert(ShipyardDisplay::Picture);
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
    let dlog = find_descendant(root, fourcc!("DLOG"), children, tags);
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
                Visibility::Hidden,
                Pickable::IGNORE,
                ZIndex(1),
                ChildOf(dlog),
                ShipyardDisplay::MaterialIcon { index },
                Name::new(format!("shipyard-material-icon-{index}-{top}")),
            ));
        }
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(58.0 + index as f32 * 40.0),
                top: Val::Px(168.0),
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
            ShipyardDisplay::MaterialRequired { index },
            Name::new(format!("shipyard-material-value-{index}-false")),
        ));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(58.0 + index as f32 * 40.0),
                top: Val::Px(220.0),
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
            ShipyardDisplay::MaterialAvailable { index },
            Name::new(format!("shipyard-material-value-{index}-true")),
        ));
    }
    for (index, &(left, baseline)) in generated::SHIPYARD_STAT_ORIGINS.iter().enumerate() {
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
            detail_line_height,
            TextLayout::justify(Justify::Left),
            TextColor(normal_color),
            Pickable::IGNORE,
            ZIndex(1),
            ChildOf(dlog),
            Name::new(format!("shipyard-stat-{index}-false")),
        ));
        commands.spawn((
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
            detail_line_height,
            TextLayout::justify(Justify::Left),
            TextColor(normal_color),
            Pickable::IGNORE,
            ZIndex(1),
            ChildOf(dlog),
            ShipyardDisplay::Stat { index },
            Name::new(format!("shipyard-stat-{index}-true")),
        ));
    }
    commands.entity(root).insert(CityRowSelection {
        order: CityOrderId::Ship(ShipOrderSlot::MerchantEarlyPrimary),
        normal_color,
        warning_color,
    });
}

pub(in crate::ui::city) fn sync_shipyard_details(
    session: Res<GameSession>,
    selections: Query<Ref<CityRowSelection>>,
    rows: Query<(&CityRowChoice, &ShipyardRowAssets)>,
    mut texts: Query<(&ShipyardDisplay, &mut Text), Without<ImageNode>>,
    mut text_colors: Query<(&ShipyardDisplay, &mut TextColor), Without<ImageNode>>,
    mut images: Query<(&ShipyardDisplay, &mut ImageNode)>,
    mut visibilities: Query<(&ShipyardDisplay, &mut Visibility)>,
) {
    let Some(selection) = selections
        .iter()
        .find(|selection| matches!(selection.order, CityOrderId::Ship(_)))
    else {
        return;
    };
    if !session.is_changed() && !selection.is_changed() && !selection.is_added() {
        return;
    }
    let nation = city_active_nation(&session);
    let city = &session.game.nations().major(nation).city;
    let row = rows
        .iter()
        .find(|(choice, _)| choice.0 == selection.order)
        .and_then(|(_, assets)| assets.details.as_ref())
        .expect("Shipyard selection has a bound retail row");
    for (display, mut text) in &mut texts {
        match *display {
            ShipyardDisplay::ShipName => text.0.clone_from(&row.ship_name),
            ShipyardDisplay::Description => text.0.clone_from(&row.description),
            ShipyardDisplay::MaterialRequired { index } => {
                if let Some(material) = row.materials.get(index) {
                    text.0 = material.required.to_string();
                }
            }
            ShipyardDisplay::MaterialAvailable { index } => {
                if let Some(material) = row.materials.get(index) {
                    text.0 = city.stockpile[material.resource].to_string();
                }
            }
            ShipyardDisplay::Stat { index } => text.0 = row.stats[index].to_string(),
            _ => {}
        }
    }
    for (display, mut color) in &mut text_colors {
        let ShipyardDisplay::MaterialAvailable { index } = *display else {
            continue;
        };
        let Some(material) = row.materials.get(index) else {
            continue;
        };
        color.0 = city_stock_color(
            city.stockpile[material.resource] < material.required,
            &selection,
        );
    }
    for (display, mut image) in &mut images {
        match *display {
            ShipyardDisplay::Picture => image.image.clone_from(&row.picture),
            ShipyardDisplay::MaterialIcon { index } => {
                if let Some(material) = row.materials.get(index) {
                    image.image.clone_from(&material.picture);
                }
            }
            _ => {}
        }
    }
    for (display, mut visibility) in &mut visibilities {
        let present = match *display {
            ShipyardDisplay::MaterialIcon { index }
            | ShipyardDisplay::MaterialRequired { index }
            | ShipyardDisplay::MaterialAvailable { index } => row.materials.get(index).is_some(),
            _ => continue,
        };
        *visibility = if present {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}
