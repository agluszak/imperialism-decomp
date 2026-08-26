use super::*;
use crate::ui::retail::RetailPictureSwap;
use crate::ui::retail_raster::IndexedRasterExt;

struct ShipyardRowView {
    button: Entity,
    quantity: Entity,
}

/// One material column: cost icon, required value, available icon, available value.
struct MaterialView {
    icon: Entity,
    required: Entity,
    available_icon: Entity,
    available: Entity,
}

/// Root view of the Shipyard dialog.
#[derive(Component)]
pub(in crate::ui::city) struct ShipyardView {
    selected: ShipOrderSlot,
    rows: [ShipyardRowView; SHIPYARD_ROWS.len()],
    ship_name: Entity,
    description: Entity,
    picture: Entity,
    materials: [MaterialView; SHIPYARD_MATERIALS.len()],
    stat_values: [Entity; 6],
}

pub(in crate::ui::city) fn configure_shipyard_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) {
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("City active nation is a major nation");
    let city = &state.nations().major(nation).city;
    let queue_icons = assets
        .indexed_picture(PictureId::new(9807))
        .expect("retail Shipyard queue icons must load");
    let rows = SHIPYARD_ROWS.map(|spec| {
        let slot = spec.slot();
        let ship_type = city.orders.ships[slot].ship_type;
        let available = ship_type != ShipType::NoShip;
        let bound = bind_city_order_row(
            commands,
            root,
            tree,
            spec.binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
        );
        for tag in [fourcc!("minu"), fourcc!("plus")] {
            commands.entity(tree.find(bound.row, tag)).observe(
                move |_: On<Activate>, mut views: Query<&mut ShipyardView>| {
                    if let Ok(mut view) = views.get_mut(root) {
                        view.selected = slot;
                    }
                },
            );
        }
        let button = tree.find(root, spec.button_tag);
        bound.set_available(commands, available);
        commands.entity(button).insert(if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
        if available {
            let (idle, active) = shipyard_queue_pictures(
                assets,
                &queue_icons,
                slot,
                ship_type,
                spec.overlay_left as i32,
            );
            commands.entity(button).insert((
                RetailPictureSwap {
                    idle: idle.clone(),
                    active,
                },
                ImageNode::new(idle),
            ));
            commands.entity(button).remove::<InteractionDisabled>();
        } else {
            commands.entity(button).insert(InteractionDisabled);
        }
        commands.entity(button).observe(
            move |change: On<ValueChange<bool>>, mut views: Query<&mut ShipyardView>| {
                if change.value
                    && let Ok(mut view) = views.get_mut(root)
                {
                    view.selected = slot;
                }
            },
        );
        commands.entity(bound.quantity).insert(InteractionDisabled);
        ShipyardRowView {
            button,
            quantity: bound.quantity,
        }
    });
    let dlog = tree.find(root, fourcc!("DLOG"));
    commands.entity(dlog).insert(ImageNode::new(
        assets
            .picture(PictureId::new(9800))
            .expect("retail Shipyard dialog picture must load"),
    ));
    let (detail_font, detail_layout, detail_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        })
        .expect("retail Shipyard detail text style");
    let detail_cell = match detail_line_height {
        bevy::text::LineHeight::Px(pixels) => pixels,
        _ => 10.0,
    };
    let mut bind_text = |tag| {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(""));
        entity
    };
    let ship_name = bind_text(fourcc!("snam"));
    let description = bind_text(fourcc!("desc"));
    let picture = tree.find(root, fourcc!("spic"));
    let materials = std::array::from_fn(|index| {
        let text_x = 0x3a as f32 + index as f32 * 0x28 as f32;
        let icon = spawn_detail_child(
            commands,
            dlog,
            text_x - 0x20 as f32,
            0x98 as f32,
            20.0,
            24.0,
            ImageNode::default(),
        );
        let required = spawn_detail_child(
            commands,
            dlog,
            text_x,
            0xb2 as f32 - detail_cell,
            40.0,
            detail_cell,
            (
                Text::new(""),
                detail_font.clone(),
                detail_layout,
                detail_line_height,
            ),
        );
        let available_icon = spawn_detail_child(
            commands,
            dlog,
            text_x - 0x20 as f32,
            0xcc as f32,
            20.0,
            24.0,
            ImageNode::default(),
        );
        let available = spawn_detail_child(
            commands,
            dlog,
            text_x,
            0xe6 as f32 - detail_cell,
            40.0,
            detail_cell,
            (
                Text::new(""),
                detail_font.clone(),
                detail_layout,
                detail_line_height,
            ),
        );
        for entity in [icon, required, available_icon, available] {
            commands.entity(entity).insert(Visibility::Hidden);
        }
        MaterialView {
            icon,
            required,
            available_icon,
            available,
        }
    });
    for (index, &(left, baseline)) in generated::SHIPYARD_STAT_ORIGINS.iter().enumerate() {
        spawn_detail_child(
            commands,
            dlog,
            left,
            baseline - detail_cell,
            60.0,
            detail_cell,
            (
                Text::new(city_string(assets, 0x2736, 0x10 + index as i16)),
                detail_font.clone(),
                detail_layout,
                detail_line_height,
                TextColor(assets.palette_color(0xd2)),
            ),
        );
    }
    let stat_values = std::array::from_fn(|index| {
        let (left, baseline) = generated::SHIPYARD_STAT_ORIGINS[index];
        spawn_detail_child(
            commands,
            dlog,
            left + 0x3c as f32,
            baseline - detail_cell,
            40.0,
            detail_cell,
            (
                Text::new(""),
                detail_font.clone(),
                detail_layout,
                detail_line_height,
                TextColor(assets.palette_color(0xd2)),
            ),
        )
    });
    commands.entity(root).insert(ShipyardView {
        selected: ShipOrderSlot::MerchantEarlyPrimary,
        rows,
        ship_name,
        description,
        picture,
        materials,
        stat_values,
    });
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

fn shipyard_queue_pictures(
    assets: &mut RetailUiAssets,
    queue_icons: &IndexedPicture,
    slot: ShipOrderSlot,
    ship_type: ShipType,
    overlay_left: i32,
) -> (Handle<Image>, Handle<Image>) {
    let palette = *assets.default_dib_palette();
    let source_left = i32::from(ship_type.retail() - 1) * 0x50;
    let source = IRect::new(source_left, 0, source_left + 0x50, 0x2d);
    let mut compose = |picture_id| {
        let mut picture = assets
            .indexed_picture(PictureId::new(picture_id))
            .expect("retail Shipyard queue button picture must load");
        picture.blit_keyed(queue_icons, source, IVec2::new(overlay_left, 0x0c), 0x10);
        assets.add_image(picture.to_image(&palette))
    };
    let idle_id = 9808 + i16::from(slot as u8) * 2;
    (compose(idle_id), compose(idle_id + 1))
}

pub(in crate::ui::city) fn render_shipyard_dialog(
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
    views: Query<Ref<ShipyardView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut images: Query<&mut ImageNode>,
    mut visibilities: Query<&mut Visibility>,
    mut text_colors: Query<&mut TextColor>,
    checked: Query<Has<Checked>>,
) {
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    for view in &views {
        if !session.is_changed() && !view.is_added() && !view.is_changed() {
            continue;
        }
        let nation = session.active_major_nation();
        for (spec, row) in SHIPYARD_ROWS.iter().zip(&view.rows) {
            let selected = spec.slot() == view.selected;
            let is_checked = checked.get(row.button).unwrap_or(false);
            if selected && !is_checked {
                commands.entity(row.button).insert(Checked);
            } else if !selected && is_checked {
                commands.entity(row.button).remove::<Checked>();
            }
            texts
                .get_mut(row.quantity)
                .expect("bound Shipyard order quantity")
                .0 = session
                .game
                .city_order_quantity(nation, spec.binding.order)
                .to_string();
        }
        let major = session.game.nations().major(nation);
        let city = &major.city;
        let ship_type = city.orders.ships[view.selected].ship_type;
        if ship_type == ShipType::NoShip {
            continue;
        }
        texts
            .get_mut(view.ship_name)
            .expect("bound Shipyard ship name")
            .0 = assets
            .string(0x2716, i16::from(ship_type.retail()) + 1)
            .expect("retail ship name");
        texts
            .get_mut(view.description)
            .expect("bound Shipyard description")
            .0 = assets
            .string(0x2752, i16::from(ship_type.retail()))
            .expect("retail ship description");
        images
            .get_mut(view.picture)
            .expect("bound Shipyard picture")
            .image = assets
            .picture(PictureId::new(9834 + i16::from(ship_type.retail())))
            .expect("retail Shipyard detail picture");
        let costs = ship_order_costs(ship_type);
        for (index, material) in view.materials.iter().enumerate() {
            let resource = SHIPYARD_MATERIALS[index];
            let required = costs[resource];
            if required == 0 {
                for entity in [
                    material.icon,
                    material.required,
                    material.available_icon,
                    material.available,
                ] {
                    *visibilities
                        .get_mut(entity)
                        .expect("bound Shipyard material") = Visibility::Hidden;
                }
                continue;
            }
            let icon = assets
                .picture(PictureId::new(700 + i16::from(resource.retail())))
                .expect("retail Shipyard material picture must load");
            images
                .get_mut(material.icon)
                .expect("bound Shipyard material icon")
                .image
                .clone_from(&icon);
            images
                .get_mut(material.available_icon)
                .expect("bound Shipyard material icon")
                .image
                .clone_from(&icon);
            texts
                .get_mut(material.required)
                .expect("bound Shipyard material required")
                .0 = required.to_string();
            let available = city.stockpile[resource];
            texts
                .get_mut(material.available)
                .expect("bound Shipyard material available")
                .0 = available.to_string();
            text_colors
                .get_mut(material.available)
                .expect("bound Shipyard material available")
                .0 = if available < required {
                warning_color
            } else {
                normal_color
            };
            for entity in [
                material.icon,
                material.required,
                material.available_icon,
                material.available,
            ] {
                *visibilities
                    .get_mut(entity)
                    .expect("bound Shipyard material") = Visibility::Visible;
            }
        }
        let capabilities = ship_capabilities(ship_type);
        let values = [
            capabilities.resolve_weight,
            capabilities.calculation_weight,
            capabilities.task_force_weight,
            capabilities.stock_capacity,
            capabilities.navy_priority_weight,
            capabilities.resource_weight,
        ];
        for (entity, value) in view.stat_values.iter().zip(&values) {
            texts.get_mut(*entity).expect("bound Shipyard stat value").0 = value.to_string();
        }
    }
}
