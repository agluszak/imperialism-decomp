use super::*;
use crate::ui::retail::RetailPictureSwap;
use crate::ui::retail_raster::IndexedRasterExt;
use crate::ui::retail_raster_text::RetailRasterTextPainter;

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
    picture: IndexedPicture,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum ShipyardDisplay {
    ShipName,
    Description,
    Picture,
}

#[derive(Component)]
pub(in crate::ui::city) struct ShipyardDetailsVisual {
    base: IndexedPicture,
    stat_labels: [String; 6],
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
    let material_pictures = SHIPYARD_MATERIALS.map(|resource| {
        assets
            .indexed_picture(PictureId::new(700 + i16::from(resource.retail())))
            .expect("retail Shipyard material picture must load")
    });
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
                    .string(0x2716, i16::from(ship_type.retail()) + 1)
                    .expect("retail ship name"),
                description: assets
                    .string(0x2752, i16::from(ship_type.retail()))
                    .expect("retail ship description"),
                picture: assets
                    .picture(PictureId::new(9834 + i16::from(ship_type.retail())))
                    .expect("retail Shipyard detail picture"),
                materials: SHIPYARD_MATERIALS
                    .iter()
                    .zip(&material_pictures)
                    .filter_map(|(&resource, picture)| {
                        let required = costs[resource];
                        (required != 0).then(|| ShipyardMaterialData {
                            resource,
                            required,
                            picture: (*picture).clone(),
                        })
                    })
                    .collect(),
                stats: {
                    let capabilities = ship_capabilities(ship_type);
                    [
                        capabilities.resolve_weight,
                        capabilities.calculation_weight,
                        capabilities.task_force_weight,
                        capabilities.stock_capacity,
                        capabilities.navy_priority_weight,
                        capabilities.resource_weight,
                    ]
                },
            }),
        )
    });
    let queue_icons = assets
        .indexed_picture(PictureId::new(9807))
        .expect("retail Shipyard queue icons must load");
    let stat_labels: [String; 6] =
        std::array::from_fn(|index| city_string(assets, 0x2736, 0x10 + index as i16));
    let normal_color = assets.palette_color(0xd2);
    let warning_color = assets.palette_color(0xcb);
    for (spec, details) in prepared_rows {
        let slot = spec.slot();
        let button = tree.find(root, spec.button_tag);
        let bound = bind_city_order_row(
            commands,
            root,
            tree,
            spec.binding,
            fourcc!("minu"),
            fourcc!("plus"),
            fourcc!("numb"),
            1,
            Some(root),
        );
        let available = details.is_some();
        bound.set_available(commands, available);
        commands.entity(button).insert(if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
        if let Some(row_data) = details.as_ref() {
            let (idle, active) = shipyard_queue_pictures(
                assets,
                &queue_icons,
                slot,
                row_data.ship_type,
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
        commands
            .entity(button)
            .insert((
                CityRowChoice {
                    order: spec.binding.order,
                    selection: root,
                },
                ShipyardRowAssets { details },
            ))
            .observe(on_city_row_selected);
        commands.entity(bound.quantity).insert(InteractionDisabled);
    }
    let bind_text = |commands: &mut Commands, tag, display: ShipyardDisplay| {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(display);
    };
    bind_text(commands, fourcc!("snam"), ShipyardDisplay::ShipName);
    bind_text(commands, fourcc!("desc"), ShipyardDisplay::Description);
    let picture = tree.find(root, fourcc!("spic"));
    commands.entity(picture).insert(ShipyardDisplay::Picture);
    let dlog = tree.find(root, fourcc!("DLOG"));
    let base = assets
        .indexed_picture(PictureId::new(9800))
        .expect("retail Shipyard dialog picture must load");
    let palette = *assets.default_dib_palette();
    let image = assets.add_image(base.to_image(&palette));
    commands.entity(dlog).insert((
        ImageNode::new(image),
        ShipyardDetailsVisual { base, stat_labels },
    ));
    commands.entity(root).insert(CityRowSelection {
        order: CityOrderId::Ship(ShipOrderSlot::MerchantEarlyPrimary),
        normal_color,
        warning_color,
    });
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

fn draw_shipyard_details(
    picture: &mut IndexedPicture,
    text: &mut RetailRasterTextPainter,
    stat_labels: &[String; 6],
    row: &ShipyardRowData,
    city: &CityState,
) {
    for (index, material) in row.materials.iter().enumerate() {
        let text_x = 0x3a + index as i32 * 0x28;
        picture.blit_keyed_at(&material.picture, IVec2::new(text_x - 0x20, 0x98), 0x10);
        picture.blit_keyed_at(&material.picture, IVec2::new(text_x - 0x20, 0xcc), 0x10);
        text.draw(
            picture,
            IVec2::new(text_x, 0xb2),
            &material.required.to_string(),
            0xd2,
        );
        let available = city.stockpile[material.resource];
        text.draw(
            picture,
            IVec2::new(text_x, 0xe6),
            &available.to_string(),
            if available < material.required {
                0xcb
            } else {
                0xd2
            },
        );
    }
    for (index, &(left, baseline)) in generated::SHIPYARD_STAT_ORIGINS.iter().enumerate() {
        let origin = IVec2::new(left as i32, baseline as i32);
        text.draw(picture, origin, &stat_labels[index], 0xd2);
        text.draw(
            picture,
            origin + IVec2::new(0x3c, 0),
            &row.stats[index].to_string(),
            0xd2,
        );
    }
}

pub(in crate::ui::city) fn sync_shipyard_details(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    mut image_assets: ResMut<Assets<Image>>,
    selections: Query<Ref<CityRowSelection>>,
    rows: Query<(&CityRowChoice, &ShipyardRowAssets)>,
    mut texts: Query<(&ShipyardDisplay, &mut Text), Without<ImageNode>>,
    mut images: Query<(&ShipyardDisplay, &mut ImageNode), Without<ShipyardDetailsVisual>>,
    details: Query<(&ShipyardDetailsVisual, &ImageNode)>,
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
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    let row = rows
        .iter()
        .find(|(choice, _)| choice.order == selection.order)
        .and_then(|(_, assets)| assets.details.as_ref())
        .expect("Shipyard selection has a bound retail row");
    for (display, mut text) in &mut texts {
        match *display {
            ShipyardDisplay::ShipName => text.0.clone_from(&row.ship_name),
            ShipyardDisplay::Description => text.0.clone_from(&row.description),
            _ => {}
        }
    }
    for (display, mut image) in &mut images {
        if matches!(*display, ShipyardDisplay::Picture) {
            image.image.clone_from(&row.picture);
        }
    }
    let mut text = RetailRasterTextPainter::from_preset(
        retail.assets(),
        RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        },
    )
    .expect("retail Shipyard custom-drawing text style");
    for (visual, image_node) in &details {
        let mut picture = visual.base.clone();
        draw_shipyard_details(&mut picture, &mut text, &visual.stat_labels, row, city);
        if let Some(mut image) = image_assets.get_mut(&image_node.image) {
            *image = picture.to_image(retail.assets().default_dib_palette());
        }
    }
}
