use super::*;
use crate::RetailFonts;
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
    ui: &generated::Shipyard9207,
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
    let prepared_rows: [_; 8] = SHIPYARD_SLOTS.map(|(slot, overlay_left)| {
        let ship_type = city.orders.ships[slot].ship_type;
        if ship_type == ShipType::NoShip {
            return (slot, overlay_left, None);
        }
        let costs = ship_order_costs(ship_type);
        (
            slot,
            overlay_left,
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
    let row_controls = [
        (ui.clu0, ui.clu0_minu, ui.clu0_plus, ui.clu0_numb, ui.but0),
        (ui.clu1, ui.clu1_minu, ui.clu1_plus, ui.clu1_numb, ui.but1),
        (ui.clu2, ui.clu2_minu, ui.clu2_plus, ui.clu2_numb, ui.but2),
        (ui.clu3, ui.clu3_minu, ui.clu3_plus, ui.clu3_numb, ui.but3),
        (ui.clu4, ui.clu4_minu, ui.clu4_plus, ui.clu4_numb, ui.but4),
        (ui.clu5, ui.clu5_minu, ui.clu5_plus, ui.clu5_numb, ui.but5),
        (ui.clu6, ui.clu6_minu, ui.clu6_plus, ui.clu6_numb, ui.but6),
        (ui.clu7, ui.clu7_minu, ui.clu7_plus, ui.clu7_numb, ui.but7),
    ];
    for ((slot, overlay_left, details), (row, decrease, increase, quantity, button)) in
        prepared_rows.into_iter().zip(row_controls)
    {
        let order = CityOrderId::Ship(slot);
        let bound = bind_city_order_row(
            commands,
            order,
            row,
            decrease,
            increase,
            quantity,
            1,
            Some(ui.root),
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
                overlay_left as i32,
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
                    order,
                    selection: ui.root,
                },
                ShipyardRowAssets { details },
            ))
            .observe(on_city_row_selected);
        commands.entity(bound.quantity).insert(InteractionDisabled);
    }
    commands.entity(ui.snam).insert(ShipyardDisplay::ShipName);
    commands
        .entity(ui.desc)
        .insert(ShipyardDisplay::Description);
    commands.entity(ui.spic).insert(ShipyardDisplay::Picture);
    let base = assets
        .indexed_picture(PictureId::new(9800))
        .expect("retail Shipyard dialog picture must load");
    let palette = *assets.default_dib_palette();
    let image = assets.add_image(base.to_image(&palette));
    commands.entity(ui.dlog).insert((
        ImageNode::new(image),
        ShipyardDetailsVisual { base, stat_labels },
    ));
    commands.entity(ui.root).insert(CityRowSelection {
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
    text: &mut RetailRasterTextPainter<'_>,
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
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
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
        &fonts,
        &font_assets,
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
