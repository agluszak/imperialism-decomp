use super::*;
use crate::RetailFonts;
use crate::ui::retail::RetailPictureSwap;
use crate::ui::retail_raster::IndexedRasterExt;
use crate::ui::retail_raster_text::RetailRasterTextPainter;

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

/// One Shipyard row's button and the retail ship facts it selects.
struct ShipyardRowView {
    button: Entity,
    quantity: Entity,
    details: Option<ShipyardRowData>,
}

/// Root view of the Shipyard dialog.
#[derive(Component)]
pub(in crate::ui::city) struct ShipyardView {
    selected: ShipOrderSlot,
    rows: [ShipyardRowView; SHIPYARD_ROWS.len()],
    ship_name: Entity,
    description: Entity,
    picture: Entity,
    details: Entity,
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
    let queue_icons = assets
        .indexed_picture(PictureId::new(9807))
        .expect("retail Shipyard queue icons must load");
    let stat_labels: [String; 6] =
        std::array::from_fn(|index| city_string(assets, 0x2736, 0x10 + index as i16));
    let rows = SHIPYARD_ROWS.map(|spec| {
        let slot = spec.slot();
        let ship_type = city.orders.ships[slot].ship_type;
        let details = if ship_type == ShipType::NoShip {
            None
        } else {
            let costs = ship_order_costs(ship_type);
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
            })
        };
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
        for arrow in [bound.decrease, bound.increase] {
            commands.entity(arrow).observe(
                move |_: On<Activate>, mut views: Query<&mut ShipyardView>| {
                    if let Ok(mut view) = views.get_mut(root) {
                        view.selected = slot;
                    }
                },
            );
        }
        let button = tree.find(root, spec.button_tag);
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
            details,
        }
    });
    let mut bind_text = |tag| {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(""));
        entity
    };
    let ship_name = bind_text(fourcc!("snam"));
    let description = bind_text(fourcc!("desc"));
    let picture = tree.find(root, fourcc!("spic"));
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
    commands.entity(root).insert(ShipyardView {
        selected: ShipOrderSlot::MerchantEarlyPrimary,
        rows,
        ship_name,
        description,
        picture,
        details: dlog,
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

pub(in crate::ui::city) fn render_shipyard_dialog(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    fonts: Res<RetailFonts>,
    font_assets: Res<Assets<Font>>,
    mut image_assets: ResMut<Assets<Image>>,
    views: Query<Ref<ShipyardView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut images: Query<&mut ImageNode>,
    details: Query<(&ShipyardDetailsVisual, &ImageNode)>,
    checked: Query<Has<Checked>>,
) {
    for view in &views {
        if !session.is_changed() && !view.is_added() && !view.is_changed() {
            continue;
        }
        let nation = session.active_major_nation();
        for (spec, row) in SHIPYARD_ROWS.iter().zip(&view.rows) {
            let selected = spec.slot() == view.selected;
            let checked = checked.get(row.button).unwrap_or(false);
            if selected && !checked {
                commands.entity(row.button).insert(Checked);
            } else if !selected && checked {
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
        let row = SHIPYARD_ROWS
            .iter()
            .zip(&view.rows)
            .find(|(spec, _)| spec.slot() == view.selected)
            .and_then(|(_, row)| row.details.as_ref())
            .expect("Shipyard selection has a bound retail row");
        texts
            .get_mut(view.ship_name)
            .expect("bound Shipyard ship name")
            .0
            .clone_from(&row.ship_name);
        texts
            .get_mut(view.description)
            .expect("bound Shipyard description")
            .0
            .clone_from(&row.description);
        images
            .get_mut(view.picture)
            .expect("bound Shipyard picture")
            .image
            .clone_from(&row.picture);
        let city = &session.game.nations().major(nation).city;
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
        let Ok((visual, image_node)) = details.get(view.details) else {
            continue;
        };
        let mut picture = visual.base.clone();
        draw_shipyard_details(&mut picture, &mut text, &visual.stat_labels, row, city);
        if let Some(mut image) = image_assets.get_mut(&image_node.image) {
            *image = picture.to_image(retail.assets().default_dib_palette());
        }
    }
}
