use super::*;
use crate::ui::retail::RetailPictureSwap;
use crate::ui::retail_raster::IndexedRasterExt;

struct ShipyardRowView {
    button: Entity,
    quantity: Entity,
}

/// Text that retail drew over the Shipyard detail DIB.  Icons remain indexed;
/// the recovered numeric labels use the normal UI text path.
#[derive(Component)]
pub(in crate::ui::city) struct ShipyardDetailText;

/// Root view of the Shipyard dialog. The detail pane is one retail picture
/// redrawn from the selected ship.
#[derive(Component)]
pub(in crate::ui::city) struct ShipyardView {
    selected: ShipOrderSlot,
    rows: ShipOrderTable<ShipyardRowView>,
    ship_name: Entity,
    description: Entity,
    picture: Entity,
    details: Entity,
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
    let rows = SHIPYARD_CONTROLS.map(|slot, (order_tag, button_tag, overlay_left)| {
        let ship_type = city.orders.ships[slot].ship_type;
        let available = ship_type != ShipType::NoShip;
        let bound = bind_recruitment_order_row(
            commands,
            root,
            tree,
            CityOrderBinding {
                order: CityOrderId::Ship(slot),
                tag: order_tag,
            },
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
        let button = tree.find(root, button_tag);
        bound.set_available(commands, available);
        commands.entity(button).insert(if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
        if available {
            let (idle, active) =
                shipyard_queue_pictures(assets, &queue_icons, slot, ship_type, overlay_left);
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
    let mut bind_text = |tag| {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert(Text::new(""));
        entity
    };
    let ship_name = bind_text(fourcc!("snam"));
    let description = bind_text(fourcc!("desc"));
    let picture = tree.find(root, fourcc!("spic"));
    let dlog = tree.find(root, fourcc!("DLOG"));
    let details_base = assets
        .indexed_picture(PictureId::new(9800))
        .expect("retail Shipyard dialog picture must load");
    let details_image = assets.add_image(details_base.to_image(assets.default_dib_palette()));
    commands.entity(dlog).insert(ImageNode::new(details_image));
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

pub(in crate::ui::city) fn render_shipyard_dialog(
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
    views: Query<Ref<ShipyardView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut images: Query<&mut ImageNode>,
    checked: Query<Has<Checked>>,
    detail_texts: Query<Entity, With<ShipyardDetailText>>,
) {
    for view in &views {
        if !session.is_changed() && !view.is_added() && !view.is_changed() {
            continue;
        }
        let nation = session.active_major_nation();
        for (slot, row) in &view.rows {
            sync_recruitment_row(
                &mut commands,
                &checked,
                &mut texts,
                row.button,
                slot == view.selected,
                row.quantity,
                session
                    .game
                    .city_order_quantity(nation, CityOrderId::Ship(slot))
                    .to_string(),
            );
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
        let mut picture = assets
            .indexed_picture(PictureId::new(9800))
            .expect("retail Shipyard dialog picture must load");
        let costs = ship_order_costs(ship_type);
        for entity in &detail_texts {
            commands.entity(entity).despawn();
        }
        let (font, layout, line_height, _) = assets
            .text_style(RetailTextStylePreset::explicit(3, 0, 10, -2))
            .expect("retail Shipyard detail text style");
        for (column, resource) in SHIPYARD_MATERIALS
            .iter()
            .filter_map(|&resource| {
                let required = costs[resource];
                (required != 0).then_some(resource)
            })
            .enumerate()
        {
            let text_x = 0x3a + column as i32 * 0x28;
            let material = assets
                .indexed_picture(PictureId::new(700 + i16::from(resource.retail())))
                .expect("retail Shipyard material picture must load");
            picture.blit_keyed_at(&material, IVec2::new(text_x - 0x20, 0x98), 0x10);
            picture.blit_keyed_at(&material, IVec2::new(text_x - 0x20, 0xcc), 0x10);
            let required = costs[resource];
            let available = city.stockpile[resource];
            for (baseline, value, color) in [
                (0xb2, required, assets.palette_color(0xd2)),
                (
                    0xe6,
                    available,
                    if available < required {
                        assets.palette_color(0xcb)
                    } else {
                        assets.palette_color(0xd2)
                    },
                ),
            ] {
                commands.spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(text_x),
                        top: px(baseline - 11),
                        ..default()
                    },
                    Text::new(value.to_string()),
                    font.clone(),
                    layout,
                    line_height,
                    TextColor(color),
                    Pickable::IGNORE,
                    ShipyardDetailText,
                    ChildOf(view.details),
                ));
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
        for (index, &(left, baseline)) in generated::SHIPYARD_STAT_ORIGINS.iter().enumerate() {
            for (x, value) in [
                (left, city_string(&assets, 0x2736, 0x10 + index as i16)),
                (left + 0x3c, values[index].to_string()),
            ] {
                commands.spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(x),
                        top: px(baseline - 11),
                        ..default()
                    },
                    Text::new(value),
                    font.clone(),
                    layout,
                    line_height,
                    TextColor(assets.palette_color(0xd2)),
                    Pickable::IGNORE,
                    ShipyardDetailText,
                    ChildOf(view.details),
                ));
            }
        }
        let image = images
            .get_mut(view.details)
            .expect("bound Shipyard details picture");
        assets.replace_image(&image.image, picture.to_image(assets.default_dib_palette()));
    }
}
