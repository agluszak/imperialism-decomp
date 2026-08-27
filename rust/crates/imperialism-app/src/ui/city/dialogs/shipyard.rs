use super::*;
use crate::RetailFonts;
use crate::ui::retail::RetailPictureSwap;
use crate::ui::retail_raster::IndexedRasterExt;
use crate::ui::retail_raster_text::RetailRasterTextPainter;
use imperialism_formats::StringGroup;

const SHIPYARD_MATERIALS: [ResourceKind; 6] = [
    ResourceKind::Fabric,
    ResourceKind::Lumber,
    ResourceKind::Arms,
    ResourceKind::Steel,
    ResourceKind::Coal,
    ResourceKind::Fuel,
];

pub(in crate::ui::city) struct ShipyardUi {
    pub(in crate::ui::city) selected: ShipOrderSlot,
    rows: ShipOrderTable<SelectionRow>,
    ship_name: Entity,
    description: Entity,
    picture: Entity,
    details: Entity,
}

pub(in crate::ui::city) fn bind_shipyard(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    state: &GameState,
) -> ShipyardUi {
    let nation = MajorNationId::from_nation(state.turn().active_nation).expect("major nation");
    let city = &state.nations().major(nation).city;
    let queue_icons = assets
        .indexed_picture(PictureId::new(9807))
        .expect("queue icons");
    let rows = ShipOrderTable::from_array(generated::SHIPYARD_ROW_CONTROLS).map(
        |slot, (order_tag, button_tag, overlay_left)| {
            let ship_type = city.orders.ships[slot].ship_type;
            let available = ship_type != ShipType::NoShip;
            let bound = bind_recruitment_order_row(
                commands,
                root,
                tree,
                CityOrderId::Ship(slot),
                order_tag,
            );
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
            bind_row_selection(commands, tree, root, bound.row, button, move |view| {
                if let CityDialogView::Shipyard(s) = view {
                    s.selected = slot;
                }
            });
            commands.entity(bound.quantity).insert(InteractionDisabled);
            SelectionRow(button, bound.quantity)
        },
    );
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
        .expect("dialog pic");
    let details_image = assets.add_image(details_base.to_image(assets.default_dib_palette()));
    commands.entity(dlog).insert(ImageNode::new(details_image));
    ShipyardUi {
        selected: ShipOrderSlot::MerchantEarlyPrimary,
        rows,
        ship_name,
        description,
        picture,
        details: dlog,
    }
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
    let mut compose = |picture_id: PictureId| {
        let mut picture = assets.indexed_picture(picture_id).expect("queue button");
        picture.blit_keyed(queue_icons, source, IVec2::new(overlay_left, 0x0c), 0x10);
        assets.add_image(picture.to_image(&palette))
    };
    let idle_id = PictureId::new(9808).offset(i16::from(slot as u8) * 2);
    (compose(idle_id), compose(idle_id.offset(1)))
}

pub(in crate::ui::city) fn render_shipyard(
    view: &ShipyardUi,
    session: &GameSession,
    assets: &mut RetailUiAssets,
    fonts: &RetailFonts,
    font_assets: &Assets<Font>,
    ui: &mut CityUi,
) {
    let nation = session.active_major_nation();
    for (slot, row) in &view.rows {
        sync_recruitment_row(
            ui,
            *row,
            slot == view.selected,
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
        return;
    }
    ui.text(
        view.ship_name,
        assets.string(ship_type.name_string()).expect("ship name"),
    );
    ui.text(
        view.description,
        assets
            .string(ship_type.description_string())
            .expect("ship desc"),
    );
    ui.image(
        view.picture,
        assets
            .picture(ship_type.detail_picture())
            .expect("detail pic"),
    );
    let mut picture = assets
        .indexed_picture(PictureId::new(9800))
        .expect("dialog pic");
    let mut text = RetailRasterTextPainter::from_preset(
        fonts,
        font_assets,
        RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: -2,
        },
    )
    .expect("text style");
    let costs = ship_order_costs(ship_type);
    for (column, (resource, required)) in SHIPYARD_MATERIALS
        .iter()
        .filter_map(|&resource| {
            let required = costs[resource];
            (required != 0).then_some((resource, required))
        })
        .enumerate()
    {
        let text_x = 0x3a + column as i32 * 0x28;
        let material = assets
            .indexed_picture(resource.material_picture())
            .expect("material");
        picture.blit_keyed_at(&material, IVec2::new(text_x - 0x20, 0x98), 0x10);
        picture.blit_keyed_at(&material, IVec2::new(text_x - 0x20, 0xcc), 0x10);
        text.draw(
            &mut picture,
            IVec2::new(text_x, 0xb2),
            &required.to_string(),
            0xd2,
        );
        let available = city.stockpile[resource];
        text.draw(
            &mut picture,
            IVec2::new(text_x, 0xe6),
            &available.to_string(),
            if available < required { 0xcb } else { 0xd2 },
        );
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
        let origin = IVec2::new(left, baseline);
        text.draw(
            &mut picture,
            origin,
            &assets
                .string(StringGroup::new(0x2736).offset(0x10 + index as u16))
                .expect("shipyard stat label"),
            0xd2,
        );
        text.draw(
            &mut picture,
            origin + IVec2::new(0x3c, 0),
            &values[index].to_string(),
            0xd2,
        );
    }
    let image = ui.images.get_mut(view.details).expect("details");
    assets.replace_image(&image.image, picture.to_image(assets.default_dib_palette()));
}
