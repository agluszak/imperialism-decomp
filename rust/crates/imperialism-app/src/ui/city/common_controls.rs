use super::*;
use crate::ui::retail_amount_bar::{
    AmountBarGeometry, INDUSTRY_AMOUNT_BAR, INDUSTRY_BAR_FILL, amount_bar_click_value,
    amount_bar_x_from_normalized, quantize_amount_bar_value,
};

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct AmountBarUi {
    pub(in crate::ui::city) track: Entity,
    pub(in crate::ui::city) quantity: Entity,
    pub(in crate::ui::city) fill: Entity,
    pub(in crate::ui::city) limit: Entity,
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct IndustryOrderUi {
    pub(in crate::ui::city) item: ManufacturedItem,
    pub(in crate::ui::city) bar: AmountBarUi,
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct RailUi {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) bar: AmountBarUi,
}

pub(in crate::ui::city) struct IndustryUi {
    capacity: Entity,
    labor: Entity,
    stocks: Vec<(Entity, ResourceKind, i16)>,
    expansion: Entity,
    pub(in crate::ui::city) orders: Vec<IndustryOrderUi>,
}

pub(in crate::ui::city) fn city_building_name(
    assets: &RetailUiAssets,
    slot: CityFacilitySlot,
) -> String {
    city_string(assets, CITY_BUILDING_STRING_GROUP, i16::from(slot.retail()))
}

pub(in crate::ui::city) struct CityOrderRow {
    pub(in crate::ui::city) row: Entity,
    pub(in crate::ui::city) quantity: Entity,
}

impl CityOrderRow {
    pub(in crate::ui::city) fn set_available(&self, commands: &mut Commands, available: bool) {
        commands.entity(self.row).insert(if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
    }
}

fn bind_city_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
) -> CityOrderRow {
    let row = tree.find(root, tag);
    let decrease = tree.find(row, decrease_tag);
    let increase = tree.find(row, increase_tag);
    let quantity = tree.find(row, quantity_tag);
    let bind_step = |commands: &mut Commands, entity: Entity, delta: i16| {
        commands.entity(entity).observe(
            move |_: On<Activate>, mut session: ResMut<GameSession>| {
                let nation = session.active_major_nation();
                session.game.adjust_city_order(nation, order, delta);
            },
        );
    };
    bind_step(commands, decrease, -step);
    bind_step(commands, increase, step);
    CityOrderRow { row, quantity }
}

pub(in crate::ui::city) fn bind_industry_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
    step: i16,
) -> CityOrderRow {
    bind_city_order_row(
        commands,
        root,
        tree,
        order,
        tag,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
    )
}

pub(in crate::ui::city) fn bind_recruitment_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    tag: FourCc,
) -> CityOrderRow {
    bind_city_order_row(
        commands,
        root,
        tree,
        order,
        tag,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    )
}

fn bind_amount_bar_visual(
    commands: &mut Commands,
    assets: &RetailUiAssets,
    parent: Entity,
) -> (Entity, Entity) {
    let mut spawn_child = |left, top, width, height, color| {
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
                BackgroundColor(color),
                Pickable::IGNORE,
                ChildOf(parent),
            ))
            .id()
    };
    let fill = spawn_child(0.0, 1.0, 0.0, 4.0, assets.palette_color(INDUSTRY_BAR_FILL));
    let limit = spawn_child(0.0, 0.0, 1.0, 5.0, assets.palette_color(0));
    (fill, limit)
}

fn bind_industry_orders(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    slot: CityFacilitySlot,
    items: &[ManufacturedItem],
    order_tags: &[FourCc],
) -> Vec<IndustryOrderUi> {
    items
        .iter()
        .zip(order_tags)
        .map(|(&item, &tag)| {
            let bound =
                bind_industry_order_row(commands, root, tree, CityOrderId::Item(item), tag, 1);
            let track = tree.find(bound.row, fourcc!("bar "));
            let (fill, limit) = bind_amount_bar_visual(commands, assets, track);
            commands.entity(track).observe(
                move |mut click: On<Pointer<Click>>, mut session: ResMut<GameSession>| {
                    let Some(position) = click.hit.position else {
                        return;
                    };
                    click.propagate(false);
                    let nation = session.active_major_nation();
                    let city = &session.game.nations().major(nation).city;
                    let capacity = city.production_orders[slot];
                    let previous = city.orders.items[item].progress.quantity;
                    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
                    let x = amount_bar_x_from_normalized(geometry, position.x);
                    let quantity = amount_bar_click_value(geometry, x, previous);
                    session
                        .game
                        .set_city_order_quantity(nation, CityOrderId::Item(item), quantity);
                },
            );
            IndustryOrderUi {
                item,
                bar: AmountBarUi {
                    track,
                    quantity: bound.quantity,
                    fill,
                    limit,
                },
            }
        })
        .collect()
}

pub(in crate::ui::city) fn bind_industry(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    slot: CityFacilitySlot,
) -> IndustryUi {
    let page = generated::INDUSTRY_PAGE_CONTROLS
        .iter()
        .find(|page| page.slot == slot)
        .expect("industry page");
    let items: Vec<_> = ManufacturedItem::ALL
        .into_iter()
        .filter(|item| item.facility() == slot)
        .collect();
    debug_assert_eq!(items.len(), page.order_tags.len());

    let mut inputs: Vec<_> = items
        .iter()
        .flat_map(|item| match item.inputs() {
            ItemInputs::Double(a) => [Some(a), None],
            ItemInputs::Both(a, b) | ItemInputs::Either(a, b) => [Some(a), Some(b)],
        })
        .flatten()
        .collect();
    inputs.sort_unstable();
    inputs.dedup();
    debug_assert_eq!(inputs.len(), page.stocks.len());

    commands
        .entity(tree.find(root, fourcc!("name")))
        .insert(Text::new(city_building_name(assets, slot)));
    let capacity = tree.find(root, fourcc!("capT"));
    let labor = tree.find(root, fourcc!("labV"));
    commands.entity(labor).insert(Text::new("X"));
    let stocks = inputs
        .iter()
        .zip(page.stocks)
        .map(|(&resource, &(tag, minimum))| (tree.find(root, tag), resource, minimum))
        .collect();
    let orders = bind_industry_orders(commands, assets, root, tree, slot, &items, page.order_tags);
    commands.entity(tree.find(root, fourcc!("expa"))).observe(
        move |_: On<Activate>, session: Res<GameSession>, mut commands: Commands| {
            open_city_expansion_dialog(&mut commands, &session, slot);
        },
    );
    IndustryUi {
        capacity,
        labor,
        stocks,
        expansion: tree.find(root, fourcc!("flag")),
        orders,
    }
}

pub(in crate::ui::city) fn render_amount_bar(
    ui: &mut CityUi,
    bar: &AmountBarUi,
    geometry: AmountBarGeometry,
    quantity: i16,
    maximum: i16,
) {
    ui.text(bar.quantity, quantity.to_string());
    let span = geometry.span(quantity);
    ui.nodes.get_mut(bar.fill).expect("fill").width = px(f32::from(span));
    ui.nodes.get_mut(bar.limit).expect("limit").left = px(f32::from(geometry.span(maximum)));
    let track = ui.nodes.get(bar.track).expect("track");
    let (Val::Px(bar_left), Val::Px(bar_top)) = (track.left, track.top) else {
        return;
    };
    let mut counter = ui.nodes.get_mut(bar.quantity).expect("qty");
    counter.left = px(bar_left + f32::from(span) - 2.0);
    counter.top = px(bar_top + 6.0);
}

pub(in crate::ui::city) fn render_industry(
    slot: CityFacilitySlot,
    view: &IndustryUi,
    session: &GameSession,
    nation: MajorNationId,
    assets: &RetailUiAssets,
    ui: &mut CityUi,
) {
    let city = &session.game.nations().major(nation).city;
    let capacity_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x10);
    ui.text(
        view.capacity,
        format_retail_number(&capacity_template, city.production_orders[slot]),
    );
    ui.visible(view.labor, city.population.strength() >= 2);
    for &(entity, resource, minimum) in &view.stocks {
        ui.visible(entity, city.stockpile[resource] < minimum);
    }
    ui.visible(view.expansion, city_is_expanding(city, slot));
    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(city.production_orders[slot]);
    for order in &view.orders {
        let quantity = session
            .game
            .city_order_quantity(nation, CityOrderId::Item(order.item));
        let maximum = session
            .game
            .city_order_limit(nation, CityOrderId::Item(order.item))
            .maximum;
        render_amount_bar(ui, &order.bar, geometry, quantity, maximum);
    }
}

pub(in crate::ui::city) fn rail_bar_capacity(
    city: &CityState,
    order: CityOrderId,
    nation: MajorNationId,
    game: &GameState,
) -> i16 {
    match order {
        CityOrderId::FoodProcessing | CityOrderId::TransportCapacity => {
            let labor = city.population.production_labor();
            ((labor.high * 2 + labor.medium) * 2 + city.population.extra() + labor.low) / 2
        }
        _ => game.city_order_limit(nation, order).maximum,
    }
}

pub(in crate::ui::city) fn render_rail(
    session: &GameSession,
    nation: MajorNationId,
    rail: &RailUi,
    ui: &mut CityUi,
) {
    let city = &session.game.nations().major(nation).city;
    let quantity = session.game.city_order_quantity(nation, rail.order);
    let capacity = rail_bar_capacity(city, rail.order, nation, &session.game);
    let maximum = session.game.city_order_limit(nation, rail.order).maximum;
    render_amount_bar(
        ui,
        &rail.bar,
        INDUSTRY_AMOUNT_BAR.with_segments(capacity),
        quantity,
        maximum,
    );
}

pub(in crate::ui::city) fn bind_rail_bar_click(
    commands: &mut Commands,
    bar: Entity,
    order: CityOrderId,
    step: i16,
) {
    commands.entity(bar).observe(
        move |mut click: On<Pointer<Click>>, mut session: ResMut<GameSession>| {
            let Some(position) = click.hit.position else {
                return;
            };
            click.propagate(false);
            let nation = session.active_major_nation();
            let city = &session.game.nations().major(nation).city;
            let capacity = rail_bar_capacity(city, order, nation, &session.game);
            let previous = session.game.city_order_quantity(nation, order);
            let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
            let x = amount_bar_x_from_normalized(geometry, position.x);
            let quantity =
                quantize_amount_bar_value(amount_bar_click_value(geometry, x, previous), step);
            session
                .game
                .set_city_order_quantity(nation, order, quantity);
        },
    );
}

pub(in crate::ui::city) fn bind_rail(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    slot: CityFacilitySlot,
    order: CityOrderId,
    tag: FourCc,
    step: i16,
) -> RailUi {
    commands
        .entity(tree.find(root, fourcc!("name")))
        .insert(Text::new(city_building_name(assets, slot)));
    let counter = bind_industry_order_row(commands, root, tree, order, tag, step);
    let track = tree.find(counter.row, fourcc!("bar "));
    let (fill, limit) = bind_amount_bar_visual(commands, assets, track);
    bind_rail_bar_click(commands, track, order, step);
    RailUi {
        order,
        bar: AmountBarUi {
            track,
            quantity: counter.quantity,
            fill,
            limit,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specialized_city_buildings_use_the_one_based_retail_name_indexes() {
        assert_eq!(
            city_string_index(i16::from(CityFacilitySlot::OilRefinery.retail())),
            7
        );
        assert_eq!(
            city_string_index(i16::from(CityFacilitySlot::Shipyard.retail())),
            8
        );
        assert_eq!(
            city_string_index(i16::from(CityFacilitySlot::Armory.retail())),
            9
        );
    }
}
