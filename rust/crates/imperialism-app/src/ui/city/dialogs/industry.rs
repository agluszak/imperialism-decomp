use super::*;
use crate::ui::retail::AmountBarParts;

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct IndustryOrderUi {
    pub(in crate::ui::city) item: ManufacturedItem,
    pub(in crate::ui::city) bar: AmountBarView,
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct RailUi {
    pub(in crate::ui::city) bar: AmountBarView,
}

pub(in crate::ui::city) struct IndustryUi {
    capacity: Entity,
    labor: Entity,
    stocks: Vec<(Entity, ResourceKind, i16)>,
    expansion: Entity,
    pub(in crate::ui::city) orders: Vec<IndustryOrderUi>,
}

fn bind_industry_orders(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    amount_bars: &Query<&AmountBarParts>,
    items: &[ManufacturedItem],
    order_tags: &[FourCc],
) -> Vec<IndustryOrderUi> {
    items
        .iter()
        .zip(order_tags)
        .map(|(&item, &tag)| {
            let bound = bind_industry_order_row(
                commands,
                root,
                tree,
                amount_bars,
                CityOrderId::Item(item),
                tag,
                1,
            );
            IndustryOrderUi {
                item,
                bar: bound.bar.expect("industry amount bar"),
            }
        })
        .collect()
}

pub(in crate::ui::city) fn bind_industry(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    amount_bars: &Query<&AmountBarParts>,
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
    let orders = bind_industry_orders(commands, root, tree, amount_bars, &items, page.order_tags);
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

pub(in crate::ui::city) fn render_industry(
    slot: CityFacilitySlot,
    view: &IndustryUi,
    session: &GameSession,
    nation: MajorNationId,
    assets: &RetailUiAssets,
    ui: &mut CityUi,
) {
    let city = &session.game.nations().major(nation).city;
    let capacity_template = city_text(assets, 0x10);
    ui.text(
        view.capacity,
        format_retail_number(&capacity_template, city.production_orders[slot]),
    );
    ui.visible(view.labor, city.population.strength() >= 2);
    for &(entity, resource, minimum) in &view.stocks {
        ui.visible(entity, city.stockpile[resource] < minimum);
    }
    ui.visible(view.expansion, city_is_expanding(city, slot));
    let range = city.production_orders[slot];
    for order in &view.orders {
        let quantity = session
            .game
            .city_order_quantity(nation, CityOrderId::Item(order.item));
        let maximum = session
            .game
            .city_order_limit(nation, CityOrderId::Item(order.item))
            .maximum;
        ui.amount_bar(order.bar, quantity, range, maximum);
    }
}

fn rail_bar_capacity(
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
    order: CityOrderId,
    rail: &RailUi,
    ui: &mut CityUi,
) {
    let city = &session.game.nations().major(nation).city;
    let quantity = session.game.city_order_quantity(nation, order);
    let range = rail_bar_capacity(city, order, nation, &session.game);
    let maximum = session.game.city_order_limit(nation, order).maximum;
    ui.amount_bar(rail.bar, quantity, range, maximum);
}

pub(in crate::ui::city) fn bind_rail(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    amount_bars: &Query<&AmountBarParts>,
    slot: CityFacilitySlot,
    order: CityOrderId,
    tag: FourCc,
    step: i16,
) -> RailUi {
    commands
        .entity(tree.find(root, fourcc!("name")))
        .insert(Text::new(city_building_name(assets, slot)));
    let counter = bind_industry_order_row(commands, root, tree, amount_bars, order, tag, step);
    RailUi {
        bar: counter.bar.expect("rail amount bar"),
    }
}
