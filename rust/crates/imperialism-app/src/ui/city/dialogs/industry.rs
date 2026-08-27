use super::*;
use crate::ui::retail::AmountBarParts;

fn industry_stock_minimum(resource: ResourceKind) -> i16 {
    match resource {
        ResourceKind::Cotton | ResourceKind::Wool | ResourceKind::Iron | ResourceKind::Coal => 1,
        ResourceKind::Fabric
        | ResourceKind::Steel
        | ResourceKind::Timber
        | ResourceKind::Lumber
        | ResourceKind::Oil => 2,
        other => panic!("unexpected industry input resource {other:?}"),
    }
}

fn industry_items(slot: CityFacilitySlot) -> Vec<ManufacturedItem> {
    ManufacturedItem::ALL
        .into_iter()
        .filter(|item| item.facility() == slot)
        .collect()
}

fn industry_inputs(items: &[ManufacturedItem]) -> Vec<ResourceKind> {
    let mut inputs: Vec<_> = items
        .iter()
        .flat_map(|item| match item.inputs() {
            ItemInputs::Double(resource) => [Some(resource), None],
            ItemInputs::Both(a, b) | ItemInputs::Either(a, b) => [Some(a), Some(b)],
        })
        .flatten()
        .collect();
    inputs.sort_unstable();
    inputs.dedup();
    inputs
}

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
    let items = industry_items(slot);
    let order_tags: Vec<_> = items
        .iter()
        .copied()
        .map(|item| resource_control_tag(item.resource()))
        .collect();
    let inputs = industry_inputs(&items);

    commands
        .entity(tree.find(root, fourcc!("name")))
        .insert(Text::new(city_building_name(assets, slot)));
    let capacity = tree.find(root, fourcc!("capT"));
    let labor = tree.find(root, fourcc!("labV"));
    commands.entity(labor).insert(Text::new("X"));
    let stocks = inputs
        .iter()
        .copied()
        .map(|resource| {
            let tag = resource_control_tag(resource);
            let minimum = industry_stock_minimum(resource);
            (tree.find(root, tag), resource, minimum)
        })
        .collect();
    let orders = bind_industry_orders(commands, root, tree, amount_bars, &items, &order_tags);
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
    for order in &view.orders {
        let order_id = CityOrderId::Item(order.item);
        let quantity = session.game.city_order_quantity(nation, order_id);
        let range = amount_bar_range(&session.game, nation, order_id);
        let maximum = session.game.city_order_limit(nation, order_id).maximum;
        ui.amount_bar(order.bar, quantity, range, maximum);
    }
}

pub(in crate::ui::city) fn render_rail(
    session: &GameSession,
    nation: MajorNationId,
    order: CityOrderId,
    rail: &RailUi,
    ui: &mut CityUi,
) {
    let quantity = session.game.city_order_quantity(nation, order);
    let range = amount_bar_range(&session.game, nation, order);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn industry_order_tags_match_retail_controls() {
        assert_eq!(
            industry_items(CityFacilitySlot::TextileMill)
                .into_iter()
                .map(|item| resource_control_tag(item.resource()))
                .collect::<Vec<_>>(),
            vec![fourcc!("fabr")]
        );
        assert_eq!(
            industry_items(CityFacilitySlot::Metalworks)
                .into_iter()
                .map(|item| resource_control_tag(item.resource()))
                .collect::<Vec<_>>(),
            vec![fourcc!("hard"), fourcc!("arma")]
        );
        assert_eq!(
            industry_items(CityFacilitySlot::LumberMill)
                .into_iter()
                .map(|item| resource_control_tag(item.resource()))
                .collect::<Vec<_>>(),
            vec![fourcc!("lumb"), fourcc!("pape")]
        );
    }

    #[test]
    fn industry_stock_indicators_follow_input_resources() {
        let textile = industry_items(CityFacilitySlot::TextileMill);
        assert_eq!(
            industry_inputs(&textile)
                .into_iter()
                .map(|resource| (
                    resource_control_tag(resource),
                    industry_stock_minimum(resource)
                ))
                .collect::<Vec<_>>(),
            vec![(fourcc!("cott"), 1), (fourcc!("wool"), 1)]
        );

        let metalworks = industry_items(CityFacilitySlot::Metalworks);
        assert_eq!(
            industry_inputs(&metalworks)
                .into_iter()
                .map(|resource| (
                    resource_control_tag(resource),
                    industry_stock_minimum(resource)
                ))
                .collect::<Vec<_>>(),
            vec![(fourcc!("stee"), 2)]
        );
    }
}
