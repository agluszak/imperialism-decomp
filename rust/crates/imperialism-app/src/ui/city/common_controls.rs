use super::*;
use crate::ui::retail_amount_bar::{
    INDUSTRY_AMOUNT_BAR, INDUSTRY_BAR_FILL, amount_bar_click_value, amount_bar_x_from_normalized,
    quantize_amount_bar_value,
};

pub(in crate::ui::city) const INDUSTRY_BAR_X: f32 = 62.0;
pub(in crate::ui::city) const INDUSTRY_BAR_Y: f32 = 8.0;

/// Syncs one recruitment row's checked button and quantity marker. The checked
/// guard writes only on change so the radio button does not re-emit
/// `ValueChange` every render.
pub(in crate::ui::city) fn sync_recruitment_row(
    commands: &mut Commands,
    checked: &Query<Has<Checked>>,
    texts: &mut Query<&mut Text>,
    button: Entity,
    selected: bool,
    quantity: Entity,
    quantity_text: String,
) {
    let is_checked = checked.get(button).unwrap_or(false);
    if selected && !is_checked {
        commands.entity(button).insert(Checked);
    } else if !selected && is_checked {
        commands.entity(button).remove::<Checked>();
    }
    texts
        .get_mut(quantity)
        .expect("bound recruitment order quantity")
        .0 = quantity_text;
}

/// The rail-style order counter and native amount bar owned by one rail dialog.
#[derive(Clone, Copy)]
pub(in crate::ui::city) struct RailControls {
    pub(in crate::ui::city) bar: Entity,
    pub(in crate::ui::city) quantity: Entity,
    pub(in crate::ui::city) fill: Entity,
    pub(in crate::ui::city) tick: Entity,
}

/// One industry-dialog order row: the quantity marker over the amount bar.
#[derive(Clone, Copy)]
pub(in crate::ui::city) struct IndustryOrderView {
    quantity: Entity,
    fill: Entity,
    tick: Entity,
}

/// Root view of an ordinary industry dialog.
#[derive(Component)]
pub(in crate::ui::city) struct IndustryView {
    pub(in crate::ui::city) slot: CityFacilitySlot,
    capacity: Entity,
    labor: Entity,
    stocks: Vec<(Entity, ResourceKind, i16)>,
    expansion: Entity,
    pub(in crate::ui::city) orders: Vec<IndustryOrderView>,
}

pub(in crate::ui::city) fn city_building_name(
    assets: &RetailUiAssets,
    slot: CityFacilitySlot,
) -> String {
    city_string(assets, CITY_BUILDING_STRING_GROUP, i16::from(slot.retail()))
}

pub(in crate::ui::city) fn configure_industry_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    page: IndustryPage,
) {
    let building_name = city_building_name(assets, page.slot);
    bind_industry_dialog(commands, assets, root, tree, page, building_name);
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

#[allow(clippy::too_many_arguments)]
fn bind_city_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    binding: CityOrderBinding,
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
) -> CityOrderRow {
    let row = tree.find(root, binding.tag);
    let decrease = tree.find(row, decrease_tag);
    let increase = tree.find(row, increase_tag);
    let quantity = tree.find(row, quantity_tag);
    let order = binding.order;
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

/// Binds an ordinary industry/rail order row with its `left`/`rght` arrows.
pub(in crate::ui::city) fn bind_industry_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    binding: CityOrderBinding,
    step: i16,
) -> CityOrderRow {
    bind_city_order_row(
        commands,
        root,
        tree,
        binding,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
    )
}

/// Binds a recruitment order row with its `minu`/`plus` arrows.
pub(in crate::ui::city) fn bind_recruitment_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    binding: CityOrderBinding,
) -> CityOrderRow {
    bind_city_order_row(
        commands,
        root,
        tree,
        binding,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
    )
}

fn bind_industry_orders(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    page: IndustryPage,
) -> Vec<IndustryOrderView> {
    page.orders
        .iter()
        .map(|binding| {
            let bound = bind_industry_order_row(commands, root, tree, *binding, 1);
            let bar = tree.find(bound.row, fourcc!("bar "));
            let visual = bind_amount_bar_visual(commands, assets, bar);
            let order = binding.order;
            let slot = page.slot;
            commands.entity(bar).observe(
                move |mut click: On<Pointer<Click>>, mut session: ResMut<GameSession>| {
                    let Some(position) = click.hit.position else {
                        return;
                    };
                    click.propagate(false);
                    let nation = session.active_major_nation();
                    let city = &session.game.nations().major(nation).city;
                    let capacity = city.production_orders[slot];
                    let previous = match order {
                        CityOrderId::Item(output) => city.orders.items[output].progress.quantity,
                        _ => unreachable!("industry amount bar has an item order"),
                    };
                    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
                    let x = amount_bar_x_from_normalized(geometry, position.x);
                    let quantity = amount_bar_click_value(geometry, x, previous);
                    session
                        .game
                        .set_city_order_quantity(nation, order, quantity);
                },
            );
            IndustryOrderView {
                quantity: bound.quantity,
                fill: visual.fill,
                tick: visual.tick,
            }
        })
        .collect()
}

/// Native fill/range nodes over a recovered amount-bar track.
#[derive(Clone, Copy)]
struct AmountBarView {
    fill: Entity,
    tick: Entity,
}

/// Overlays an amount bar's fill and range tick as children of `parent`.
fn bind_amount_bar_visual(
    commands: &mut Commands,
    assets: &RetailUiAssets,
    parent: Entity,
) -> AmountBarView {
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
    let tick = spawn_child(0.0, 0.0, 1.0, 5.0, assets.palette_color(0));
    AmountBarView { fill, tick }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_industry_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    page: IndustryPage,
    building_name: String,
) {
    let name = tree.find(root, fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    let capacity = tree.find(root, fourcc!("capT"));
    let labor = tree.find(root, fourcc!("labV"));
    commands.entity(labor).insert(Text::new("X"));
    let stocks = page
        .stocks
        .iter()
        .map(|&(resource, tag, minimum)| (tree.find(root, tag), resource, minimum))
        .collect();
    let orders = bind_industry_orders(commands, assets, root, tree, page);
    let expansion_action = tree.find(root, fourcc!("expa"));
    commands
        .entity(expansion_action)
        .insert(CityExpansionOpen { slot: page.slot })
        .observe(on_city_expansion_open);
    let expansion = tree.find(root, fourcc!("flag"));
    commands.entity(root).insert(IndustryView {
        slot: page.slot,
        capacity,
        labor,
        stocks,
        expansion,
        orders,
    });
}

pub(in crate::ui::city) fn render_industry_dialog(
    session: Res<GameSession>,
    views: Query<Ref<IndustryView>>,
    assets: RetailUiAssets,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut nodes: Query<&mut Node>,
) {
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    let capacity_template = city_string(&assets, CITY_TEXT_STRING_GROUP, 0x10);
    for view in &views {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let page = INDUSTRY_PAGES
            .iter()
            .find(|page| page.slot == view.slot)
            .expect("industry dialog view has a recovered page");
        texts
            .get_mut(view.capacity)
            .expect("bound industry capacity text must exist")
            .0 = format_retail_number(&capacity_template, city.production_orders[view.slot]);
        commands
            .entity(view.labor)
            .insert(if city.population.strength() >= 2 {
                Visibility::Visible
            } else {
                Visibility::Hidden
            });
        for &(entity, resource, minimum) in &view.stocks {
            commands
                .entity(entity)
                .insert(if city.stockpile[resource] < minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                });
        }
        commands
            .entity(view.expansion)
            .insert(if city_is_expanding(city, view.slot) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            });
        for (binding, order) in page.orders.iter().zip(&view.orders) {
            let quantity = session.game.city_order_quantity(nation, binding.order);
            texts
                .get_mut(order.quantity)
                .expect("bound industry order quantity must exist")
                .0 = quantity.to_string();
            let geometry = INDUSTRY_AMOUNT_BAR.with_segments(city.production_orders[view.slot]);
            let span = geometry.span(quantity);
            nodes
                .get_mut(order.quantity)
                .expect("bound industry order marker must exist")
                .left = px(INDUSTRY_BAR_X + f32::from(span) - 2.0);
            nodes
                .get_mut(order.quantity)
                .expect("bound industry order marker must exist")
                .top = px(INDUSTRY_BAR_Y + 6.0);
            nodes
                .get_mut(order.fill)
                .expect("bound industry amount bar must exist")
                .width = px(f32::from(span));
            let maximum = session.game.city_order_limit(nation, binding.order).maximum;
            nodes
                .get_mut(order.tick)
                .expect("bound industry amount-bar range must exist")
                .left = px(f32::from(geometry.span(maximum)));
        }
    }
}

/// Overlays a rail amount bar as native fill/range nodes over the static
/// recovered track. Returns `(bar, fill, tick)` for the owning dialog view.
pub(in crate::ui::city) fn bind_rail_amount_bar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    row: Entity,
    tree: &RetailTree,
) -> (Entity, Entity, Entity) {
    let bar = tree.find(row, fourcc!("bar "));
    let visual = bind_amount_bar_visual(commands, assets, bar);
    (bar, visual.fill, visual.tick)
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

/// Writes one rail dialog's counter and native amount bar from authoritative state.
pub(in crate::ui::city) fn render_rail(
    session: &GameSession,
    nation: MajorNationId,
    rail: &RailControls,
    order: CityOrderId,
    texts: &mut Query<&mut Text>,
    nodes: &mut Query<&mut Node>,
) {
    let city = &session.game.nations().major(nation).city;
    let quantity = session.game.city_order_quantity(nation, order);
    texts
        .get_mut(rail.quantity)
        .expect("bound rail counter text must exist")
        .0 = quantity.to_string();
    let capacity = rail_bar_capacity(city, order, nation, &session.game);
    let maximum = session.game.city_order_limit(nation, order).maximum;
    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
    let span = geometry.span(quantity);
    nodes
        .get_mut(rail.fill)
        .expect("bound rail amount bar must exist")
        .width = px(f32::from(span));
    nodes
        .get_mut(rail.tick)
        .expect("bound rail amount-bar range must exist")
        .left = px(f32::from(geometry.span(maximum)));
    let bar_node = nodes
        .get(rail.bar)
        .expect("bound rail amount bar must exist");
    let (Val::Px(bar_left), Val::Px(bar_top)) = (bar_node.left, bar_node.top) else {
        return;
    };
    let mut counter = nodes
        .get_mut(rail.quantity)
        .expect("bound rail counter must exist");
    counter.left = px(bar_left + f32::from(span) - 2.0);
    counter.top = px(bar_top + 6.0);
}

/// Attaches the recovered rail amount-bar click behavior, capturing the order
/// and quantization step.
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
