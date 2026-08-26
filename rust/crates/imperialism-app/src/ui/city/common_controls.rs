use super::*;
use crate::ui::retail_amount_bar::INDUSTRY_AMOUNT_BAR;
use crate::ui::retail_amount_bar::INDUSTRY_BAR_FILL;

pub(in crate::ui::city) const INDUSTRY_BAR_X: f32 = 62.0;
pub(in crate::ui::city) const INDUSTRY_BAR_Y: f32 = 8.0;

#[derive(Component)]
pub(in crate::ui::city) struct CityOrderAdjust {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) delta: i16,
    pub(in crate::ui::city) selection: Option<Entity>,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityOrderQuantity(pub(in crate::ui::city) CityOrderId);

#[derive(Component, Clone, Copy, Eq, PartialEq)]
pub(in crate::ui::city) struct CityRowChoice {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) selection: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityRowSelection {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) normal_color: Color,
    pub(in crate::ui::city) warning_color: Color,
}

#[derive(Component)]
pub(in crate::ui::city) struct RailView {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) step: i16,
    pub(in crate::ui::city) quantity: Entity,
    pub(in crate::ui::city) bar: Entity,
    pub(in crate::ui::city) fill: Entity,
    pub(in crate::ui::city) tick: Entity,
}

/// One industry-dialog order row: the quantity marker over the amount bar.
#[derive(Clone, Copy)]
pub(in crate::ui::city) struct IndustryOrderView {
    quantity: Entity,
    pub(in crate::ui::city) bar: Entity,
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
    pub(in crate::ui::city) decrease: Entity,
    pub(in crate::ui::city) increase: Entity,
    pub(in crate::ui::city) quantity: Entity,
}

impl CityOrderRow {
    pub(in crate::ui::city) fn set_available(&self, commands: &mut Commands, available: bool) {
        let visibility = if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        commands.entity(self.row).insert(visibility);
        for control in [self.decrease, self.increase] {
            if available {
                commands.entity(control).remove::<InteractionDisabled>();
            } else {
                commands.entity(control).insert(InteractionDisabled);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_city_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    binding: CityOrderBinding,
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
    selection: Option<Entity>,
    record_quantity: bool,
) -> CityOrderRow {
    let row = tree.find(root, binding.tag);
    let decrease = tree.find(row, decrease_tag);
    let increase = tree.find(row, increase_tag);
    let quantity = tree.find(row, quantity_tag);
    let mut decrease_commands = commands.entity(decrease);
    decrease_commands
        .insert(CityOrderAdjust {
            order: binding.order,
            delta: -step,
            selection,
        })
        .observe(on_city_order_adjust);
    if selection.is_some() {
        decrease_commands.observe(on_city_recruitment_order_selected);
    }
    let mut increase_commands = commands.entity(increase);
    increase_commands
        .insert(CityOrderAdjust {
            order: binding.order,
            delta: step,
            selection,
        })
        .observe(on_city_order_adjust);
    if selection.is_some() {
        increase_commands.observe(on_city_recruitment_order_selected);
    }
    if record_quantity {
        commands
            .entity(quantity)
            .insert((Text::new(""), CityOrderQuantity(binding.order)));
    }
    CityOrderRow {
        row,
        decrease,
        increase,
        quantity,
    }
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
            let bound = bind_city_order_row(
                commands,
                root,
                tree,
                *binding,
                fourcc!("left"),
                fourcc!("rght"),
                fourcc!("move"),
                1,
                None,
                false,
            );
            let bar = tree.find(bound.row, fourcc!("bar "));
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
                        ChildOf(bar),
                    ))
                    .id()
            };
            let fill_color = assets.palette_color(INDUSTRY_BAR_FILL);
            let tick_color = assets.palette_color(0);
            let fill = spawn_child(0.0, 1.0, 0.0, 4.0, fill_color);
            let tick = spawn_child(0.0, 0.0, 1.0, 5.0, tick_color);
            commands.entity(bar).observe(on_city_amount_bar_click);
            IndustryOrderView {
                quantity: bound.quantity,
                bar,
                fill,
                tick,
            }
        })
        .collect()
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

pub(in crate::ui::city) fn on_city_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<&CityRowChoice>,
    mut views: Query<&mut CityRowSelection>,
) {
    if !change.value {
        return;
    }
    let Ok(row) = rows.get(change.source) else {
        return;
    };
    let Ok(mut selection) = views.get_mut(row.selection) else {
        return;
    };
    if recruitment_kind_matches(selection.order, row.order) {
        selection.order = row.order;
    }
}

pub(in crate::ui::city) fn on_city_recruitment_order_selected(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    mut views: Query<&mut CityRowSelection>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let Some(selection_entity) = action.selection else {
        return;
    };
    let Ok(mut selection) = views.get_mut(selection_entity) else {
        return;
    };
    if recruitment_kind_matches(selection.order, action.order) {
        selection.order = action.order;
    }
}

const fn recruitment_kind_matches(selected: CityOrderId, candidate: CityOrderId) -> bool {
    matches!(
        (selected, candidate),
        (
            CityOrderId::MilitaryRecruit(_),
            CityOrderId::MilitaryRecruit(_)
        ) | (
            CityOrderId::CivilianRecruit(_),
            CityOrderId::CivilianRecruit(_)
        ) | (CityOrderId::Ship(_), CityOrderId::Ship(_))
    )
}

pub(in crate::ui::city) fn city_stock_color(short: bool, selection: &CityRowSelection) -> Color {
    if short {
        selection.warning_color
    } else {
        selection.normal_color
    }
}

pub(in crate::ui::city) fn sync_city_row_selection(
    mut commands: Commands,
    session: Res<GameSession>,
    selections: Query<(Entity, Ref<CityRowSelection>)>,
    rows: Query<(Entity, &CityRowChoice, Has<Checked>)>,
) {
    if selections.is_empty() {
        return;
    }
    if !session.is_changed()
        && selections
            .iter()
            .all(|(_, selection)| !selection.is_changed() && !selection.is_added())
    {
        return;
    }
    for (entity, row, checked) in &rows {
        let Ok((_, selection)) = selections.get(row.selection) else {
            continue;
        };
        let should_check = row.order == selection.order;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
}

pub(in crate::ui::city) fn sync_city_order_quantities(
    session: Res<GameSession>,
    added: Query<(), Added<CityOrderQuantity>>,
    mut quantities: Query<(&CityOrderQuantity, &mut Text)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    for (CityOrderQuantity(order), mut text) in &mut quantities {
        text.0 = session.game.city_order_quantity(nation, *order).to_string();
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
                ChildOf(bar),
            ))
            .id()
    };
    let fill = spawn_child(0.0, 1.0, 0.0, 4.0, assets.palette_color(INDUSTRY_BAR_FILL));
    let tick = spawn_child(0.0, 0.0, 1.0, 5.0, assets.palette_color(0));
    commands.entity(bar).observe(on_city_rail_amount_bar_click);
    (bar, fill, tick)
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

pub(in crate::ui::city) fn render_rail_dialogs(
    session: Res<GameSession>,
    views: Query<Ref<RailView>>,
    mut nodes: Query<&mut Node>,
    mut texts: Query<&mut Text>,
) {
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    for view in &views {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let quantity = session.game.city_order_quantity(nation, view.order);
        texts
            .get_mut(view.quantity)
            .expect("bound rail counter text must exist")
            .0 = quantity.to_string();
        let capacity = rail_bar_capacity(city, view.order, nation, &session.game);
        let maximum = session.game.city_order_limit(nation, view.order).maximum;
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
        let span = geometry.span(quantity);
        nodes
            .get_mut(view.fill)
            .expect("bound rail amount bar must exist")
            .width = px(f32::from(span));
        nodes
            .get_mut(view.tick)
            .expect("bound rail amount-bar range must exist")
            .left = px(f32::from(geometry.span(maximum)));
        let bar_node = nodes
            .get(view.bar)
            .expect("bound rail amount bar must exist");
        let (Val::Px(bar_left), Val::Px(bar_top)) = (bar_node.left, bar_node.top) else {
            continue;
        };
        let mut counter = nodes
            .get_mut(view.quantity)
            .expect("bound rail counter must exist");
        counter.left = px(bar_left + f32::from(span) - 2.0);
        counter.top = px(bar_top + 6.0);
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
