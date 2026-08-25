use super::*;
use crate::ui::retail_amount_bar::{
    AmountBarPixels, INDUSTRY_AMOUNT_BAR, INDUSTRY_BAR_FILL, industry_amount_bar_picture,
};
use crate::ui::retail_raster::IndexedRasterExt;

pub(in crate::ui::city) const INDUSTRY_BAR_X: f32 = 62.0;
pub(in crate::ui::city) const INDUSTRY_BAR_Y: f32 = 8.0;

pub(in crate::ui::city) fn set_text(
    texts: &mut Query<&mut Text>,
    entity: Entity,
    value: impl Into<String>,
) {
    texts.get_mut(entity).expect("bound city UI text").0 = value.into();
}

pub(in crate::ui::city) fn set_visible(
    visibilities: &mut Query<&mut Visibility>,
    entity: Entity,
    visible: bool,
) {
    *visibilities
        .get_mut(entity)
        .expect("bound city UI visibility") = if visible {
        Visibility::Visible
    } else {
        Visibility::Hidden
    };
}

pub(in crate::ui::city) fn set_colored_text(
    texts: &mut Query<&mut Text>,
    colors: &mut Query<&mut TextColor>,
    entity: Entity,
    value: impl Into<String>,
    color: Color,
) {
    set_text(texts, entity, value);
    colors.get_mut(entity).expect("bound city UI text color").0 = color;
}

#[derive(Component)]
pub(in crate::ui::city) struct CityOrderAdjust {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) delta: i16,
    pub(in crate::ui::city) selection: Option<Entity>,
}

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
pub(in crate::ui::city) struct CityIndustryAmountBar {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityRailAmountBar {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) step: i16,
}

pub(in crate::ui::city) struct IndustryStockUi {
    pub(in crate::ui::city) resource: ResourceKind,
    pub(in crate::ui::city) minimum: i16,
    pub(in crate::ui::city) entity: Entity,
}

pub(in crate::ui::city) struct IndustryOrderUi {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) quantity: Entity,
    pub(in crate::ui::city) bar: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct IndustryDialogUi {
    pub(in crate::ui::city) slot: CityFacilitySlot,
    pub(in crate::ui::city) capacity: Entity,
    pub(in crate::ui::city) capacity_template: String,
    pub(in crate::ui::city) labor: Entity,
    pub(in crate::ui::city) stocks: Vec<IndustryStockUi>,
    pub(in crate::ui::city) orders: Vec<IndustryOrderUi>,
    pub(in crate::ui::city) expansion: Entity,
}

pub(in crate::ui::city) struct RailOrderUi {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) quantity: Entity,
    pub(in crate::ui::city) bar: Entity,
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
    let capacity_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x10);
    bind_industry_dialog(
        commands,
        assets,
        root,
        tree,
        page,
        building_name,
        capacity_template,
    );
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
    commands.entity(quantity).insert(Text::new(""));
    CityOrderRow {
        row,
        decrease,
        increase,
        quantity,
    }
}

fn bind_industry_amount_bars(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    page: IndustryPage,
) -> Vec<IndustryOrderUi> {
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
            );
            let bar = tree.find(bound.row, fourcc!("bar "));
            let picture = industry_amount_bar_picture(AmountBarPixels {
                range: 0,
                current: 0,
                color: INDUSTRY_BAR_FILL,
            });
            let palette = *assets.default_dib_palette();
            let image = assets.add_image(picture.to_keyed_image(&palette, 0x10));
            commands
                .entity(bar)
                .insert((
                    ImageNode::new(image),
                    RelativeCursorPosition::default(),
                    CityIndustryAmountBar {
                        order: binding.order,
                        slot: page.slot,
                    },
                ))
                .observe(on_city_amount_bar_click);
            IndustryOrderUi {
                order: binding.order,
                quantity: bound.quantity,
                bar,
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
    capacity_template: String,
) {
    let name = tree.find(root, fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    let capacity = tree.find(root, fourcc!("capT"));
    commands.entity(capacity).insert(Text::new(""));
    let labor = tree.find(root, fourcc!("labV"));
    commands.entity(labor).insert(Text::new("X"));
    let stocks = page
        .stocks
        .iter()
        .map(|&(resource, tag, minimum)| {
            let entity = tree.find(root, tag);
            commands.entity(entity).insert(Text::new("X"));
            IndustryStockUi {
                resource,
                minimum,
                entity,
            }
        })
        .collect();
    let orders = bind_industry_amount_bars(commands, assets, root, tree, page);
    let expansion_action = tree.find(root, fourcc!("expa"));
    commands
        .entity(expansion_action)
        .insert(CityExpansionOpen { slot: page.slot })
        .observe(on_city_expansion_open);
    let expansion = tree.find(root, fourcc!("flag"));
    commands.entity(root).insert(IndustryDialogUi {
        slot: page.slot,
        capacity,
        capacity_template,
        labor,
        stocks,
        orders,
        expansion,
    });
}

pub(in crate::ui::city) fn on_city_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<&CityRowChoice>,
    mut views: Query<&mut CityRowSelection>,
    roots: Query<Entity, With<CityScreenRoot>>,
    mut commands: Commands,
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
        mark_city_ui_dirty(&mut commands, &roots);
    }
}

pub(in crate::ui::city) fn on_city_recruitment_order_selected(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    mut views: Query<&mut CityRowSelection>,
    roots: Query<Entity, With<CityScreenRoot>>,
    mut commands: Commands,
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
        mark_city_ui_dirty(&mut commands, &roots);
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

pub(in crate::ui::city) fn refresh_city_row_selection(
    commands: &mut Commands,
    selections: &Query<&CityRowSelection>,
    rows: &Query<(Entity, &CityRowChoice, Has<Checked>)>,
) {
    for (entity, row, checked) in rows {
        let Ok(selection) = selections.get(row.selection) else {
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

pub(in crate::ui::city) fn refresh_industry_dialog(
    game: &GameState,
    nation: MajorNationId,
    ui: &IndustryDialogUi,
    texts: &mut Query<&mut Text>,
    visibilities: &mut Query<&mut Visibility>,
    nodes: &mut Query<&mut Node>,
    images: &mut Query<&mut ImageNode>,
    assets: &mut RetailUiAssets,
) {
    let city = &game.nations().major(nation).city;
    set_text(
        texts,
        ui.capacity,
        format_retail_number(&ui.capacity_template, city.production_orders[ui.slot]),
    );
    set_visible(visibilities, ui.labor, city.population.strength() >= 2);
    for stock in &ui.stocks {
        set_visible(
            visibilities,
            stock.entity,
            city.stockpile[stock.resource] < stock.minimum,
        );
    }
    set_visible(visibilities, ui.expansion, city_is_expanding(city, ui.slot));
    for order in &ui.orders {
        refresh_industry_order(game, nation, ui.slot, order, texts, nodes, images, assets);
    }
}

fn refresh_industry_order(
    game: &GameState,
    nation: MajorNationId,
    slot: CityFacilitySlot,
    order: &IndustryOrderUi,
    texts: &mut Query<&mut Text>,
    nodes: &mut Query<&mut Node>,
    images: &mut Query<&mut ImageNode>,
    assets: &mut RetailUiAssets,
) {
    let city = &game.nations().major(nation).city;
    let capacity = city.production_orders[slot];
    let quantity = game.city_order_quantity(nation, order.order);
    let maximum = game.city_order_limit(nation, order.order).maximum;
    set_text(texts, order.quantity, quantity.to_string());
    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
    let mut node = nodes
        .get_mut(order.quantity)
        .expect("bound industry quantity");
    node.left = Val::Px(INDUSTRY_BAR_X + f32::from(geometry.span(quantity)) - 2.0);
    node.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
    let picture = industry_amount_bar_picture(AmountBarPixels {
        range: geometry.span(maximum),
        current: geometry.span(quantity),
        color: INDUSTRY_BAR_FILL,
    });
    let handle = images
        .get(order.bar)
        .expect("bound industry bar")
        .image
        .clone();
    assets.replace_image(
        &handle,
        picture.to_keyed_image(assets.default_dib_palette(), 0x10),
    );
}

pub(in crate::ui::city) fn bind_rail_amount_bar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    row: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    step: i16,
) -> Entity {
    let bar = tree.find(row, fourcc!("bar "));
    let picture = industry_amount_bar_picture(AmountBarPixels {
        range: 0,
        current: 0,
        color: INDUSTRY_BAR_FILL,
    });
    let palette = *assets.default_dib_palette();
    let image = assets.add_image(picture.to_keyed_image(&palette, 0x10));
    commands
        .entity(bar)
        .insert((
            ImageNode::new(image),
            RelativeCursorPosition::default(),
            CityRailAmountBar { order, step },
        ))
        .observe(on_city_rail_amount_bar_click);
    bar
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

pub(in crate::ui::city) fn refresh_rail_order(
    game: &GameState,
    nation: MajorNationId,
    ui: &RailOrderUi,
    texts: &mut Query<&mut Text>,
    nodes: &mut Query<&mut Node>,
    images: &mut Query<&mut ImageNode>,
    assets: &mut RetailUiAssets,
) {
    let city = &game.nations().major(nation).city;
    let capacity = rail_bar_capacity(city, ui.order, nation, game);
    let quantity = game.city_order_quantity(nation, ui.order);
    let maximum = game.city_order_limit(nation, ui.order).maximum;
    set_text(texts, ui.quantity, quantity.to_string());
    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
    let picture = industry_amount_bar_picture(AmountBarPixels {
        range: geometry.span(maximum),
        current: geometry.span(quantity),
        color: INDUSTRY_BAR_FILL,
    });
    let handle = images.get(ui.bar).expect("bound rail bar").image.clone();
    assets.replace_image(
        &handle,
        picture.to_keyed_image(assets.default_dib_palette(), 0x10),
    );
    let (bar_left, bar_top) = {
        let bar_node = nodes.get(ui.bar).expect("bound rail bar node");
        let (Val::Px(bar_left), Val::Px(bar_top)) = (bar_node.left, bar_node.top) else {
            return;
        };
        (bar_left, bar_top)
    };
    let mut quantity_node = nodes.get_mut(ui.quantity).expect("bound rail quantity");
    quantity_node.left = Val::Px(bar_left + f32::from(geometry.span(quantity)) - 2.0);
    quantity_node.top = Val::Px(bar_top + 6.0);
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
