use super::*;
use crate::ui::retail_amount_bar::{
    AmountBarPixels, INDUSTRY_AMOUNT_BAR, INDUSTRY_BAR_FILL, industry_amount_bar_picture,
};
use crate::ui::retail_raster::IndexedRasterExt;

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
pub(in crate::ui::city) struct CityIndustryAmountBar {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityRailAmountBar {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) step: i16,
    pub(in crate::ui::city) quantity: Entity,
}

#[derive(Clone, Copy)]
struct IndustryOrderRow {
    order: CityOrderId,
    quantity: Entity,
    bar: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct IndustryDialogView {
    slot: CityFacilitySlot,
    capacity: Entity,
    capacity_template: String,
    labor: Entity,
    stocks: Vec<(Entity, ResourceKind, i16)>,
    expansion: Entity,
    rows: Vec<IndustryOrderRow>,
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
    let mut increase_commands = commands.entity(increase);
    increase_commands
        .insert(CityOrderAdjust {
            order: binding.order,
            delta: step,
            selection,
        })
        .observe(on_city_order_adjust);
    commands
        .entity(quantity)
        .insert((Text::new(""), CityOrderQuantity(binding.order)));
    CityOrderRow { row, quantity }
}

fn bind_industry_amount_bars(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    page: IndustryPage,
) -> Vec<IndustryOrderRow> {
    let mut rows = Vec::new();
    for binding in page.orders {
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
        rows.push(IndustryOrderRow {
            order: binding.order,
            quantity: bound.quantity,
            bar,
        });
    }
    rows
}

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
            (entity, resource, minimum)
        })
        .collect();
    let rows = bind_industry_amount_bars(commands, assets, root, tree, page);
    let expansion_action = tree.find(root, fourcc!("expa"));
    commands
        .entity(expansion_action)
        .insert(CityExpansionOpen { slot: page.slot })
        .observe(on_city_expansion_open);
    let expansion = tree.find(root, fourcc!("flag"));
    commands.entity(root).insert(IndustryDialogView {
        slot: page.slot,
        capacity,
        capacity_template,
        labor,
        stocks,
        expansion,
        rows,
    });
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

pub(in crate::ui::city) const fn recruitment_kind_matches(
    selected: CityOrderId,
    candidate: CityOrderId,
) -> bool {
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

pub(in crate::ui::city) fn sync_industry_dialog(
    session: Res<GameSession>,
    added: Query<(), Added<IndustryDialogView>>,
    views: Query<&IndustryDialogView>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
    mut nodes: Query<&mut Node>,
    bars: Query<&ImageNode>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    for view in &views {
        if let Ok(mut text) = texts.get_mut(view.capacity) {
            text.0 =
                format_retail_number(&view.capacity_template, city.production_orders[view.slot]);
        }
        set_visible(
            &mut visibilities,
            view.labor,
            city.population.strength() >= 2,
        );
        for &(entity, resource, minimum) in &view.stocks {
            set_visible(
                &mut visibilities,
                entity,
                city.stockpile[resource] < minimum,
            );
        }
        set_visible(
            &mut visibilities,
            view.expansion,
            city_is_expanding(city, view.slot),
        );
        let capacity = city.production_orders[view.slot];
        for row in &view.rows {
            let quantity = session.game.city_order_quantity(nation, row.order);
            if let Ok(mut text) = texts.get_mut(row.quantity) {
                text.0 = quantity.to_string();
            }
            let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
            if let Ok(mut node) = nodes.get_mut(row.quantity) {
                node.left = Val::Px(INDUSTRY_BAR_X + f32::from(geometry.span(quantity)) - 2.0);
                node.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
            }
            let maximum = session.game.city_order_limit(nation, row.order).maximum;
            let picture = industry_amount_bar_picture(AmountBarPixels {
                range: geometry.span(maximum),
                current: geometry.span(quantity),
                color: INDUSTRY_BAR_FILL,
            });
            if let Ok(image_node) = bars.get(row.bar)
                && let Some(mut image) = images.get_mut(&image_node.image)
            {
                *image = picture.to_keyed_image(retail.assets().default_dib_palette(), 0x10);
            }
        }
    }
}

fn set_visible(visibilities: &mut Query<&mut Visibility>, entity: Entity, visible: bool) {
    if let Ok(mut visibility) = visibilities.get_mut(entity) {
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

pub(in crate::ui::city) fn bind_rail_amount_bar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    row: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    step: i16,
    quantity: Entity,
) {
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
            CityRailAmountBar {
                order,
                step,
                quantity,
            },
        ))
        .observe(on_city_rail_amount_bar_click);
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

pub(in crate::ui::city) fn sync_rail_bars(
    session: Res<GameSession>,
    added: Query<(), Added<CityRailAmountBar>>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut nodes: Query<&mut Node>,
    bars: Query<(Entity, &CityRailAmountBar, &ImageNode)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    for (entity, bar, image_node) in &bars {
        let capacity = rail_bar_capacity(city, bar.order, nation, &session.game);
        let quantity = session.game.city_order_quantity(nation, bar.order);
        let maximum = session.game.city_order_limit(nation, bar.order).maximum;
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
        let picture = industry_amount_bar_picture(AmountBarPixels {
            range: geometry.span(maximum),
            current: geometry.span(quantity),
            color: INDUSTRY_BAR_FILL,
        });
        if let Some(mut image) = images.get_mut(&image_node.image) {
            *image = picture.to_keyed_image(retail.assets().default_dib_palette(), 0x10);
        }
        let Ok(bar_node) = nodes.get(entity) else {
            continue;
        };
        let (Val::Px(bar_left), Val::Px(bar_top)) = (bar_node.left, bar_node.top) else {
            continue;
        };
        let left = bar_left + f32::from(geometry.span(quantity)) - 2.0;
        let top = bar_top + 6.0;
        if let Ok(mut counter) = nodes.get_mut(bar.quantity) {
            counter.left = Val::Px(left);
            counter.top = Val::Px(top);
        }
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
