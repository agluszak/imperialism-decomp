use super::*;
use crate::ui::retail_amount_bar::{
    AmountBarPixels, INDUSTRY_AMOUNT_BAR, INDUSTRY_BAR_FILL, industry_amount_bar_picture,
};
use crate::ui::retail_raster::IndexedRasterExt;

pub(in crate::ui::city) const INDUSTRY_BAR_X: f32 = 62.0;
pub(in crate::ui::city) const INDUSTRY_BAR_Y: f32 = 8.0;

// TAmtBarCluster::DoPostCreate applies this to every `move` TNumberText before
// its derived city cluster positions it over the amount bar.
pub(in crate::ui::city) const AMOUNT_BAR_COUNTER_STYLE: RetailTextStylePreset =
    RetailTextStylePreset {
        font_family: 3,
        face_flags: 0,
        point_size: 10,
        alignment: -2,
    };

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
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct RailBarCounter {
    pub(in crate::ui::city) order: CityOrderId,
}

#[derive(Component)]
pub(in crate::ui::city) struct IndustryCapacity {
    slot: CityFacilitySlot,
    template: String,
}

#[derive(Component)]
pub(in crate::ui::city) enum IndustryIndicator {
    Labor,
    Stock {
        resource: ResourceKind,
        minimum: i16,
    },
    Expansion(CityFacilitySlot),
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct IndustryAmount {
    order: CityOrderId,
    slot: CityFacilitySlot,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) enum IndustryBar {
    Quantity(IndustryAmount),
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct IndustryBarVisual(IndustryAmount);

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
    commands
        .entity(quantity)
        .insert((Text::new(""), CityOrderQuantity(binding.order)));
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
) {
    let (counter_font, counter_layout, counter_line_height, _) = assets
        .text_style(AMOUNT_BAR_COUNTER_STYLE)
        .expect("retail industry amount counter style");
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
        let amount = IndustryAmount {
            order: binding.order,
            slot: page.slot,
        };
        commands.entity(bound.quantity).insert((
            IndustryBar::Quantity(amount),
            counter_font.clone(),
            counter_layout,
            counter_line_height,
        ));
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
                IndustryBarVisual(amount),
                RelativeCursorPosition::default(),
                CityIndustryAmountBar {
                    order: binding.order,
                    slot: page.slot,
                },
            ))
            .observe(on_city_amount_bar_click);
    }
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
    commands.entity(capacity).insert((
        Text::new(""),
        IndustryCapacity {
            slot: page.slot,
            template: capacity_template,
        },
    ));
    let labor = tree.find(root, fourcc!("labV"));
    commands
        .entity(labor)
        .insert((Text::new("X"), IndustryIndicator::Labor));
    for &(resource, tag, minimum) in page.stocks {
        let entity = tree.find(root, tag);
        commands.entity(entity).insert((
            Text::new("X"),
            IndustryIndicator::Stock { resource, minimum },
        ));
    }
    bind_industry_amount_bars(commands, assets, root, tree, page);
    let expansion_action = tree.find(root, fourcc!("expa"));
    commands
        .entity(expansion_action)
        .insert(CityExpansionOpen { slot: page.slot })
        .observe(on_city_expansion_open);
    let expansion = tree.find(root, fourcc!("flag"));
    commands
        .entity(expansion)
        .insert(IndustryIndicator::Expansion(page.slot));
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

pub(in crate::ui::city) fn sync_industry_texts(
    session: Res<GameSession>,
    added: Query<(), Added<IndustryCapacity>>,
    mut capacities: Query<(&IndustryCapacity, &mut Text)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    for (capacity, mut text) in &mut capacities {
        text.0 = format_retail_number(&capacity.template, city.production_orders[capacity.slot]);
    }
}

pub(in crate::ui::city) fn sync_industry_indicators(
    session: Res<GameSession>,
    added: Query<(), Added<IndustryIndicator>>,
    mut indicators: Query<(&IndustryIndicator, &mut Visibility)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    for (indicator, mut visibility) in &mut indicators {
        let visible = match *indicator {
            IndustryIndicator::Labor => city.population.strength() >= 2,
            IndustryIndicator::Stock { resource, minimum } => city.stockpile[resource] < minimum,
            IndustryIndicator::Expansion(slot) => city_is_expanding(city, slot),
        };
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
}

pub(in crate::ui::city) fn sync_industry_bars(
    session: Res<GameSession>,
    added: Query<(), Added<IndustryBar>>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut quantities: Query<(&IndustryBar, &mut Node)>,
    bars: Query<(&IndustryBarVisual, &ImageNode)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    for (bar, mut node) in &mut quantities {
        let IndustryBar::Quantity(amount) = *bar;
        let capacity = city.production_orders[amount.slot];
        let quantity = session.game.city_order_quantity(nation, amount.order);
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
        node.left = Val::Px(INDUSTRY_BAR_X + f32::from(geometry.span(quantity)) - 2.0);
        node.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
    }
    for (bar, image_node) in &bars {
        let amount = bar.0;
        let capacity = city.production_orders[amount.slot];
        let quantity = session.game.city_order_quantity(nation, amount.order);
        let maximum = session.game.city_order_limit(nation, amount.order).maximum;
        let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
        let picture = industry_amount_bar_picture(AmountBarPixels {
            range: geometry.span(maximum),
            current: geometry.span(quantity),
            color: INDUSTRY_BAR_FILL,
        });
        if let Some(mut image) = images.get_mut(&image_node.image) {
            *image = picture.to_keyed_image(retail.assets().default_dib_palette(), 0x10);
        }
    }
}

pub(in crate::ui::city) fn bind_rail_amount_bar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    row: Entity,
    tree: &RetailTree,
    order: CityOrderId,
    step: i16,
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
            CityRailAmountBar { order, step },
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
    mut counters: Query<(&RailBarCounter, &mut Node)>,
    bars: Query<(&CityRailAmountBar, &ImageNode, &Node), Without<RailBarCounter>>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    let mut positions = Vec::new();
    for (bar, image_node, node) in &bars {
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
        let (Val::Px(bar_left), Val::Px(bar_top)) = (node.left, node.top) else {
            continue;
        };
        positions.push((bar.order, bar_left, bar_top, geometry.span(quantity)));
    }
    for (counter, mut counter_node) in &mut counters {
        let Some((_, bar_left, bar_top, span)) = positions
            .iter()
            .copied()
            .find(|(order, _, _, _)| *order == counter.order)
        else {
            continue;
        };
        counter_node.left = Val::Px(bar_left + f32::from(span) - 2.0);
        counter_node.top = Val::Px(bar_top + 6.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn industry_amount_counter_uses_the_retail_post_create_style() {
        let style = resolve_retail_text_style(AMOUNT_BAR_COUNTER_STYLE).unwrap();
        assert_eq!(style.face, RetailFontFace::BookAntiquaRegular);
        assert_eq!(style.logical_pixel_height, 14);
        assert_eq!(style.alignment, RetailTextAlignment::Left);
    }

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
