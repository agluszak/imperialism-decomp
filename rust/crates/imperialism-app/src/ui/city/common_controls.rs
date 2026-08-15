use super::*;

pub(in crate::ui::city) const INDUSTRY_BAR_WIDTH: i16 = 150;
pub(in crate::ui::city) const INDUSTRY_BAR_X: f32 = 62.0;
pub(in crate::ui::city) const INDUSTRY_BAR_Y: f32 = 8.0;

#[derive(Component)]
pub(in crate::ui::city) struct CityOrderAdjust {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) delta: i16,
}

#[derive(Component)]
pub(in crate::ui::city) struct CityOrderQuantity(pub(in crate::ui::city) CityOrderId);

#[derive(Component, Clone, Copy, Eq, PartialEq)]
pub(in crate::ui::city) struct CityRowChoice(pub(in crate::ui::city) CityOrderId);

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
    Fill(IndustryAmount),
    Maximum(IndustryAmount),
    Quantity(IndustryAmount),
}

pub(in crate::ui::city) fn city_building_name(
    assets: &RetailUiAssets,
    slot: CityFacilitySlot,
) -> String {
    city_string(assets, CITY_BUILDING_STRING_GROUP, slot as i16)
}

pub(in crate::ui::city) fn configure_industry_dialog(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    page: IndustryPage,
) {
    let building_name = city_building_name(assets, page.slot);
    let capacity_template = city_string(assets, CITY_TEXT_STRING_GROUP, 0x10);
    let bar_color = assets.palette_color(0x16);
    bind_industry_dialog(
        commands,
        root,
        children,
        tags,
        page,
        building_name,
        capacity_template,
        bar_color,
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    binding: CityOrderBinding,
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
) -> CityOrderRow {
    let row = find_descendant(root, binding.tag, children, tags);
    let decrease = find_descendant(row, decrease_tag, children, tags);
    let increase = find_descendant(row, increase_tag, children, tags);
    let quantity = find_descendant(row, quantity_tag, children, tags);
    commands.entity(decrease).insert(CityOrderAdjust {
        order: binding.order,
        delta: -step,
    });
    commands.entity(increase).insert(CityOrderAdjust {
        order: binding.order,
        delta: step,
    });
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
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    page: IndustryPage,
    bar_color: Color,
) {
    for binding in page.orders {
        let bound = bind_city_order_row(
            commands,
            root,
            children,
            tags,
            *binding,
            fourcc!("left"),
            fourcc!("rght"),
            fourcc!("move"),
            1,
        );
        let amount = IndustryAmount {
            order: binding.order,
            slot: page.slot,
        };
        commands
            .entity(bound.quantity)
            .insert(IndustryBar::Quantity(amount));
        let bar = find_descendant(bound.row, fourcc!("bar "), children, tags);
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(0.0),
                top: Val::Px(1.0),
                width: Val::Px(0.0),
                height: Val::Px(4.0),
                ..default()
            },
            BackgroundColor(bar_color),
            Pickable::IGNORE,
            ChildOf(bar),
            IndustryBar::Fill(amount),
            Name::new("city-industry-amount"),
        ));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(0.0),
                top: Val::Px(0.0),
                width: Val::Px(1.0),
                height: Val::Px(5.0),
                ..default()
            },
            BackgroundColor(Color::BLACK),
            Pickable::IGNORE,
            ChildOf(bar),
            IndustryBar::Maximum(amount),
            Name::new("city-industry-maximum"),
        ));
        commands.entity(bar).insert((
            RelativeCursorPosition::default(),
            CityIndustryAmountBar {
                order: binding.order,
                slot: page.slot,
            },
        ));
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_industry_dialog(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    page: IndustryPage,
    building_name: String,
    capacity_template: String,
    bar_color: Color,
) {
    bind_city_dialog_root(commands, root, children, tags, page.slot);

    let name = find_descendant(root, fourcc!("name"), children, tags);
    commands.entity(name).insert(Text::new(building_name));
    let capacity = find_descendant(root, fourcc!("capT"), children, tags);
    commands.entity(capacity).insert((
        Text::new(""),
        IndustryCapacity {
            slot: page.slot,
            template: capacity_template,
        },
    ));
    let labor = find_descendant(root, fourcc!("labV"), children, tags);
    commands
        .entity(labor)
        .insert((Text::new("X"), IndustryIndicator::Labor));
    for &(resource, tag, minimum) in page.stocks {
        let entity = find_descendant(root, tag, children, tags);
        commands.entity(entity).insert((
            Text::new("X"),
            IndustryIndicator::Stock { resource, minimum },
        ));
    }
    bind_industry_amount_bars(commands, root, children, tags, page, bar_color);
    let expansion_action = find_descendant(root, fourcc!("expa"), children, tags);
    commands
        .entity(expansion_action)
        .insert(CityExpansionOpen { slot: page.slot });
    let expansion = find_descendant(root, fourcc!("flag"), children, tags);
    commands
        .entity(expansion)
        .insert(IndustryIndicator::Expansion(page.slot));
}

pub(in crate::ui::city) fn on_city_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<&CityRowChoice>,
    parents: Query<&ChildOf>,
    mut views: Query<&mut CityRowSelection>,
) {
    if !change.value {
        return;
    }
    let Ok(row) = rows.get(change.source) else {
        return;
    };
    let Some(mut selection) = city_row_selection_mut(change.source, &parents, &mut views) else {
        return;
    };
    if recruitment_kind_matches(selection.order, row.0) {
        selection.order = row.0;
    }
}

pub(in crate::ui::city) fn on_city_recruitment_order_selected(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    parents: Query<&ChildOf>,
    mut views: Query<&mut CityRowSelection>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let Some(mut selection) = city_row_selection_mut(activate.entity, &parents, &mut views) else {
        return;
    };
    if recruitment_kind_matches(selection.order, action.order) {
        selection.order = action.order;
    }
}

fn city_row_selection_mut<'w>(
    mut entity: Entity,
    parents: &Query<&ChildOf>,
    views: &'w mut Query<&mut CityRowSelection>,
) -> Option<Mut<'w, CityRowSelection>> {
    loop {
        if views.contains(entity) {
            return views.get_mut(entity).ok();
        }
        entity = parents.get(entity).ok()?.parent();
    }
}

fn ancestor_city_row_selection(
    mut entity: Entity,
    parents: &Query<&ChildOf>,
    selections: &Query<(Entity, Ref<CityRowSelection>)>,
) -> Option<Entity> {
    loop {
        if selections.contains(entity) {
            return Some(entity);
        }
        entity = parents.get(entity).ok()?.parent();
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
    parents: Query<&ChildOf>,
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
        let Some(root) = ancestor_city_row_selection(entity, &parents, &selections) else {
            continue;
        };
        let Ok((_, selection)) = selections.get(root) else {
            continue;
        };
        let should_check = row.0 == selection.order;
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
    let nation = city_active_nation(&session);
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
    let nation = city_active_nation(&session);
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
    let nation = city_active_nation(&session);
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
    mut bars: Query<(&IndustryBar, &mut Node)>,
) {
    if city_projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = city_active_nation(&session);
    let city = &session.game.nations().major(nation).city;
    let scale = |value: i16, capacity: i16| {
        if capacity > 0 {
            (i32::from(value) * i32::from(INDUSTRY_BAR_WIDTH) / i32::from(capacity))
                .clamp(0, i32::from(INDUSTRY_BAR_WIDTH)) as i16
        } else {
            0
        }
    };
    for (bar, mut node) in &mut bars {
        match *bar {
            IndustryBar::Fill(amount) => {
                let capacity = city.production_orders[amount.slot];
                let quantity = session.game.city_order_quantity(nation, amount.order);
                node.width = Val::Px(f32::from(scale(quantity, capacity)));
            }
            IndustryBar::Maximum(amount) => {
                let capacity = city.production_orders[amount.slot];
                let maximum = session.game.city_order_limit(nation, amount.order).maximum;
                node.left = Val::Px(f32::from(scale(maximum, capacity)));
            }
            IndustryBar::Quantity(amount) => {
                let capacity = city.production_orders[amount.slot];
                let quantity = session.game.city_order_quantity(nation, amount.order);
                node.left = Val::Px(INDUSTRY_BAR_X + f32::from(scale(quantity, capacity)) - 2.0);
                node.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specialized_city_buildings_use_the_one_based_retail_name_indexes() {
        assert_eq!(city_string_index(CityFacilitySlot::OilRefinery as i16), 7);
        assert_eq!(city_string_index(CityFacilitySlot::Shipyard as i16), 8);
        assert_eq!(city_string_index(CityFacilitySlot::Armory as i16), 9);
    }
}
