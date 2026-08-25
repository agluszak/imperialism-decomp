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

#[derive(Component, Clone, Copy, Eq, PartialEq)]
pub(in crate::ui::city) struct CityRowChoice {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) selection: Entity,
}

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityOrderSelection(pub(in crate::ui::city) CityOrderId);

#[derive(Component, Clone, Copy)]
pub(in crate::ui::city) struct CityAmountBar {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) step: i16,
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct CityOrderRow {
    pub(in crate::ui::city) row: Entity,
    pub(in crate::ui::city) quantity: Entity,
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct IndustryOrderView {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) row: CityOrderRow,
    pub(in crate::ui::city) bar: Entity,
}

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct RailOrderView {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) quantity: Entity,
    pub(in crate::ui::city) bar: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct IndustryDialogView {
    slot: CityFacilitySlot,
    capacity: Entity,
    capacity_template: String,
    labor: Entity,
    stocks: Vec<(Entity, ResourceKind, i16)>,
    expansion: Entity,
    rows: Vec<IndustryOrderView>,
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

impl CityOrderRow {
    pub(in crate::ui::city) fn set_available(&self, commands: &mut Commands, available: bool) {
        commands.entity(self.row).insert(if available {
            Visibility::Visible
        } else {
            Visibility::Hidden
        });
    }
}

pub(in crate::ui::city) fn bind_industry_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    binding: CityOrderBinding,
    step: i16,
) -> CityOrderRow {
    bind_order_row_controls(
        commands,
        root,
        tree,
        binding,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        step,
        None,
    )
}

pub(in crate::ui::city) fn bind_recruitment_order_row(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    binding: CityOrderBinding,
    selection: Entity,
) -> CityOrderRow {
    bind_order_row_controls(
        commands,
        root,
        tree,
        binding,
        fourcc!("minu"),
        fourcc!("plus"),
        fourcc!("numb"),
        1,
        Some(selection),
    )
}

fn bind_order_row_controls(
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
    commands
        .entity(decrease)
        .insert(CityOrderAdjust {
            order: binding.order,
            delta: -step,
            selection,
        })
        .observe(on_city_order_adjust);
    commands
        .entity(increase)
        .insert(CityOrderAdjust {
            order: binding.order,
            delta: step,
            selection,
        })
        .observe(on_city_order_adjust);
    commands.entity(quantity).insert(Text::new(""));
    CityOrderRow { row, quantity }
}

fn bind_industry_amount_bars(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    page: IndustryPage,
) -> Vec<IndustryOrderView> {
    let mut rows = Vec::new();
    for binding in page.orders {
        let row = bind_industry_order_row(commands, root, tree, *binding, 1);
        let bar = tree.find(row.row, fourcc!("bar "));
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
                CityAmountBar {
                    order: binding.order,
                    step: 1,
                },
            ))
            .observe(on_city_amount_bar_click);
        rows.push(IndustryOrderView {
            order: binding.order,
            row,
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
    commands
        .entity(tree.find(root, fourcc!("name")))
        .insert(Text::new(building_name));
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
    commands
        .entity(tree.find(root, fourcc!("expa")))
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

pub(in crate::ui::city) fn bind_rail_order(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    building_name: String,
    binding: CityOrderBinding,
    step: i16,
) -> RailOrderView {
    commands
        .entity(tree.find(root, fourcc!("name")))
        .insert(Text::new(building_name));
    let row = bind_industry_order_row(commands, root, tree, binding, step);
    let bar = tree.find(row.row, fourcc!("bar "));
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
            CityAmountBar {
                order: binding.order,
                step,
            },
        ))
        .observe(on_city_amount_bar_click);
    RailOrderView {
        order: binding.order,
        quantity: row.quantity,
        bar,
    }
}

pub(in crate::ui::city) fn on_city_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<&CityRowChoice>,
    mut commands: Commands,
) {
    if !change.value {
        return;
    }
    let Ok(row) = rows.get(change.source) else {
        return;
    };
    commands
        .entity(row.selection)
        .insert(CityOrderSelection(row.order));
}

pub(in crate::ui::city) fn city_stock_color(short: bool, warning: Color, normal: Color) -> Color {
    if short { warning } else { normal }
}

pub(in crate::ui::city) fn sync_city_row_selection(
    mut commands: Commands,
    session: Res<GameSession>,
    selections: Query<(Entity, Ref<CityOrderSelection>)>,
    rows: Query<(Entity, &CityRowChoice, Has<Checked>)>,
) {
    if selections.is_empty() {
        return;
    }
    let selections_changed = selections
        .iter()
        .any(|(_, selection)| selection.is_changed() || selection.is_added());
    if !session.is_changed() && !selections_changed {
        return;
    }
    for (entity, row, checked) in &rows {
        let Ok((_, selection)) = selections.get(row.selection) else {
            continue;
        };
        let should_check = row.order == selection.0;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
}

pub(in crate::ui::city) fn set_bound_text(
    texts: &mut Query<&mut Text>,
    entity: Entity,
    value: impl Into<String>,
    what: &str,
) {
    texts.get_mut(entity).expect(what).0 = value.into();
}

pub(in crate::ui::city) fn set_bound_visible(
    visibilities: &mut Query<&mut Visibility>,
    entity: Entity,
    visible: bool,
    what: &str,
) {
    *visibilities.get_mut(entity).expect(what) = if visible {
        Visibility::Visible
    } else {
        Visibility::Hidden
    };
}

pub(in crate::ui::city) fn set_bound_text_color(
    colors: &mut Query<&mut TextColor>,
    entity: Entity,
    color: Color,
    what: &str,
) {
    colors.get_mut(entity).expect(what).0 = color;
}

pub(in crate::ui::city) fn project_city_order_rows(
    session: &GameSession,
    texts: &mut Query<&mut Text>,
    rows: &[(CityOrderId, CityOrderRow)],
    what: &str,
) {
    for &(order, row) in rows {
        project_order_quantity(session, texts, row, order, what);
    }
}

pub(in crate::ui::city) fn project_order_quantity(
    session: &GameSession,
    texts: &mut Query<&mut Text>,
    row: CityOrderRow,
    order: CityOrderId,
    what: &str,
) {
    let nation = session.active_major_nation();
    set_bound_text(
        texts,
        row.quantity,
        session.game.city_order_quantity(nation, order).to_string(),
        what,
    );
}

pub(in crate::ui::city) fn amount_bar_capacity(
    city: &CityState,
    order: CityOrderId,
    nation: MajorNationId,
    game: &GameState,
) -> i16 {
    match order {
        CityOrderId::Item(item) => city.production_orders[item.facility()],
        CityOrderId::FoodProcessing | CityOrderId::TransportCapacity => {
            let labor = city.population.production_labor();
            ((labor.high * 2 + labor.medium) * 2 + city.population.extra() + labor.low) / 2
        }
        _ => game.city_order_limit(nation, order).maximum,
    }
}

pub(in crate::ui::city) fn project_rail_order(
    session: &GameSession,
    retail: &RetailAssetsResource,
    images: &mut Assets<Image>,
    texts: &mut Query<&mut Text>,
    nodes: &mut Query<&mut Node>,
    pictures: &Query<&ImageNode>,
    rail: RailOrderView,
    what: &str,
) {
    let nation = session.active_major_nation();
    let city = &session.game.nations().major(nation).city;
    let quantity = session.game.city_order_quantity(nation, rail.order);
    set_bound_text(texts, rail.quantity, quantity.to_string(), what);
    let capacity = amount_bar_capacity(city, rail.order, nation, &session.game);
    let maximum = session.game.city_order_limit(nation, rail.order).maximum;
    let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
    let picture = industry_amount_bar_picture(AmountBarPixels {
        range: geometry.span(maximum),
        current: geometry.span(quantity),
        color: INDUSTRY_BAR_FILL,
    });
    let image_node = pictures.get(rail.bar).expect(what);
    images
        .get_mut(&image_node.image)
        .expect(what)
        .clone_from(&picture.to_keyed_image(retail.assets().default_dib_palette(), 0x10));
    let bar_node = nodes.get(rail.bar).expect(what);
    let (Val::Px(bar_left), Val::Px(bar_top)) = (bar_node.left, bar_node.top) else {
        panic!("{what} rail bar has pixel coordinates");
    };
    let left = bar_left + f32::from(geometry.span(quantity)) - 2.0;
    let top = bar_top + 6.0;
    let mut counter = nodes.get_mut(rail.quantity).expect(what);
    counter.left = Val::Px(left);
    counter.top = Val::Px(top);
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
        set_bound_text(
            &mut texts,
            view.capacity,
            format_retail_number(&view.capacity_template, city.production_orders[view.slot]),
            "industry capacity remains bound",
        );
        set_bound_visible(
            &mut visibilities,
            view.labor,
            city.population.strength() >= 2,
            "industry labor warning remains bound",
        );
        for &(entity, resource, minimum) in &view.stocks {
            set_bound_visible(
                &mut visibilities,
                entity,
                city.stockpile[resource] < minimum,
                "industry stock warning remains bound",
            );
        }
        set_bound_visible(
            &mut visibilities,
            view.expansion,
            city_is_expanding(city, view.slot),
            "industry expansion flag remains bound",
        );
        let capacity = city.production_orders[view.slot];
        for row in &view.rows {
            let quantity = session.game.city_order_quantity(nation, row.order);
            set_bound_text(
                &mut texts,
                row.row.quantity,
                quantity.to_string(),
                "industry order quantity remains bound",
            );
            let geometry = INDUSTRY_AMOUNT_BAR.with_segments(capacity);
            let mut node = nodes
                .get_mut(row.row.quantity)
                .expect("industry order quantity remains bound");
            node.left = Val::Px(INDUSTRY_BAR_X + f32::from(geometry.span(quantity)) - 2.0);
            node.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
            let maximum = session.game.city_order_limit(nation, row.order).maximum;
            let picture = industry_amount_bar_picture(AmountBarPixels {
                range: geometry.span(maximum),
                current: geometry.span(quantity),
                color: INDUSTRY_BAR_FILL,
            });
            let image_node = bars
                .get(row.bar)
                .expect("industry amount bar remains bound");
            images
                .get_mut(&image_node.image)
                .expect("industry amount bar image remains bound")
                .clone_from(&picture.to_keyed_image(retail.assets().default_dib_palette(), 0x10));
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
