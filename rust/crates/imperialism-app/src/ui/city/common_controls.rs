use super::*;

pub(in crate::ui::city) const INDUSTRY_BAR_WIDTH: i16 = 150;
pub(in crate::ui::city) const INDUSTRY_BAR_X: f32 = 62.0;
pub(in crate::ui::city) const INDUSTRY_BAR_Y: f32 = 8.0;

#[derive(Clone, Copy)]
pub(in crate::ui::city) struct CityOrderControl {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) quantity: Entity,
}

struct IndustryStockControl {
    resource: ResourceKind,
    minimum: i16,
    entity: Entity,
}

struct IndustryAmountBarControl {
    order: CityOrderId,
    quantity: Entity,
    fill: Entity,
    maximum: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct IndustryDialogControls {
    capacity: Entity,
    capacity_template: String,
    labor: Entity,
    stocks: Vec<IndustryStockControl>,
    orders: Vec<CityOrderControl>,
    amount_bars: Vec<IndustryAmountBarControl>,
    expansion_indicator: Entity,
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_city_order_controls(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    root: Entity,
    nation: MajorNationId,
    bindings: &[CityOrderBinding],
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
) -> Vec<CityOrderControl> {
    let mut controls = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let left = spawned.under(catalog, binding.tag, decrease_tag);
        let right = spawned.under(catalog, binding.tag, increase_tag);
        let quantity = spawned.under(catalog, binding.tag, quantity_tag);
        commands.entity(left).insert(CityOrderAdjust {
            dialog: root,
            nation,
            order: binding.order,
            delta: -step,
        });
        commands.entity(right).insert(CityOrderAdjust {
            dialog: root,
            nation,
            order: binding.order,
            delta: step,
        });
        commands.entity(quantity).insert(Text::new(""));
        controls.push(CityOrderControl {
            order: binding.order,
            quantity,
        });
    }
    controls
}

fn bind_industry_amount_bars(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    root: Entity,
    nation: MajorNationId,
    page: IndustryPage,
    bar_color: Color,
) -> Vec<IndustryAmountBarControl> {
    let mut controls = Vec::with_capacity(page.orders.len());
    for binding in page.orders {
        let bar = spawned.under(catalog, binding.tag, fourcc!("bar "));
        let quantity = spawned.under(catalog, binding.tag, fourcc!("move"));
        let fill = commands
            .spawn((
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
                Name::new("city-industry-amount"),
            ))
            .id();
        let maximum = commands
            .spawn((
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
                Name::new("city-industry-maximum"),
            ))
            .id();
        commands.entity(bar).insert((
            RelativeCursorPosition::default(),
            CityIndustryAmountBar {
                dialog: root,
                nation,
                order: binding.order,
                slot: page.slot,
            },
        ));
        controls.push(IndustryAmountBarControl {
            order: binding.order,
            quantity,
            fill,
            maximum,
        });
    }
    controls
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_industry_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    nation: MajorNationId,
    page: IndustryPage,
    building_name: String,
    capacity_template: String,
    bar_color: Color,
) {
    let root = bind_city_dialog_root(commands, spawned, nation, page.slot);

    let name = spawned.unique(fourcc!("name"));
    commands.entity(name).insert(Text::new(building_name));
    let capacity = spawned.unique(fourcc!("capT"));
    commands.entity(capacity).insert(Text::new(""));
    let labor = spawned.unique(fourcc!("labV"));
    commands.entity(labor).insert(Text::new("X"));
    let mut stocks = Vec::with_capacity(page.stocks.len());
    for &(resource, tag, minimum) in page.stocks {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new("X"));
        stocks.push(IndustryStockControl {
            resource,
            minimum,
            entity,
        });
    }
    let orders = bind_city_order_controls(
        commands,
        catalog,
        spawned,
        root,
        nation,
        page.orders,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        1,
    );
    let amount_bars =
        bind_industry_amount_bars(commands, catalog, spawned, root, nation, page, bar_color);
    let expansion = spawned.unique(fourcc!("expa"));
    commands.entity(expansion).insert(CityExpansionOpen {
        dialog: root,
        nation,
        slot: page.slot,
    });
    let expansion_indicator = spawned.unique(fourcc!("flag"));
    commands.entity(root).insert(IndustryDialogControls {
        capacity,
        capacity_template,
        labor,
        stocks,
        orders,
        amount_bars,
        expansion_indicator,
    });
}

pub(in crate::ui::city) fn sync_industry_dialog(
    session: Res<GameSession>,
    dialogs: Query<(Ref<CityBuildingDialog>, &IndustryDialogControls)>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
    mut nodes: Query<&mut Node>,
) {
    for (dialog, controls) in &dialogs {
        if !session.is_changed() && !dialog.is_added() {
            continue;
        }
        let major = session.0.nations().major(dialog.nation);
        let city = &major.city;

        let capacity = format_retail_number(
            &controls.capacity_template,
            city.production_orders[dialog.slot],
        );
        texts
            .get_mut(controls.capacity)
            .expect("industry capacity control belongs to its dialog")
            .0 = capacity;
        *visibilities
            .get_mut(controls.labor)
            .expect("industry labor indicator belongs to its dialog") =
            if city.population.strength() >= 2 {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        for stock in &controls.stocks {
            *visibilities
                .get_mut(stock.entity)
                .expect("industry stock indicator belongs to its dialog") =
                if city.stockpile[stock.resource] < stock.minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
        }
        for order in &controls.orders {
            let status = session.0.city_order_status(dialog.nation, order.order);
            texts
                .get_mut(order.quantity)
                .expect("industry order quantity belongs to its dialog")
                .0 = status.quantity.to_string();
        }
        for bar in &controls.amount_bars {
            let status = session.0.city_order_status(dialog.nation, bar.order);
            let capacity = city.production_orders[dialog.slot];
            let scale = |quantity: i16| {
                if capacity > 0 {
                    (i32::from(quantity) * i32::from(INDUSTRY_BAR_WIDTH) / i32::from(capacity))
                        .clamp(0, i32::from(INDUSTRY_BAR_WIDTH)) as i16
                } else {
                    0
                }
            };
            let current = scale(status.quantity);
            let maximum = scale(status.maximum);
            nodes
                .get_mut(bar.fill)
                .expect("industry amount fill belongs to its dialog")
                .width = Val::Px(f32::from(current));
            nodes
                .get_mut(bar.maximum)
                .expect("industry amount maximum belongs to its dialog")
                .left = Val::Px(f32::from(maximum));
            let mut quantity = nodes
                .get_mut(bar.quantity)
                .expect("industry amount quantity belongs to its dialog");
            quantity.left = Val::Px(INDUSTRY_BAR_X + f32::from(current) - 2.0);
            quantity.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
        }
        *visibilities
            .get_mut(controls.expansion_indicator)
            .expect("industry expansion indicator belongs to its dialog") =
            if city_is_expanding(city, dialog.slot) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
    }
}
