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
pub(in crate::ui::city) struct CityIndustryAmountBar {
    pub(in crate::ui::city) order: CityOrderId,
    pub(in crate::ui::city) slot: CityFacilitySlot,
}

struct IndustryAmountBarControl {
    order: CityOrderId,
    quantity: Entity,
    fill: Entity,
    maximum: Entity,
}

struct IndustryStockControl {
    resource: ResourceKind,
    minimum: i16,
    entity: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct IndustryView {
    slot: CityFacilitySlot,
    capacity_template: String,
    capacity: Entity,
    labor: Entity,
    stocks: Vec<IndustryStockControl>,
    amount_bars: Vec<IndustryAmountBarControl>,
    expansion: Entity,
}

pub(in crate::ui::city) fn city_building_name(ui: &UiSpawner, slot: CityFacilitySlot) -> String {
    city_string(ui, CITY_BUILDING_STRING_GROUP, slot as i16)
}

pub(in crate::ui::city) fn configure_industry_dialog(
    ui: &mut UiSpawner,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    page: IndustryPage,
) {
    let building_name = city_building_name(ui, page.slot);
    let capacity_template = city_string(ui, CITY_TEXT_STRING_GROUP, 0x10);
    let bar_color = ui.palette_color(0x16);
    bind_industry_dialog(
        &mut ui.commands,
        catalog,
        spawned,
        page,
        building_name,
        capacity_template,
        bar_color,
    );
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_city_order_control(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    binding: CityOrderBinding,
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
) -> Entity {
    let left = spawned.under(catalog, binding.tag, decrease_tag);
    let right = spawned.under(catalog, binding.tag, increase_tag);
    let quantity = spawned.under(catalog, binding.tag, quantity_tag);
    commands.entity(left).insert(CityOrderAdjust {
        order: binding.order,
        delta: -step,
    });
    commands.entity(right).insert(CityOrderAdjust {
        order: binding.order,
        delta: step,
    });
    commands.entity(quantity).insert(Text::new(""));
    quantity
}

fn bind_industry_amount_bars(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    page: IndustryPage,
    bar_color: Color,
) -> Vec<IndustryAmountBarControl> {
    let mut controls = Vec::with_capacity(page.orders.len());
    for binding in page.orders {
        let quantity = bind_city_order_control(
            commands,
            catalog,
            spawned,
            *binding,
            fourcc!("left"),
            fourcc!("rght"),
            fourcc!("move"),
            1,
        );
        let bar = spawned.under(catalog, binding.tag, fourcc!("bar "));
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

pub(in crate::ui::city) fn bind_industry_dialog(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    page: IndustryPage,
    building_name: String,
    capacity_template: String,
    bar_color: Color,
) {
    let root = bind_city_dialog_root(commands, spawned, page.slot);

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
    let amount_bars = bind_industry_amount_bars(commands, catalog, spawned, page, bar_color);
    let expansion_action = spawned.unique(fourcc!("expa"));
    commands
        .entity(expansion_action)
        .insert(CityExpansionOpen { slot: page.slot });
    let expansion = spawned.unique(fourcc!("flag"));
    commands.entity(root).insert(IndustryView {
        slot: page.slot,
        capacity_template,
        capacity,
        labor,
        stocks,
        amount_bars,
        expansion,
    });
}

pub(in crate::ui::city) fn sync_industry_dialog(
    session: Res<GameSession>,
    dialogs: Query<Ref<IndustryView>>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
    mut nodes: Query<&mut Node>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for view in &dialogs {
        if !session.is_changed() && !view.is_added() {
            continue;
        }
        let major = session.0.nations().major(nation);
        let city = &major.city;

        let capacity =
            format_retail_number(&view.capacity_template, city.production_orders[view.slot]);
        texts
            .get_mut(view.capacity)
            .expect("industry capacity control belongs to its dialog")
            .0 = capacity;
        *visibilities
            .get_mut(view.labor)
            .expect("industry labor indicator belongs to its dialog") =
            if city.population.strength() >= 2 {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        for stock in &view.stocks {
            *visibilities
                .get_mut(stock.entity)
                .expect("industry stock indicator belongs to its dialog") =
                if city.stockpile[stock.resource] < stock.minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
        }
        for bar in &view.amount_bars {
            let status = session.0.city_order_status(nation, bar.order);
            texts
                .get_mut(bar.quantity)
                .expect("industry order quantity belongs to its dialog")
                .0 = status.quantity.to_string();
            let capacity = city.production_orders[view.slot];
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
            .get_mut(view.expansion)
            .expect("industry expansion indicator belongs to its dialog") =
            if city_is_expanding(city, view.slot) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
    }
}
