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

pub(in crate::ui::city) fn city_building_name(
    assets: &UiAssetResources,
    slot: CityFacilitySlot,
) -> String {
    city_string(assets, CITY_BUILDING_STRING_GROUP, slot as i16)
}

pub(in crate::ui::city) fn configure_industry_dialog(
    commands: &mut Commands,
    assets: &mut UiAssetResources,
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

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_city_order_control(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    binding: CityOrderBinding,
    decrease_tag: FourCc,
    increase_tag: FourCc,
    quantity_tag: FourCc,
    step: i16,
) -> Entity {
    let row = find_descendant(root, binding.tag, children, tags);
    let left = find_child_or_descendant(row, decrease_tag, children, tags);
    let right = find_child_or_descendant(row, increase_tag, children, tags);
    let quantity = find_child_or_descendant(row, quantity_tag, children, tags);
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
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    page: IndustryPage,
    bar_color: Color,
) -> Vec<IndustryAmountBarControl> {
    let mut controls = Vec::with_capacity(page.orders.len());
    for binding in page.orders {
        let quantity = bind_city_order_control(
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
        let row = find_descendant(root, binding.tag, children, tags);
        let bar = find_child_or_descendant(row, fourcc!("bar "), children, tags);
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
    commands.entity(capacity).insert(Text::new(""));
    let labor = find_descendant(root, fourcc!("labV"), children, tags);
    commands.entity(labor).insert(Text::new("X"));
    let mut stocks = Vec::with_capacity(page.stocks.len());
    for &(resource, tag, minimum) in page.stocks {
        let entity = find_descendant(root, tag, children, tags);
        commands.entity(entity).insert(Text::new("X"));
        stocks.push(IndustryStockControl {
            resource,
            minimum,
            entity,
        });
    }
    let amount_bars = bind_industry_amount_bars(commands, root, children, tags, page, bar_color);
    let expansion_action = find_descendant(root, fourcc!("expa"), children, tags);
    commands
        .entity(expansion_action)
        .insert(CityExpansionOpen { slot: page.slot });
    let expansion = find_descendant(root, fourcc!("flag"), children, tags);
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
