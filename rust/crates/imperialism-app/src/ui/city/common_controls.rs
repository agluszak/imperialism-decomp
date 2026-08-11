use super::*;

pub(in crate::ui::city) const INDUSTRY_BAR_WIDTH: i16 = 150;
pub(in crate::ui::city) const INDUSTRY_BAR_X: f32 = 62.0;
pub(in crate::ui::city) const INDUSTRY_BAR_Y: f32 = 8.0;

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
) {
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
        commands.entity(quantity).insert((
            Text::new(""),
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::OrderQuantity(binding.order),
            },
        ));
    }
}

pub(in crate::ui::city) fn bind_industry_amount_bars(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    root: Entity,
    nation: MajorNationId,
    page: IndustryPage,
    bar_color: Color,
) {
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
                quantity,
                fill,
                maximum,
            },
        ));
    }
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
    commands.entity(capacity).insert((
        Text::new(""),
        CityValueBinding {
            dialog: Some(root),
            value: CityValue::BuildingCapacity(page.slot),
        },
        RetailNumberTemplate(capacity_template),
    ));
    let labor = spawned.unique(fourcc!("labV"));
    commands.entity(labor).insert((
        Text::new("X"),
        CityValueBinding {
            dialog: Some(root),
            value: CityValue::LaborIndicator,
        },
    ));
    for &(resource, tag, minimum) in page.stocks {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert((
            Text::new("X"),
            CityValueBinding {
                dialog: Some(root),
                value: CityValue::StockIndicator(resource, minimum),
            },
        ));
    }
    bind_city_order_controls(
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
    bind_industry_amount_bars(commands, catalog, spawned, root, nation, page, bar_color);
    let expansion = spawned.unique(fourcc!("expa"));
    commands.entity(expansion).insert(CityExpansionOpen {
        dialog: root,
        nation,
        slot: page.slot,
    });
    let expansion_indicator = spawned.unique(fourcc!("flag"));
    commands
        .entity(expansion_indicator)
        .insert(CityExpansionIndicator {
            dialog: root,
            slot: page.slot,
        });
}
