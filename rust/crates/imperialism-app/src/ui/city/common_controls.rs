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
    binding: CityOrderBinding,
    fill: Entity,
    maximum: Entity,
}

#[derive(Component)]
pub(in crate::ui::city) struct IndustryDialogControls {
    capacity_template: String,
    amount_bars: Vec<IndustryAmountBarControl>,
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn bind_city_order_controls(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
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
            order: binding.order,
            delta: -step,
        });
        commands.entity(right).insert(CityOrderAdjust {
            order: binding.order,
            delta: step,
        });
        commands.entity(quantity).insert(Text::new(""));
    }
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
            binding: *binding,
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
    for &(_, tag, _) in page.stocks {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(Text::new("X"));
    }
    bind_city_order_controls(
        commands,
        catalog,
        spawned,
        page.orders,
        fourcc!("left"),
        fourcc!("rght"),
        fourcc!("move"),
        1,
    );
    let amount_bars = bind_industry_amount_bars(commands, catalog, spawned, page, bar_color);
    let expansion = spawned.unique(fourcc!("expa"));
    commands
        .entity(expansion)
        .insert(CityExpansionOpen { slot: page.slot });
    commands.entity(root).insert(IndustryDialogControls {
        capacity_template,
        amount_bars,
    });
}

pub(in crate::ui::city) fn sync_industry_dialog(
    session: Res<GameSession>,
    catalog: Res<UiCatalogResource>,
    dialogs: Query<(
        &SpawnedView,
        Ref<CityBuildingDialog>,
        &IndustryDialogControls,
    )>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
    mut nodes: Query<&mut Node>,
) {
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("City active nation is a major nation");
    for (spawned, dialog, controls) in &dialogs {
        if !session.is_changed() && !dialog.is_added() {
            continue;
        }
        let page = industry_page(dialog.slot).expect("industry dialog has an industry slot");
        let major = session.0.nations().major(nation);
        let city = &major.city;

        let capacity = format_retail_number(
            &controls.capacity_template,
            city.production_orders[dialog.slot],
        );
        texts
            .get_mut(spawned.unique(fourcc!("capT")))
            .expect("industry capacity control belongs to its dialog")
            .0 = capacity;
        *visibilities
            .get_mut(spawned.unique(fourcc!("labV")))
            .expect("industry labor indicator belongs to its dialog") =
            if city.population.strength() >= 2 {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
        for &(resource, tag, minimum) in page.stocks {
            *visibilities
                .get_mut(spawned.unique(tag))
                .expect("industry stock indicator belongs to its dialog") =
                if city.stockpile[resource] < minimum {
                    Visibility::Visible
                } else {
                    Visibility::Hidden
                };
        }
        for binding in page.orders {
            let status = session.0.city_order_status(nation, binding.order);
            texts
                .get_mut(spawned.under(&catalog, binding.tag, fourcc!("move")))
                .expect("industry order quantity belongs to its dialog")
                .0 = status.quantity.to_string();
        }
        for bar in &controls.amount_bars {
            let status = session.0.city_order_status(nation, bar.binding.order);
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
                .get_mut(spawned.under(&catalog, bar.binding.tag, fourcc!("move")))
                .expect("industry amount quantity belongs to its dialog");
            quantity.left = Val::Px(INDUSTRY_BAR_X + f32::from(current) - 2.0);
            quantity.top = Val::Px(INDUSTRY_BAR_Y + 6.0);
        }
        *visibilities
            .get_mut(spawned.unique(fourcc!("flag")))
            .expect("industry expansion indicator belongs to its dialog") =
            if city_is_expanding(city, dialog.slot) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
    }
}
