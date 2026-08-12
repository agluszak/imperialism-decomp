use super::catalog::{SpawnedView, UiAssetResources, UiCatalogResource, spawn_view};
use super::format_currency;
use super::game_shell::{bind_game_screen_nav, transport_view_id};
use super::random_setup::GameSession;
use crate::AppState;
use bevy::picking::hover::Hovered;
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::Activate;
use imperialism_core::*;
use imperialism_formats::*;

#[derive(Clone, Copy)]
struct TransportRowBinding {
    tag: FourCc,
    label: &'static str,
    allocation: TransportAllocation,
}

const TRANSPORT_ROWS: [TransportRowBinding; 18] = [
    TransportRowBinding {
        tag: fourcc!("fish"),
        label: "Fish and livestock",
        allocation: TransportAllocation::FISH_AND_LIVESTOCK,
    },
    TransportRowBinding {
        tag: fourcc!("prod"),
        label: "Fruit",
        allocation: TransportAllocation::FRUIT,
    },
    TransportRowBinding {
        tag: fourcc!("grai"),
        label: "Grain",
        allocation: TransportAllocation::GRAIN,
    },
    TransportRowBinding {
        tag: fourcc!("timb"),
        label: "Timber",
        allocation: TransportAllocation::TIMBER,
    },
    TransportRowBinding {
        tag: fourcc!("lumb"),
        label: "Lumber",
        allocation: TransportAllocation::LUMBER,
    },
    TransportRowBinding {
        tag: fourcc!("furn"),
        label: "Furniture",
        allocation: TransportAllocation::FURNITURE,
    },
    TransportRowBinding {
        tag: fourcc!("coal"),
        label: "Coal",
        allocation: TransportAllocation::COAL,
    },
    TransportRowBinding {
        tag: fourcc!("iron"),
        label: "Iron",
        allocation: TransportAllocation::IRON,
    },
    TransportRowBinding {
        tag: fourcc!("stee"),
        label: "Steel",
        allocation: TransportAllocation::STEEL,
    },
    TransportRowBinding {
        tag: fourcc!("hard"),
        label: "Hardware",
        allocation: TransportAllocation::HARDWARE,
    },
    TransportRowBinding {
        tag: fourcc!("cott"),
        label: "Cotton and wool",
        allocation: TransportAllocation::COTTON_AND_WOOL,
    },
    TransportRowBinding {
        tag: fourcc!("fabr"),
        label: "Fabric",
        allocation: TransportAllocation::FABRIC,
    },
    TransportRowBinding {
        tag: fourcc!("clot"),
        label: "Clothing",
        allocation: TransportAllocation::CLOTHING,
    },
    TransportRowBinding {
        tag: fourcc!("oil "),
        label: "Oil",
        allocation: TransportAllocation::OIL,
    },
    TransportRowBinding {
        tag: fourcc!("fuel"),
        label: "Fuel",
        allocation: TransportAllocation::FUEL,
    },
    TransportRowBinding {
        tag: fourcc!("hors"),
        label: "Horses",
        allocation: TransportAllocation::HORSES,
    },
    TransportRowBinding {
        tag: fourcc!("gold"),
        label: "Gold",
        allocation: TransportAllocation::GOLD,
    },
    TransportRowBinding {
        tag: fourcc!("gems"),
        label: "Gems",
        allocation: TransportAllocation::GEMS,
    },
];

const LEFT_TRANSPORT_ROW_COUNT: usize = 10;

#[derive(Clone, Copy)]
struct TransportColors {
    allocation: Color,
    empty: Color,
    below_limit: Color,
    at_limit: Color,
}

#[derive(Component)]
struct TransportScreen;

#[derive(Component, Clone, Copy)]
struct TransportAdjust {
    allocation: TransportAllocation,
    delta: i16,
}

#[derive(Clone, Copy)]
enum TransportGaugeKind {
    Allocation(TransportAllocation),
    Capacity,
}

#[derive(Component, Clone, Copy)]
enum TransportDisplay {
    Row {
        label: &'static str,
        allocation: TransportAllocation,
    },
    RowCaption(TransportAllocation),
    CapacityCaption,
    Money {
        resource: ResourceKind,
        unit_value: i32,
    },
    Treasury,
    Cursor,
    Gauge {
        kind: TransportGaugeKind,
        normal_color: Color,
        full_color: Color,
    },
    Limit {
        allocation: TransportAllocation,
        below_color: Color,
        reached_color: Color,
    },
}

pub(crate) struct TransportPlugin;

impl Plugin for TransportPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::Transport), enter_transport_screen)
            .add_systems(
                Update,
                (sync_transport_values, sync_transport_cursor)
                    .run_if(in_state(AppState::Transport)),
            )
            .add_observer(on_transport_adjust.run_if(in_state(AppState::Transport)));
    }
}

fn enter_transport_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    mut session: ResMut<GameSession>,
) {
    let view_id = transport_view_id();
    let view = catalog.required_view(&view_id);
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_game_screen_nav(&mut commands, &catalog, &spawned);
    commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::Transport));

    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    session.0.rebuild_nation_resource_yields(nation);
    let (font, layout, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: 0,
        })
        .expect("retail transport ledger text style");
    let colors = TransportColors {
        allocation: assets.palette_color(0x3a),
        empty: assets.palette_color(0x3b),
        below_limit: assets.palette_color(0x33),
        at_limit: assets.palette_color(0x34),
    };
    bind_transport_screen(&mut commands, &catalog, &spawned, font, layout, colors);
}

fn bind_transport_screen(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    font: TextFont,
    layout: TextLayout,
    colors: TransportColors,
) {
    commands.entity(spawned.root).insert(TransportScreen);
    let selected = spawned.unique(fourcc!("tran"));
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    for (index, binding) in TRANSPORT_ROWS.into_iter().enumerate() {
        let row = spawned.unique(binding.tag);
        commands.entity(row).insert((
            TransportDisplay::Row {
                label: binding.label,
                allocation: binding.allocation,
            },
            Hovered::default(),
        ));
        let left = spawned.under(catalog, binding.tag, fourcc!("left"));
        let right = spawned.under(catalog, binding.tag, fourcc!("rght"));
        commands.entity(left).insert(TransportAdjust {
            allocation: binding.allocation,
            delta: -1,
        });
        commands.entity(right).insert(TransportAdjust {
            allocation: binding.allocation,
            delta: 1,
        });
        let track_left = if index < LEFT_TRANSPORT_ROW_COUNT {
            0x61
        } else {
            0x5d
        };
        spawn_transport_track(commands, row, track_left, colors.empty);
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(track_left as f32),
                top: Val::Px(0x0d as f32),
                width: Val::Px(0.0),
                height: Val::Px(4.0),
                ..default()
            },
            BackgroundColor(colors.allocation),
            ZIndex(1),
            Pickable::IGNORE,
            ChildOf(row),
            TransportDisplay::Gauge {
                kind: TransportGaugeKind::Allocation(binding.allocation),
                normal_color: colors.allocation,
                full_color: colors.allocation,
            },
        ));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px((track_left - 1) as f32),
                top: Val::Px(0x12 as f32),
                width: Val::Px(0x73 as f32),
                height: Val::Px(2.0),
                ..default()
            },
            BackgroundColor(colors.below_limit),
            Pickable::IGNORE,
            ChildOf(row),
            TransportDisplay::Limit {
                allocation: binding.allocation,
                below_color: colors.below_limit,
                reached_color: colors.at_limit,
            },
        ));
        commands.spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(0x98 as f32),
                top: Val::Px(0x12 as f32),
                width: Val::Px(0x46 as f32),
                height: Val::Px(0x0b as f32),
                ..default()
            },
            Text::new(""),
            font.clone(),
            layout,
            TextColor(Color::BLACK),
            Pickable::IGNORE,
            ChildOf(row),
            TransportDisplay::RowCaption(binding.allocation),
        ));
        if let Some((resource, unit_value)) = if binding.allocation == TransportAllocation::GOLD {
            Some((ResourceKind::Gold, 200))
        } else if binding.allocation == TransportAllocation::GEMS {
            Some((ResourceKind::Gems, 500))
        } else {
            None
        } {
            commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: Val::Px(0x32 as f32),
                    top: Val::Px(0x14 as f32),
                    width: Val::Px(0x3c as f32),
                    height: Val::Px(0x0b as f32),
                    ..default()
                },
                Text::new(""),
                font.clone(),
                layout,
                TextColor(Color::BLACK),
                Pickable::IGNORE,
                ChildOf(row),
                TransportDisplay::Money {
                    resource,
                    unit_value,
                },
            ));
        }
    }

    let total = spawned.unique(fourcc!("tota"));
    spawn_transport_track(commands, total, 0x5d, colors.empty);
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(0x5d as f32),
            top: Val::Px(0x0d as f32),
            width: Val::Px(0.0),
            height: Val::Px(4.0),
            ..default()
        },
        BackgroundColor(colors.below_limit),
        ZIndex(1),
        Pickable::IGNORE,
        ChildOf(total),
        TransportDisplay::Gauge {
            kind: TransportGaugeKind::Capacity,
            normal_color: colors.below_limit,
            full_color: colors.at_limit,
        },
    ));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(0xa2 as f32),
            top: Val::Px(0x14 as f32),
            width: Val::Px(0x3c as f32),
            height: Val::Px(0x0b as f32),
            ..default()
        },
        Text::new(""),
        font.clone(),
        layout,
        TextColor(Color::BLACK),
        Pickable::IGNORE,
        ChildOf(total),
        TransportDisplay::CapacityCaption,
    ));
    let cursor = spawned.unique(fourcc!("curs"));
    commands.entity(cursor).insert((
        Text::new(""),
        font,
        layout,
        TextColor(Color::BLACK),
        TransportDisplay::Cursor,
    ));
    let treasury = spawned.unique(fourcc!("trea"));
    commands.entity(treasury).insert(TransportDisplay::Treasury);
}

fn spawn_transport_track(commands: &mut Commands, parent: Entity, left: i32, color: Color) {
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(left as f32),
            top: Val::Px(0x0d as f32),
            width: Val::Px(0x71 as f32),
            height: Val::Px(4.0),
            ..default()
        },
        BackgroundColor(color),
        Pickable::IGNORE,
        ChildOf(parent),
    ));
}

fn on_transport_adjust(
    activate: On<Activate>,
    actions: Query<&TransportAdjust>,
    mut session: ResMut<GameSession>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    session
        .0
        .step_transport_allocation(nation, action.allocation, action.delta);
}

#[allow(clippy::type_complexity)]
fn sync_transport_values(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<(), Added<TransportScreen>>,
    mut displays: Query<(
        &TransportDisplay,
        Option<&mut Text>,
        &mut Node,
        &mut Visibility,
        Option<&mut BackgroundColor>,
    )>,
    actions: Query<(Entity, &TransportAdjust, Has<InteractionDisabled>)>,
) {
    if !session.is_changed() && screens.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    let major = session.0.nations().major(nation);
    let economy = &major.economy;
    for (display, text, mut node, mut visibility, color) in &mut displays {
        match *display {
            TransportDisplay::Row { allocation, .. } => {
                let current = allocation_amount(allocation, |resource| {
                    economy.need_current_by_type[resource]
                });
                *visibility = if current == 0 {
                    Visibility::Hidden
                } else {
                    Visibility::Visible
                };
            }
            TransportDisplay::RowCaption(allocation) => {
                let target =
                    allocation_amount(allocation, |resource| economy.need_target_by_type[resource]);
                let current = allocation_amount(allocation, |resource| {
                    economy.need_current_by_type[resource]
                });
                text.expect("Transport row caption has text").0 = format!("{target}  /  {current}");
            }
            TransportDisplay::CapacityCaption => {
                let capacities = economy.capacities;
                text.expect("Transport capacity caption has text").0 = format!(
                    "{}  /  {}",
                    capacities.reserved_transport, capacities.transport
                );
            }
            TransportDisplay::Money {
                resource,
                unit_value,
            } => {
                let target = economy.need_target_by_type[resource];
                text.expect("Transport money caption has text").0 =
                    format_currency(i32::from(target) * unit_value);
            }
            TransportDisplay::Treasury => {
                text.expect("Transport treasury caption has text").0 =
                    format_currency(major.common.treasury);
            }
            TransportDisplay::Cursor => {}
            TransportDisplay::Gauge {
                kind,
                normal_color,
                full_color,
            } => {
                let (value, total) = match kind {
                    TransportGaugeKind::Allocation(allocation) => (
                        allocation_amount(allocation, |resource| {
                            economy.need_target_by_type[resource]
                        }),
                        allocation_amount(allocation, |resource| {
                            economy.need_current_by_type[resource]
                        }),
                    ),
                    TransportGaugeKind::Capacity => (
                        economy.capacities.reserved_transport,
                        economy.capacities.transport,
                    ),
                };
                node.width = Val::Px(transport_gauge_width(value, total));
                color.expect("Transport gauge has a color").0 = if value == total {
                    full_color
                } else {
                    normal_color
                };
            }
            TransportDisplay::Limit {
                allocation,
                below_color,
                reached_color,
            } => {
                let Some(limit) = transport_need_limit(major, allocation) else {
                    *visibility = Visibility::Hidden;
                    continue;
                };
                let target = allocation_amount(allocation, |resource| {
                    major.economy.need_target_by_type[resource]
                });
                *visibility = Visibility::Visible;
                color.expect("Transport limit has a color").0 = if target < limit {
                    below_color
                } else {
                    reached_color
                };
            }
        }
    }
    for (entity, action, disabled) in &actions {
        let current = allocation_amount(action.allocation, |resource| {
            economy.need_current_by_type[resource]
        });
        let target = allocation_amount(action.allocation, |resource| {
            economy.need_target_by_type[resource]
        });
        let enabled = current != 0
            && if action.delta < 0 {
                target > 0
            } else {
                target < current
                    && economy.capacities.reserved_transport != economy.capacities.transport
            };
        if enabled == disabled {
            if enabled {
                commands.entity(entity).remove::<InteractionDisabled>();
            } else {
                commands.entity(entity).insert(InteractionDisabled);
            }
        }
    }
}

fn sync_transport_cursor(
    session: Res<GameSession>,
    screens: Query<(), Added<TransportScreen>>,
    changed_rows: Query<(), (With<TransportDisplay>, Changed<Hovered>)>,
    rows: Query<(&TransportDisplay, &Hovered)>,
    mut displays: Query<(&TransportDisplay, &mut Text)>,
) {
    if !session.is_changed() && screens.is_empty() && changed_rows.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    let major = session.0.nations().major(nation);
    for (display, mut text) in &mut displays {
        if !matches!(display, TransportDisplay::Cursor) {
            continue;
        }
        let economy = &major.economy;
        let Some((label, allocation)) = rows.iter().find_map(|(display, hovered)| {
            let TransportDisplay::Row { label, allocation } = *display else {
                return None;
            };
            hovered.get().then_some((label, allocation))
        }) else {
            text.0 = format!(
                "Transport: {} of {} allocated",
                economy.capacities.reserved_transport, economy.capacities.transport
            );
            continue;
        };
        let stock = allocation_amount(allocation, |resource| major.city.stockpile[resource]);
        let target =
            allocation_amount(allocation, |resource| economy.need_target_by_type[resource]);
        let current = allocation_amount(allocation, |resource| {
            economy.need_current_by_type[resource]
        });
        let supply_headroom = (current - target).max(0);
        let capacity_headroom =
            if economy.capacities.reserved_transport <= economy.capacities.transport {
                economy.capacities.transport - economy.capacities.reserved_transport
            } else {
                i16::MAX
            };
        let limit = supply_headroom.min(capacity_headroom);
        let limiting = match supply_headroom.cmp(&capacity_headroom) {
            std::cmp::Ordering::Less => "supply",
            std::cmp::Ordering::Equal => "supply and capacity",
            std::cmp::Ordering::Greater => "capacity",
        };
        let city_need = transport_need_limit(major, allocation)
            .map_or_else(|| "".to_owned(), |need| format!("; city need {need}"));
        text.0 = format!(
            "{}: city {stock}; allocated {target}; supply {current}; +{limit} max ({limiting}){city_need}",
            label,
        );
    }
}

fn allocation_amount(
    allocation: TransportAllocation,
    mut amount: impl FnMut(ResourceKind) -> i16,
) -> i16 {
    let (primary, secondary) = allocation.resources();
    amount(primary) + secondary.map_or(0, amount)
}

fn transport_gauge_width(value: i16, total: i16) -> f32 {
    if total <= 0 {
        return 0.0;
    }
    let pixels_per_unit = 113.0 / f32::from(total);
    let remainder = 113.0 - pixels_per_unit * f32::from(total);
    let value = f32::from(value);
    let width = if remainder < value {
        remainder * (pixels_per_unit + 1.0) + (value - remainder) * pixels_per_unit
    } else {
        value * (pixels_per_unit + 1.0)
    };
    width.clamp(0.0, 113.0).trunc()
}

fn transport_need_limit(major: &MajorNation, allocation: TransportAllocation) -> Option<i16> {
    let city = &major.city;
    let building = |slot| {
        city.building_type(
            slot,
            &major.economy,
            major.common.owned_region_count() as i32,
        )
    };
    let deficit = if allocation == TransportAllocation::COTTON_AND_WOOL {
        building(CityFacilitySlot::TextileMill) * 2
            - city.stockpile[ResourceKind::Cotton]
            - city.stockpile[ResourceKind::Wool]
    } else if allocation == TransportAllocation::TIMBER {
        building(CityFacilitySlot::LumberMill) * 2 - city.stockpile[ResourceKind::Timber]
    } else if allocation == TransportAllocation::COAL {
        building(CityFacilitySlot::SteelMill) - city.stockpile[ResourceKind::Coal]
    } else if allocation == TransportAllocation::IRON {
        building(CityFacilitySlot::SteelMill) - city.stockpile[ResourceKind::Iron]
    } else if allocation == TransportAllocation::OIL {
        building(CityFacilitySlot::OilRefinery) * 2 - city.stockpile[ResourceKind::Oil]
    } else if allocation == TransportAllocation::FABRIC {
        building(CityFacilitySlot::ClothingFactory) * 2 - city.stockpile[ResourceKind::Fabric]
    } else if allocation == TransportAllocation::LUMBER {
        building(CityFacilitySlot::FurnitureFactory) * 2 - city.stockpile[ResourceKind::Lumber]
    } else if allocation == TransportAllocation::STEEL {
        building(CityFacilitySlot::Metalworks) * 2 - city.stockpile[ResourceKind::Steel]
    } else if allocation == TransportAllocation::FUEL {
        building(CityFacilitySlot::PowerPlant) * 2 - city.stockpile[ResourceKind::Fuel]
    } else if allocation == TransportAllocation::GRAIN {
        city.population.predicted_need(ResourceKind::Grain) - city.stockpile[ResourceKind::Grain]
    } else if allocation == TransportAllocation::FRUIT {
        city.population.predicted_need(ResourceKind::Fruit) - city.stockpile[ResourceKind::Fruit]
    } else if allocation == TransportAllocation::FISH_AND_LIVESTOCK {
        city.population.predicted_need(ResourceKind::Livestock)
            - city.stockpile[ResourceKind::Fish]
            - city.stockpile[ResourceKind::Livestock]
    } else {
        return None;
    };
    Some(deficit.max(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::catalog::spawn_view_nodes;
    use bevy::ecs::system::RunSystemOnce;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");
    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    #[derive(Clone, Copy)]
    struct TestTransport {
        root: Entity,
        selected: Entity,
        return_to_map: Entity,
    }

    fn fixture_session() -> GameSession {
        let save = LegacySaveV62::parse(BEGINNING_OF_GAME);
        let state = save.game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 3_916_827_792,
            selected_nation: NationId::new(6),
        });
        GameSession(state)
    }

    fn spawn_transport(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        mut session: ResMut<GameSession>,
    ) -> TestTransport {
        let view = catalog.required_view(&transport_view_id());
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        commands
            .entity(spawned.unique(fourcc!("trea")))
            .insert(Text::new(""));
        let nation = MajorNationId::from_nation(session.0.turn().active_nation).unwrap();
        session.0.rebuild_nation_resource_yields(nation);
        bind_transport_screen(
            &mut commands,
            &catalog,
            &spawned,
            TextFont::default(),
            TextLayout::default(),
            TransportColors {
                allocation: Color::BLACK,
                empty: Color::BLACK,
                below_limit: Color::BLACK,
                at_limit: Color::WHITE,
            },
        );
        TestTransport {
            root: spawned.root,
            selected: spawned.unique(fourcc!("tran")),
            return_to_map: spawned.unique(fourcc!("end ")),
        }
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    fn amount(state: &GameState, nation: MajorNationId, allocation: TransportAllocation) -> i16 {
        let economy = &state.nations().major(nation).economy;
        allocation_amount(allocation, |resource| economy.need_target_by_type[resource])
    }

    fn caption(app: &mut App, allocation: TransportAllocation) -> String {
        let mut query = app.world_mut().query::<(&TransportDisplay, &Text)>();
        query
            .iter(app.world())
            .find(|(display, _)| {
                matches!(display, TransportDisplay::RowCaption(found) if *found == allocation)
            })
            .unwrap()
            .1
            .0
            .clone()
    }

    fn capacity_caption(app: &mut App) -> String {
        let mut query = app.world_mut().query::<(&TransportDisplay, &Text)>();
        query
            .iter(app.world())
            .find(|(display, _)| matches!(display, TransportDisplay::CapacityCaption))
            .unwrap()
            .1
            .0
            .clone()
    }

    fn capacity_gauge_width(app: &mut App) -> f32 {
        let mut query = app.world_mut().query::<(&TransportDisplay, &Node)>();
        let (_, node) = query
            .iter(app.world())
            .find(|(display, _)| {
                matches!(
                    display,
                    TransportDisplay::Gauge {
                        kind: TransportGaugeKind::Capacity,
                        ..
                    }
                )
            })
            .unwrap();
        match node.width {
            Val::Px(width) => width,
            other => panic!("expected pixel gauge width, found {other:?}"),
        }
    }

    #[test]
    fn allocation_round_trips_through_generated_controls_and_reopen() {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog))
            .insert_resource(fixture_session())
            .add_observer(on_transport_adjust)
            .add_systems(Update, (sync_transport_values, sync_transport_cursor));

        let first = app.world_mut().run_system_once(spawn_transport).unwrap();
        app.update();
        assert!(app.world().get::<Checked>(first.selected).is_some());
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.selected)
                .is_some()
        );
        assert!(
            app.world()
                .get::<InteractionDisabled>(first.return_to_map)
                .is_none()
        );
        let mut panels = app.world_mut().query::<(&TransportDisplay, &Visibility)>();
        assert!(
            panels
                .iter(app.world())
                .any(
                    |(display, visibility)| matches!(display, TransportDisplay::Row { .. })
                        && *visibility == Visibility::Hidden
                )
        );
        let nation = MajorNationId::new(6);
        let (allocation, decrease) = {
            let session = app.world().resource::<GameSession>();
            let economy = &session.0.nations().major(nation).economy;
            let allocation = TRANSPORT_ROWS
                .iter()
                .map(|row| row.allocation)
                .find(|&allocation| {
                    let current = allocation_amount(allocation, |resource| {
                        economy.need_current_by_type[resource]
                    });
                    let target = allocation_amount(allocation, |resource| {
                        economy.need_target_by_type[resource]
                    });
                    current != 0 && target > 0
                })
                .expect("fixture has an adjustable transport row");
            let mut actions = app.world_mut().query::<(Entity, &TransportAdjust)>();
            let decrease = actions
                .iter(app.world())
                .find(|(_, action)| action.allocation == allocation && action.delta == -1)
                .unwrap()
                .0;
            (allocation, decrease)
        };
        let (before_target, before_reserved, city_before) = {
            let session = app.world().resource::<GameSession>();
            let major = session.0.nations().major(nation);
            (
                amount(&session.0, nation, allocation),
                major.economy.capacities.reserved_transport,
                major.city.stockpile,
            )
        };

        activate(&mut app, decrease);
        let current = {
            let session = app.world().resource::<GameSession>();
            let major = session.0.nations().major(nation);
            assert_eq!(amount(&session.0, nation, allocation), before_target - 1);
            assert_eq!(
                major.economy.capacities.reserved_transport,
                before_reserved - 1
            );
            assert_eq!(major.city.stockpile, city_before);
            allocation_amount(allocation, |resource| {
                major.economy.need_current_by_type[resource]
            })
        };
        assert_eq!(
            caption(&mut app, allocation),
            format!("{}  /  {current}", before_target - 1)
        );
        let capacity = app
            .world()
            .resource::<GameSession>()
            .0
            .nations()
            .major(nation)
            .economy
            .capacities
            .transport;
        assert_eq!(
            capacity_caption(&mut app),
            format!("{}  /  {capacity}", before_reserved - 1)
        );
        assert_eq!(
            capacity_gauge_width(&mut app),
            transport_gauge_width(before_reserved - 1, capacity)
        );

        app.world_mut().commands().entity(first.root).despawn();
        app.world_mut().flush();
        app.world_mut().run_system_once(spawn_transport).unwrap();
        app.update();
        assert_eq!(
            amount(&app.world().resource::<GameSession>().0, nation, allocation),
            before_target - 1
        );
        let reopened_caption = caption(&mut app, allocation);
        assert!(reopened_caption.starts_with(&(before_target - 1).to_string()));

        let increase = {
            let mut actions = app.world_mut().query::<(Entity, &TransportAdjust)>();
            actions
                .iter(app.world())
                .find(|(_, action)| action.allocation == allocation && action.delta == 1)
                .unwrap()
                .0
        };
        assert!(app.world().get::<InteractionDisabled>(increase).is_none());
        activate(&mut app, increase);
        assert_eq!(
            amount(&app.world().resource::<GameSession>().0, nation, allocation),
            before_target
        );
    }
}
