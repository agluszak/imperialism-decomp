use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::bind_native_game_screen_nav;
use super::generated;
use super::retail::{RetailTag, find_descendant};
use crate::AppState;
use bevy::picking::hover::Hovered;
use bevy::prelude::*;
use bevy::text::LineHeight;
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

#[derive(Component)]
struct TransportCursor;

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
        app.add_systems(
            OnEnter(AppState::Transport),
            (enter_transport_screen, bind_transport_screen).chain(),
        )
        .add_systems(
            Update,
            (
                sync_transport_text,
                sync_transport_visual,
                sync_transport_presence,
                sync_transport_cursor,
            )
                .run_if(in_state(AppState::Transport)),
        )
        .add_observer(on_transport_adjust.run_if(in_state(AppState::Transport)));
    }
}

fn enter_transport_screen(mut commands: Commands) {
    let root = commands.spawn_scene(generated::transport_2014()).id();
    commands
        .entity(root)
        .insert((TransportScreen, DespawnOnExit(AppState::Transport)));
}

fn bind_transport_screen(
    mut commands: Commands,
    root: Single<Entity, Added<TransportScreen>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        *root,
        &children,
        &tags,
        fourcc!("topB"),
        Some(fourcc!("tool")),
    );

    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    session.0.rebuild_nation_resource_yields(nation);
    let (font, layout, line_height, _) = assets
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
    bind_transport_controls(
        &mut commands,
        *root,
        &children,
        &tags,
        font,
        layout,
        line_height,
        colors,
    );
}

#[allow(clippy::too_many_arguments)]
fn bind_transport_controls(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    font: TextFont,
    layout: TextLayout,
    line_height: LineHeight,
    colors: TransportColors,
) {
    let selected = find_descendant(root, fourcc!("tran"), children, tags);
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    for (index, binding) in TRANSPORT_ROWS.into_iter().enumerate() {
        let row = find_descendant(root, binding.tag, children, tags);
        commands.entity(row).insert((
            TransportDisplay::Row {
                label: binding.label,
                allocation: binding.allocation,
            },
            Hovered::default(),
        ));
        let left = find_descendant(row, fourcc!("left"), children, tags);
        let right = find_descendant(row, fourcc!("rght"), children, tags);
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
        commands.entity(row).apply_scene(transport_row_overlay(
            binding.allocation,
            track_left,
            font.clone(),
            layout,
            line_height,
            colors,
        ));
        if let Some((resource, unit_value)) = if binding.allocation == TransportAllocation::GOLD {
            Some((ResourceKind::Gold, 200))
        } else if binding.allocation == TransportAllocation::GEMS {
            Some((ResourceKind::Gems, 500))
        } else {
            None
        } {
            commands.entity(row).apply_scene(transport_money_overlay(
                resource,
                unit_value,
                font.clone(),
                layout,
                line_height,
            ));
        }
    }

    let total = find_descendant(root, fourcc!("tota"), children, tags);
    commands
        .entity(total)
        .apply_scene(transport_capacity_overlay(
            font.clone(),
            layout,
            line_height,
            colors,
        ));
    let cursor = find_descendant(root, fourcc!("curs"), children, tags);
    commands.entity(cursor).insert((
        Text::new(""),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
        TransportCursor,
    ));
    let treasury = find_descendant(root, fourcc!("trea"), children, tags);
    commands.entity(treasury).insert(TransportDisplay::Treasury);
}

fn transport_track(left: i32, color: Color) -> impl Scene {
    bsn! {
        Node {
            position_type: PositionType::Absolute,
            left: px(left),
            top: px(0x0d),
            width: px(0x71),
            height: px(4),
        }
        BackgroundColor(color)
        Pickable::IGNORE
    }
}

fn transport_row_overlay(
    allocation: TransportAllocation,
    track_left: i32,
    font: TextFont,
    layout: TextLayout,
    line_height: LineHeight,
    colors: TransportColors,
) -> impl Scene {
    bsn! {
        Children [
            (transport_track(track_left, colors.empty)),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(track_left),
                    top: px(0x0d),
                    width: px(0),
                    height: px(4),
                }
                BackgroundColor({colors.allocation})
                ZIndex(1)
                Pickable::IGNORE
                template(move |_context| Ok(TransportDisplay::Gauge {
                    kind: TransportGaugeKind::Allocation(allocation),
                    normal_color: colors.allocation,
                    full_color: colors.allocation,
                }))
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(track_left - 1),
                    top: px(0x12),
                    width: px(0x73),
                    height: px(2),
                }
                BackgroundColor({colors.below_limit})
                Pickable::IGNORE
                template(move |_context| Ok(TransportDisplay::Limit {
                    allocation,
                    below_color: colors.below_limit,
                    reached_color: colors.at_limit,
                }))
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0x98),
                    top: px(0x12),
                    width: px(0x46),
                    height: px(0x0b),
                }
                Text("")
                template(move |_context| Ok(font.clone()))
                template(move |_context| Ok(layout))
                template(move |_context| Ok(line_height))
                TextColor(Color::BLACK)
                Pickable::IGNORE
                template(move |_context| Ok(TransportDisplay::RowCaption(allocation)))
            ),
        ]
    }
}

fn transport_money_overlay(
    resource: ResourceKind,
    unit_value: i32,
    font: TextFont,
    layout: TextLayout,
    line_height: LineHeight,
) -> impl Scene {
    bsn! {
        Children [
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0x32),
                    top: px(0x14),
                    width: px(0x3c),
                    height: px(0x0b),
                }
                Text("")
                template(move |_context| Ok(font.clone()))
                template(move |_context| Ok(layout))
                template(move |_context| Ok(line_height))
                TextColor(Color::BLACK)
                Pickable::IGNORE
                template(move |_context| Ok(TransportDisplay::Money {
                    resource,
                    unit_value,
                }))
            ),
        ]
    }
}

fn transport_capacity_overlay(
    font: TextFont,
    layout: TextLayout,
    line_height: LineHeight,
    colors: TransportColors,
) -> impl Scene {
    bsn! {
        Children [
            (transport_track(0x5d, colors.empty)),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0x5d),
                    top: px(0x0d),
                    width: px(0),
                    height: px(4),
                }
                BackgroundColor({colors.below_limit})
                ZIndex(1)
                Pickable::IGNORE
                template(move |_context| Ok(TransportDisplay::Gauge {
                    kind: TransportGaugeKind::Capacity,
                    normal_color: colors.below_limit,
                    full_color: colors.at_limit,
                }))
            ),
            (
                Node {
                    position_type: PositionType::Absolute,
                    left: px(0xa2),
                    top: px(0x14),
                    width: px(0x3c),
                    height: px(0x0b),
                }
                Text("")
                template(move |_context| Ok(font.clone()))
                template(move |_context| Ok(layout))
                template(move |_context| Ok(line_height))
                TextColor(Color::BLACK)
                Pickable::IGNORE
                template(move |_context| Ok(TransportDisplay::CapacityCaption))
            ),
        ]
    }
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

fn sync_transport_text(
    session: Res<GameSession>,
    screens: Query<(), Added<TransportScreen>>,
    mut texts: Query<(&TransportDisplay, &mut Text)>,
) {
    if !session.is_changed() && screens.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    let major = session.0.nations().major(nation);
    let economy = &major.economy;
    for (display, mut text) in &mut texts {
        match *display {
            TransportDisplay::RowCaption(allocation) => {
                let status = session.0.transport_row_status(nation, allocation);
                text.0 = format!("{}  /  {}", status.allocated, status.available);
            }
            TransportDisplay::CapacityCaption => {
                let capacities = economy.capacities;
                text.0 = format!(
                    "{}  /  {}",
                    capacities.reserved_transport, capacities.transport
                );
            }
            TransportDisplay::Money {
                resource,
                unit_value,
            } => {
                let target = economy.need_target_by_type[resource];
                text.0 = format_currency(i32::from(target) * unit_value);
            }
            TransportDisplay::Treasury => {
                text.0 = format_currency(major.common.treasury);
            }
            _ => {}
        }
    }
}

fn sync_transport_visual(
    session: Res<GameSession>,
    screens: Query<(), Added<TransportScreen>>,
    mut displays: Query<(
        &TransportDisplay,
        &mut Node,
        &mut Visibility,
        &mut BackgroundColor,
    )>,
) {
    if !session.is_changed() && screens.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    let economy = &session.0.nations().major(nation).economy;
    for (display, mut node, mut visibility, mut color) in &mut displays {
        match *display {
            TransportDisplay::Gauge {
                kind,
                normal_color,
                full_color,
            } => {
                let (value, total) = match kind {
                    TransportGaugeKind::Allocation(allocation) => {
                        let status = session.0.transport_row_status(nation, allocation);
                        (status.allocated, status.available)
                    }
                    TransportGaugeKind::Capacity => (
                        economy.capacities.reserved_transport,
                        economy.capacities.transport,
                    ),
                };
                node.width = Val::Px(transport_gauge_width(value, total));
                color.0 = if value == total {
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
                let status = session.0.transport_row_status(nation, allocation);
                let Some(limit) = status.limit else {
                    *visibility = Visibility::Hidden;
                    continue;
                };
                *visibility = Visibility::Visible;
                color.0 = if status.allocated < limit {
                    below_color
                } else {
                    reached_color
                };
            }
            _ => {}
        }
    }
}

fn sync_transport_presence(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<(), Added<TransportScreen>>,
    mut rows: Query<(&TransportDisplay, &mut Visibility), Without<BackgroundColor>>,
    actions: Query<(Entity, &TransportAdjust, Has<InteractionDisabled>)>,
) {
    if !session.is_changed() && screens.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    for (display, mut visibility) in &mut rows {
        let TransportDisplay::Row { allocation, .. } = *display else {
            continue;
        };
        let status = session.0.transport_row_status(nation, allocation);
        *visibility = if status.adjustable {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
    for (entity, action, disabled) in &actions {
        let status = session.0.transport_row_status(nation, action.allocation);
        let enabled = if action.delta < 0 {
            status.can_decrease
        } else {
            status.can_increase
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
    mut cursor: Query<&mut Text, With<TransportCursor>>,
) {
    if !session.is_changed() && screens.is_empty() && changed_rows.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    let major = session.0.nations().major(nation);
    let Ok(mut text) = cursor.single_mut() else {
        return;
    };
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
        return;
    };
    let stock = allocation_amount(allocation, |resource| major.city.stockpile[resource]);
    let status = session.0.transport_row_status(nation, allocation);
    let supply_headroom = (status.available - status.allocated).max(0);
    let capacity_headroom = if economy.capacities.reserved_transport <= economy.capacities.transport
    {
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
    let city_need = status
        .limit
        .map_or_else(|| "".to_owned(), |need| format!("; city need {need}"));
    text.0 = format!(
        "{}: city {stock}; allocated {}; supply {}; +{limit} max ({limiting}){city_need}",
        label, status.allocated, status.available,
    );
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
