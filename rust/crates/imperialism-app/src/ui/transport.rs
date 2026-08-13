use super::GameSession;
use super::RetailUiAssets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
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
    allocation: TransportAllocation,
}

const TRANSPORT_ROWS: [TransportRowBinding; 18] = [
    TransportRowBinding {
        tag: fourcc!("fish"),
        allocation: TransportAllocation::FISH_AND_LIVESTOCK,
    },
    TransportRowBinding {
        tag: fourcc!("prod"),
        allocation: TransportAllocation::FRUIT,
    },
    TransportRowBinding {
        tag: fourcc!("grai"),
        allocation: TransportAllocation::GRAIN,
    },
    TransportRowBinding {
        tag: fourcc!("timb"),
        allocation: TransportAllocation::TIMBER,
    },
    TransportRowBinding {
        tag: fourcc!("lumb"),
        allocation: TransportAllocation::LUMBER,
    },
    TransportRowBinding {
        tag: fourcc!("furn"),
        allocation: TransportAllocation::FURNITURE,
    },
    TransportRowBinding {
        tag: fourcc!("coal"),
        allocation: TransportAllocation::COAL,
    },
    TransportRowBinding {
        tag: fourcc!("iron"),
        allocation: TransportAllocation::IRON,
    },
    TransportRowBinding {
        tag: fourcc!("stee"),
        allocation: TransportAllocation::STEEL,
    },
    TransportRowBinding {
        tag: fourcc!("hard"),
        allocation: TransportAllocation::HARDWARE,
    },
    TransportRowBinding {
        tag: fourcc!("cott"),
        allocation: TransportAllocation::COTTON_AND_WOOL,
    },
    TransportRowBinding {
        tag: fourcc!("fabr"),
        allocation: TransportAllocation::FABRIC,
    },
    TransportRowBinding {
        tag: fourcc!("clot"),
        allocation: TransportAllocation::CLOTHING,
    },
    TransportRowBinding {
        tag: fourcc!("oil "),
        allocation: TransportAllocation::OIL,
    },
    TransportRowBinding {
        tag: fourcc!("fuel"),
        allocation: TransportAllocation::FUEL,
    },
    TransportRowBinding {
        tag: fourcc!("hors"),
        allocation: TransportAllocation::HORSES,
    },
    TransportRowBinding {
        tag: fourcc!("gold"),
        allocation: TransportAllocation::GOLD,
    },
    TransportRowBinding {
        tag: fourcc!("gems"),
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

#[derive(Component)]
struct TransportHoverText(String);

#[derive(Clone, Copy)]
enum TransportGaugeKind {
    Allocation(TransportAllocation),
    Capacity,
}

#[derive(Component)]
struct TransportCursor;

#[derive(Component, Clone, Copy)]
enum TransportDisplay {
    Row(TransportAllocation),
    RowCaption(TransportAllocation),
    Track(TransportAllocation),
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
        );
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
    bind_game_status_display(
        &mut commands,
        &mut assets,
        *root,
        &children,
        &tags,
        &session,
    );
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: 10,
            alignment: 0,
        })
        .expect("retail transport ledger text style");
    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 18,
            alignment: 1,
        })
        .expect("retail transport title text style");
    let title_color = assets.palette_color(0xd2);
    let title_shadow = assets.palette_color(0x28);
    for tag in [fourcc!("titL"), fourcc!("titR")] {
        commands
            .entity(find_descendant(*root, tag, &children, &tags))
            .insert((
                title_font.clone(),
                title_layout,
                title_line_height,
                TextColor(title_color),
                TextShadow {
                    offset: Vec2::ONE,
                    color: title_shadow,
                },
            ));
    }
    let colors = TransportColors {
        // TTransportPicture passes these color codes through TViewMgr::GetColor.
        allocation: assets.palette_color(0xc6),
        empty: assets.palette_color(0x27),
        below_limit: assets.palette_color(0x2d),
        at_limit: assets.palette_color(0x18),
    };
    let (cursor_font, cursor_layout, cursor_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail transport cursor text style");
    let cursor_style = (
        cursor_font,
        cursor_layout,
        cursor_line_height,
        assets.palette_color(0x28),
        assets.palette_color(0),
    );
    bind_transport_controls(
        &mut commands,
        *root,
        &children,
        &tags,
        font,
        layout,
        line_height,
        cursor_style,
        colors,
    );
    for binding in TRANSPORT_ROWS {
        let row = find_descendant(*root, binding.tag, &children, &tags);
        commands
            .entity(row)
            .insert(TransportHoverText(transport_hover_text(
                &assets,
                &session.0,
                nation,
                binding.allocation,
            )));
    }
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
    cursor_style: (TextFont, TextLayout, LineHeight, Color, Color),
    colors: TransportColors,
) {
    let selected = find_descendant(root, fourcc!("tran"), children, tags);
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    for (index, binding) in TRANSPORT_ROWS.into_iter().enumerate() {
        let row = find_descendant(root, binding.tag, children, tags);
        commands.entity(row).insert((
            TransportDisplay::Row(binding.allocation),
            Hovered::default(),
        ));
        let left = find_descendant(row, fourcc!("left"), children, tags);
        let right = find_descendant(row, fourcc!("rght"), children, tags);
        commands
            .entity(left)
            .insert(TransportAdjust {
                allocation: binding.allocation,
                delta: -1,
            })
            .observe(on_transport_arrow_activate);
        commands
            .entity(right)
            .insert(TransportAdjust {
                allocation: binding.allocation,
                delta: 1,
            })
            .observe(on_transport_arrow_activate);
        let track_left = if index < LEFT_TRANSPORT_ROW_COUNT {
            0x61
        } else {
            0x5d
        };
        commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    width: percent(100),
                    height: percent(100),
                    ..default()
                },
                Pickable::IGNORE,
                ChildOf(row),
            ))
            .apply_scene(transport_row_overlay(
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
            commands
                .spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        width: percent(100),
                        height: percent(100),
                        ..default()
                    },
                    Pickable::IGNORE,
                    ChildOf(row),
                ))
                .apply_scene(transport_money_overlay(
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
    let (cursor_font, cursor_layout, cursor_line_height, cursor_color, cursor_shadow) =
        cursor_style;
    commands.entity(cursor).insert((
        Text::new(""),
        cursor_font,
        cursor_layout,
        cursor_line_height,
        TextColor(cursor_color),
        TextShadow {
            offset: Vec2::ONE,
            color: cursor_shadow,
        },
        TransportCursor,
    ));
    let treasury = find_descendant(root, fourcc!("trea"), children, tags);
    commands.entity(treasury).insert(TransportDisplay::Treasury);
}

fn transport_track(left: i32, color: Color, allocation: Option<TransportAllocation>) -> impl Scene {
    let display = allocation.map(|allocation| {
        bsn! {
            template(move |_context| Ok(TransportDisplay::Track(allocation)))
        }
    });
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
        {display}
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
            (transport_track(track_left, colors.empty, Some(allocation))),
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
            (transport_track(0x5d, colors.empty, None)),
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

fn on_transport_arrow_activate(
    activate: On<Activate>,
    actions: Query<&TransportAdjust, Without<InteractionDisabled>>,
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
                        *visibility = if status.adjustable {
                            Visibility::Visible
                        } else {
                            Visibility::Hidden
                        };
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
                if !status.adjustable {
                    *visibility = Visibility::Hidden;
                    continue;
                }
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
    mut rows: Query<(
        Entity,
        &TransportDisplay,
        &mut Visibility,
        Has<InteractionDisabled>,
    )>,
    actions: Query<(Entity, &TransportAdjust, Has<InteractionDisabled>)>,
) {
    if !session.is_changed() && screens.is_empty() {
        return;
    }
    let nation = MajorNationId::from_nation(session.0.turn().active_nation)
        .expect("Transport screen requires an active major nation");
    for (entity, display, mut visibility, disabled) in &mut rows {
        let allocation = match *display {
            TransportDisplay::Row(allocation)
            | TransportDisplay::RowCaption(allocation)
            | TransportDisplay::Track(allocation) => allocation,
            TransportDisplay::Money { resource, .. } => match resource {
                ResourceKind::Gold => TransportAllocation::GOLD,
                ResourceKind::Gems => TransportAllocation::GEMS,
                _ => unreachable!("only gold and gems have transport money captions"),
            },
            _ => continue,
        };
        let status = session.0.transport_row_status(nation, allocation);
        *visibility = if status.adjustable {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        if status.adjustable == disabled {
            if status.adjustable {
                commands.entity(entity).remove::<InteractionDisabled>();
            } else {
                commands.entity(entity).insert(InteractionDisabled);
            }
        }
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
    rows: Query<(&TransportHoverText, &Hovered)>,
    mut cursor: Query<&mut Text, With<TransportCursor>>,
) {
    if !session.is_changed() && screens.is_empty() && changed_rows.is_empty() {
        return;
    }
    let Ok(mut text) = cursor.single_mut() else {
        return;
    };
    text.0 = rows
        .iter()
        .find_map(|(hover, hovered)| hovered.get().then_some(hover.0.clone()))
        .unwrap_or_default();
}

fn transport_hover_text(
    assets: &RetailUiAssets,
    state: &GameState,
    nation: MajorNationId,
    allocation: TransportAllocation,
) -> String {
    let major = state.nations().major(nation);
    let city = &major.city;
    let economy = &major.economy;
    let (resource, _) = allocation.resources();
    let name = if allocation == TransportAllocation::COTTON_AND_WOOL {
        transport_string(assets, 2)
    } else if allocation == TransportAllocation::FISH_AND_LIVESTOCK {
        transport_string(assets, 3)
    } else {
        assets
            .string(0x2711, resource as i16 + 1)
            .expect("retail transport commodity name must load")
    };

    if allocation == TransportAllocation::GOLD || allocation == TransportAllocation::GEMS {
        let unit_value = if allocation == TransportAllocation::GOLD {
            200
        } else {
            500
        };
        return fill_brackets(
            &transport_string(assets, 9),
            &[&name, &format_currency(unit_value)],
        );
    }

    let stock = allocation_amount(allocation, |resource| city.stockpile[resource]);
    let building =
        |slot| city.building_type(slot, economy, major.common.owned_region_count() as i32);
    let needed = if allocation == TransportAllocation::COTTON_AND_WOOL {
        Some(building(CityFacilitySlot::TextileMill) * 2)
    } else if allocation == TransportAllocation::TIMBER {
        Some(building(CityFacilitySlot::LumberMill) * 2)
    } else if allocation == TransportAllocation::COAL || allocation == TransportAllocation::IRON {
        Some(building(CityFacilitySlot::SteelMill))
    } else if allocation == TransportAllocation::OIL {
        Some(building(CityFacilitySlot::OilRefinery) * 2)
    } else if allocation == TransportAllocation::FABRIC {
        Some(building(CityFacilitySlot::ClothingFactory) * 2)
    } else if allocation == TransportAllocation::LUMBER {
        Some(building(CityFacilitySlot::FurnitureFactory) * 2)
    } else if allocation == TransportAllocation::STEEL {
        Some(building(CityFacilitySlot::Metalworks) * 2)
    } else if allocation == TransportAllocation::FUEL {
        Some(building(CityFacilitySlot::PowerPlant) * 2)
    } else if allocation == TransportAllocation::GRAIN {
        Some(city.population.predicted_need(ResourceKind::Grain))
    } else if allocation == TransportAllocation::FRUIT {
        Some(city.population.predicted_need(ResourceKind::Fruit))
    } else if allocation == TransportAllocation::FISH_AND_LIVESTOCK {
        Some(city.population.predicted_need(ResourceKind::Livestock))
    } else {
        None
    };

    if let Some(needed) = needed {
        fill_brackets(
            &transport_string(assets, 7),
            &[&name, &stock.to_string(), &needed.to_string()],
        )
    } else {
        let available = state.transport_row_status(nation, allocation).available;
        fill_brackets(
            &transport_string(assets, 8),
            &[&name, &available.to_string()],
        )
    }
}

fn transport_string(assets: &RetailUiAssets, offset: i16) -> String {
    assets
        .string(0x2735, offset + 1)
        .expect("retail transport string must load")
}

fn fill_brackets(template: &str, args: &[&str]) -> String {
    let mut output = template.to_owned();
    for (index, value) in args.iter().enumerate() {
        let slot = index + 1;
        let Some(start) = output.find(&format!("[{slot}:")) else {
            continue;
        };
        let end = output[start..]
            .find(']')
            .map(|end| start + end)
            .expect("retail bracket expression must close");
        output.replace_range(start..=end, value);
    }
    output
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

#[cfg(test)]
mod tests {
    use super::*;
    use bevy::asset::AssetPlugin;
    use bevy::camera::NormalizedRenderTarget;
    use bevy::picking::backend::HitData;
    use bevy::picking::pointer::{Location, PointerId};
    use bevy::scene::ScenePlugin;
    use bevy::ui::Pressed;
    use bevy::ui_widgets::{Button as UiButton, ButtonPlugin};
    use std::time::Duration;

    #[derive(Component)]
    struct TestTransportRoot;

    fn random_game_names() -> RandomGameNames {
        let mut localized_nation_names = NationTable::default();
        let mut province_names_by_nation = NationTable::default();
        for nation in NationId::all() {
            localized_nation_names[nation] = format!("N{}", nation.get());
            let count = if MajorNationId::from_nation(nation).is_some() {
                8
            } else {
                4
            };
            province_names_by_nation[nation] = (0..count)
                .map(|ordinal| format!("N{}P{}", nation.get(), ordinal + 1))
                .collect();
        }
        RandomGameNames {
            localized_nation_names,
            province_names_by_nation,
            zone_headline_templates: (0..24).map(|status| format!("S{status} [1]")).collect(),
            fallback_ocean_names: (0..37).map(|index| format!("Ocean{index}")).collect(),
        }
    }

    fn fixture_state() -> GameState {
        let nation = MajorNationId::new(6);
        let mut sea_zone_marker_crt = RetailCrtRng::from_state(1);
        let _ = sea_zone_marker_crt.next_rand();
        let preview = generate_random_setup_preview_with_clock_seed(
            b"Woopnist",
            MapTopology::Wrapping,
            1,
            sea_zone_marker_crt,
        );
        let mut state = create_random_game(
            &preview,
            nation,
            Difficulty::Easy,
            "Testland",
            true,
            1,
            &random_game_names(),
        );
        state.rebuild_nation_resource_yields(nation);
        state
    }

    fn spawn_transport_hierarchy(world: &mut World) {
        let root = world
            .spawn((TestTransportRoot, TransportScreen, Node::default()))
            .id();
        for tag in [
            fourcc!("tran"),
            fourcc!("tota"),
            fourcc!("curs"),
            fourcc!("trea"),
        ] {
            world.spawn((RetailTag(tag), Node::default(), ChildOf(root)));
        }
        for binding in TRANSPORT_ROWS {
            let row = world
                .spawn((RetailTag(binding.tag), Node::default(), ChildOf(root)))
                .id();
            world.spawn((
                RetailTag(fourcc!("left")),
                UiButton,
                Node::default(),
                ChildOf(row),
            ));
            world.spawn((
                RetailTag(fourcc!("rght")),
                UiButton,
                Node::default(),
                ChildOf(row),
            ));
        }
    }

    fn bind_test_transport(
        mut commands: Commands,
        root: Single<Entity, Added<TestTransportRoot>>,
        children: Query<&Children>,
        tags: Query<&RetailTag>,
    ) {
        bind_transport_controls(
            &mut commands,
            *root,
            &children,
            &tags,
            TextFont::default(),
            TextLayout::default(),
            LineHeight::default(),
            (
                TextFont::default(),
                TextLayout::default(),
                LineHeight::default(),
                Color::WHITE,
                Color::BLACK,
            ),
            TransportColors {
                allocation: Color::WHITE,
                empty: Color::BLACK,
                below_limit: Color::WHITE,
                at_limit: Color::BLACK,
            },
        );
    }

    fn click_button(app: &mut App, entity: Entity) {
        let location = Location {
            target: NormalizedRenderTarget::None {
                width: 640,
                height: 480,
            },
            position: Vec2::ZERO,
        };
        let hit = HitData {
            camera: Entity::PLACEHOLDER,
            depth: 0.0,
            position: None,
            normal: None,
            extra: None,
        };
        app.world_mut().commands().trigger(Pointer::new(
            PointerId::Mouse,
            location.clone(),
            Press {
                button: PointerButton::Primary,
                hit: hit.clone(),
                count: 1,
            },
            entity,
        ));
        app.world_mut().flush();
        app.world_mut().flush();
        assert!(app.world().get::<Pressed>(entity).is_some());
        app.world_mut().commands().trigger(Pointer::new(
            PointerId::Mouse,
            location.clone(),
            Click {
                button: PointerButton::Primary,
                hit: hit.clone(),
                duration: Duration::ZERO,
                count: 1,
            },
            entity,
        ));
        app.world_mut().flush();
        app.world_mut().flush();
        app.world_mut().commands().trigger(Pointer::new(
            PointerId::Mouse,
            location,
            Release {
                button: PointerButton::Primary,
                hit,
            },
            entity,
        ));
        app.world_mut().flush();
        app.world_mut().flush();
        app.update();
        assert!(app.world().get::<Pressed>(entity).is_none());
    }

    #[test]
    fn clicking_generated_arrows_updates_allocation_and_caption() {
        let state = fixture_state();
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
        let binding = TRANSPORT_ROWS
            .into_iter()
            .find(|binding| {
                state
                    .transport_row_status(nation, binding.allocation)
                    .can_increase
            })
            .expect("retail beginning-of-game fixture has an adjustable transport row");
        let before = state.transport_row_status(nation, binding.allocation);

        let mut app = App::new();
        app.add_plugins((
            MinimalPlugins,
            AssetPlugin::default(),
            ScenePlugin,
            ButtonPlugin,
        ))
        .insert_resource(GameSession(state))
        .add_systems(
            Update,
            (
                bind_test_transport,
                sync_transport_text,
                sync_transport_visual,
                sync_transport_presence,
            )
                .chain(),
        );
        spawn_transport_hierarchy(app.world_mut());
        app.update();

        let row = app
            .world_mut()
            .query::<(Entity, &RetailTag)>()
            .iter(app.world())
            .find_map(|(entity, tag)| (tag.0 == binding.tag).then_some(entity))
            .unwrap();
        let mut arrows = app
            .world_mut()
            .query::<(Entity, &RetailTag, &ChildOf)>()
            .iter(app.world())
            .filter_map(|(entity, tag, parent)| (parent.parent() == row).then_some((tag.0, entity)))
            .collect::<Vec<_>>();
        let left = arrows
            .iter()
            .find_map(|(tag, entity)| (*tag == fourcc!("left")).then_some(*entity))
            .unwrap();
        let right = arrows
            .drain(..)
            .find_map(|(tag, entity)| (tag == fourcc!("rght")).then_some(entity))
            .unwrap();
        assert_eq!(app.world().get::<TransportAdjust>(left).unwrap().delta, -1);
        assert_eq!(app.world().get::<TransportAdjust>(right).unwrap().delta, 1);
        assert_eq!(
            app.world_mut()
                .query::<&TransportAdjust>()
                .iter(app.world())
                .count(),
            TRANSPORT_ROWS.len() * 2
        );

        click_button(&mut app, right);

        let after = app
            .world()
            .resource::<GameSession>()
            .0
            .transport_row_status(nation, binding.allocation);
        assert_eq!(after.allocated, before.allocated + 1);
        let (gauge, visibility, color) = app
            .world_mut()
            .query::<(&TransportDisplay, &Node, &Visibility, &BackgroundColor)>()
            .iter(app.world())
            .find_map(|(display, node, visibility, color)| match display {
                TransportDisplay::Gauge {
                    kind: TransportGaugeKind::Allocation(allocation),
                    ..
                } if *allocation == binding.allocation => Some((node, visibility, color)),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            gauge.width,
            Val::Px(transport_gauge_width(after.allocated, after.available))
        );
        assert_eq!(*visibility, Visibility::Visible);
        assert_eq!(color.0, Color::WHITE);
        let caption = app
            .world_mut()
            .query::<(&TransportDisplay, &Text)>()
            .iter(app.world())
            .find_map(|(display, text)| match display {
                TransportDisplay::RowCaption(allocation) if *allocation == binding.allocation => {
                    Some(text.0.clone())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(
            caption,
            format!("{}  /  {}", after.allocated, after.available)
        );

        click_button(&mut app, left);
        let restored = app
            .world()
            .resource::<GameSession>()
            .0
            .transport_row_status(nation, binding.allocation);
        assert_eq!(restored.allocated, before.allocated);
        let caption = app
            .world_mut()
            .query::<(&TransportDisplay, &Text)>()
            .iter(app.world())
            .find_map(|(display, text)| match display {
                TransportDisplay::RowCaption(allocation) if *allocation == binding.allocation => {
                    Some(text.0.clone())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(
            caption,
            format!("{}  /  {}", restored.allocated, restored.available)
        );
    }
}
