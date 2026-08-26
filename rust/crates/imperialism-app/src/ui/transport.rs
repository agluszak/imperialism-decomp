use super::GameSession;
use super::RetailUiAssets;
use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::retail::RetailTree;
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

#[derive(Component)]
struct TransportScreen;

#[derive(Clone, Copy)]
struct TransportRowView {
    row: Entity,
    caption: Entity,
    decrease: Entity,
    increase: Entity,
    gauge: TransportGaugeView,
    money: Option<Entity>,
}

#[derive(Clone, Copy)]
struct TransportGaugeView {
    fill: Entity,
    limit: Option<Entity>,
}

/// Palette colors resolved once during binding for the recovered gauge states.
#[derive(Clone, Copy)]
struct TransportGaugeColors {
    allocation: Color,
    remainder: Color,
    partial: Color,
    full: Color,
}

/// The gauge colors that change while the screen lives: capacity fill and
/// row limit strips alternate between `partial` and `full`.
#[derive(Clone, Copy)]
struct TransportGaugeStates {
    partial: Color,
    full: Color,
}

#[derive(Component)]
struct TransportView {
    cursor: Entity,
    capacity: TransportGaugeView,
    capacity_caption: Entity,
    gauge_states: TransportGaugeStates,
    rows: [TransportRowView; TRANSPORT_ROWS.len()],
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
            (render_transport, sync_transport_cursor).run_if(in_state(AppState::Transport)),
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
    tree: RetailTree,
    mut assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        *root,
        &tree,
        fourcc!("topB"),
        Some(fourcc!("tool")),
        true,
    );

    let nation = session.active_major_nation();
    session.game.rebuild_nation_resource_yields(nation);
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);
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
    let gauge_colors = TransportGaugeColors {
        allocation: assets.palette_color(0x3a),
        remainder: assets.palette_color(0x3b),
        partial: assets.palette_color(0x33),
        full: assets.palette_color(0x34),
    };
    let view = bind_transport_view(&mut commands, *root, &tree, cursor_style, gauge_colors);
    commands.entity(*root).insert(view);
}

fn bind_transport_view(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    cursor_style: (TextFont, TextLayout, LineHeight, Color, Color),
    gauge_colors: TransportGaugeColors,
) -> TransportView {
    let selected = tree.find(root, fourcc!("tran"));
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    let (cursor_font, cursor_layout, cursor_line_height, cursor_color, cursor_shadow) =
        cursor_style;
    let cursor = tree.find(root, fourcc!("curs"));
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
    ));
    let capacity = tree.find(root, fourcc!("tota"));
    let capacity_caption = tree.find(capacity, fourcc!("text"));
    let capacity = install_transport_gauge(
        commands,
        capacity,
        0x5d,
        false,
        gauge_colors.partial,
        gauge_colors,
    );
    let rows = std::array::from_fn(|index| {
        let binding = TRANSPORT_ROWS[index];
        let row = tree.find(root, binding.tag);
        commands.entity(row).insert(Hovered::default());
        let decrease = tree.find(row, fourcc!("left"));
        let increase = tree.find(row, fourcc!("rght"));
        commands
            .entity(decrease)
            .observe(on_transport_arrow_activate);
        commands
            .entity(increase)
            .observe(on_transport_arrow_activate);
        let caption = tree.find(row, fourcc!("text"));
        let money = match binding.allocation {
            TransportAllocation::GOLD | TransportAllocation::GEMS => {
                Some(tree.find(row, fourcc!("valu")))
            }
            _ => None,
        };
        let track_left = if index < LEFT_TRANSPORT_ROW_COUNT {
            0x61
        } else {
            0x5d
        };
        let gauge = install_transport_gauge(
            commands,
            row,
            track_left,
            true,
            gauge_colors.allocation,
            gauge_colors,
        );
        TransportRowView {
            row,
            caption,
            decrease,
            increase,
            gauge,
            money,
        }
    });
    TransportView {
        cursor,
        capacity,
        capacity_caption,
        gauge_states: TransportGaugeStates {
            partial: gauge_colors.partial,
            full: gauge_colors.full,
        },
        rows,
    }
}

/// Overlays the recovered gauge fill, remainder, and optional limit strip as
/// native nodes above the static gauge background. `track_left` locates the
/// 113-pixel track; the remainder fills the whole track and the fill node
/// covers its left portion, so rendering only updates the fill width.
fn install_transport_gauge(
    commands: &mut Commands,
    entity: Entity,
    track_left: i32,
    limit_strip: bool,
    fill_color: Color,
    gauge_colors: TransportGaugeColors,
) -> TransportGaugeView {
    let mut node = |left: i32, top: i32, width: f32, height: f32, color: Color| {
        commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px(left as f32),
                    top: px(top as f32),
                    width: px(width),
                    height: px(height),
                    ..default()
                },
                BackgroundColor(color),
                Pickable::IGNORE,
                ChildOf(entity),
            ))
            .id()
    };
    let _remainder = node(
        track_left,
        0x0d,
        0x71 as f32,
        0x04 as f32,
        gauge_colors.remainder,
    );
    let fill = node(track_left, 0x0d, 0.0, 0x04 as f32, fill_color);
    let limit = limit_strip.then(|| {
        node(
            track_left - 1,
            0x12,
            0x73 as f32,
            0x02 as f32,
            gauge_colors.partial,
        )
    });
    TransportGaugeView { fill, limit }
}

fn on_transport_arrow_activate(
    activate: On<Activate>,
    views: Query<&TransportView>,
    disabled: Query<Has<InteractionDisabled>>,
    mut session: ResMut<GameSession>,
) {
    if disabled.get(activate.entity).unwrap_or(false) {
        return;
    }
    let nation = session.active_major_nation();
    for view in &views {
        for (binding, row) in TRANSPORT_ROWS.iter().zip(&view.rows) {
            if activate.entity == row.decrease {
                session
                    .game
                    .step_transport_allocation(nation, binding.allocation, -1);
                return;
            }
            if activate.entity == row.increase {
                session
                    .game
                    .step_transport_allocation(nation, binding.allocation, 1);
                return;
            }
        }
    }
}

fn render_transport(
    session: Res<GameSession>,
    view: Single<Ref<TransportView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut nodes: Query<&mut Node>,
    mut backgrounds: Query<&mut BackgroundColor>,
) {
    if !session.is_changed() && !view.is_added() {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let economy = &major.economy;
    for (binding, row) in TRANSPORT_ROWS.iter().zip(&view.rows) {
        let status = session
            .game
            .transport_row_status(nation, binding.allocation);
        texts
            .get_mut(row.caption)
            .expect("bound transport caption must exist")
            .0 = format!("{}  /  {}", status.allocated, status.available);
        if let Some(money) = row.money {
            let (resource, unit_value) = match binding.allocation {
                TransportAllocation::GOLD => (ResourceKind::Gold, 200),
                TransportAllocation::GEMS => (ResourceKind::Gems, 500),
                _ => unreachable!("only gold and gems have transport money captions"),
            };
            let target = economy.need_target_by_type[resource];
            texts
                .get_mut(money)
                .expect("bound transport money text must exist")
                .0 = format_currency(i32::from(target) * unit_value);
        }
        set_transport_visibility(&mut commands, row.row, status.adjustable);
        set_transport_enabled(&mut commands, row.decrease, status.can_decrease);
        set_transport_enabled(&mut commands, row.increase, status.can_increase);
        nodes
            .get_mut(row.gauge.fill)
            .expect("bound transport gauge fill must exist")
            .width = px(transport_gauge_width(status.allocated, status.available));
        if let Some(limit) = row.gauge.limit {
            match status.limit {
                Some(limit_value) => {
                    commands.entity(limit).insert(Visibility::Visible);
                    backgrounds
                        .get_mut(limit)
                        .expect("bound transport gauge limit must exist")
                        .0 = if status.allocated < limit_value {
                        view.gauge_states.partial
                    } else {
                        view.gauge_states.full
                    };
                }
                None => {
                    commands.entity(limit).insert(Visibility::Hidden);
                }
            }
        }
    }
    let capacities = economy.capacities;
    texts
        .get_mut(view.capacity_caption)
        .expect("bound transport capacity caption must exist")
        .0 = format!(
        "{}  /  {}",
        capacities.reserved_transport, capacities.transport
    );
    nodes
        .get_mut(view.capacity.fill)
        .expect("bound transport capacity gauge must exist")
        .width = px(transport_gauge_width(
        capacities.reserved_transport,
        capacities.transport,
    ));
    backgrounds
        .get_mut(view.capacity.fill)
        .expect("bound transport capacity gauge must exist")
        .0 = if capacities.reserved_transport == capacities.transport {
        view.gauge_states.full
    } else {
        view.gauge_states.partial
    };
}

fn set_transport_visibility(commands: &mut Commands, entity: Entity, visible: bool) {
    commands.entity(entity).insert(if visible {
        Visibility::Visible
    } else {
        Visibility::Hidden
    });
}

fn set_transport_enabled(commands: &mut Commands, entity: Entity, enabled: bool) {
    if enabled {
        commands.entity(entity).remove::<InteractionDisabled>();
    } else {
        commands.entity(entity).insert(InteractionDisabled);
    }
}

fn sync_transport_cursor(
    session: Res<GameSession>,
    views: Query<Ref<TransportView>>,
    hovered: Query<Ref<Hovered>>,
    assets: RetailUiAssets,
    mut cursor: Query<&mut Text>,
) {
    let Ok(view) = views.single() else {
        return;
    };
    if !session.is_changed()
        && !view.is_added()
        && !view.rows.iter().any(|row| {
            hovered
                .get(row.row)
                .is_ok_and(|hovered| hovered.is_changed())
        })
    {
        return;
    }
    let nation = session.active_major_nation();
    let Some(allocation) = TRANSPORT_ROWS
        .iter()
        .zip(&view.rows)
        .find_map(|(binding, row)| {
            hovered
                .get(row.row)
                .is_ok_and(|hovered| hovered.get())
                .then_some(binding.allocation)
        })
    else {
        cursor
            .get_mut(view.cursor)
            .expect("bound transport cursor text must exist")
            .0 = String::new();
        return;
    };
    cursor
        .get_mut(view.cursor)
        .expect("bound transport cursor text must exist")
        .0 = transport_hover_text(&assets, &session.game, nation, allocation);
}

fn transport_hover_text(
    assets: &RetailUiAssets,
    state: &GameState,
    nation: MajorNationId,
    allocation: TransportAllocation,
) -> String {
    let major = state.nations().major(nation);
    let city = &major.city;
    let (resource, _) = allocation.resources();
    let name = if allocation == TransportAllocation::COTTON_AND_WOOL {
        transport_string(assets, 2)
    } else if allocation == TransportAllocation::FISH_AND_LIVESTOCK {
        transport_string(assets, 3)
    } else {
        assets
            .string(0x2711, i16::from(resource.retail()) + 1)
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
    let needed = state.transport_requirement(nation, allocation);

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
    use super::super::retail::RetailTag;
    use super::*;
    use bevy::asset::AssetPlugin;
    use bevy::scene::ScenePlugin;

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

    fn spawn_transport_hierarchy(world: &mut World) -> Entity {
        let root = world
            .spawn((TestTransportRoot, TransportScreen, Node::default()))
            .id();
        for tag in [fourcc!("tran"), fourcc!("curs"), fourcc!("trea")] {
            world.spawn((RetailTag(tag), Node::default(), ChildOf(root)));
        }
        let total = world
            .spawn((RetailTag(fourcc!("tota")), Node::default(), ChildOf(root)))
            .id();
        world.spawn((
            RetailTag(fourcc!("text")),
            Node::default(),
            Text::default(),
            ChildOf(total),
        ));
        for binding in TRANSPORT_ROWS {
            let row = world
                .spawn((RetailTag(binding.tag), Node::default(), ChildOf(root)))
                .id();
            world.spawn((RetailTag(fourcc!("left")), Node::default(), ChildOf(row)));
            world.spawn((RetailTag(fourcc!("rght")), Node::default(), ChildOf(row)));
            world.spawn((
                RetailTag(fourcc!("text")),
                Node::default(),
                Text::default(),
                ChildOf(row),
            ));
            if matches!(
                binding.allocation,
                TransportAllocation::GOLD | TransportAllocation::GEMS
            ) {
                world.spawn((
                    RetailTag(fourcc!("valu")),
                    Node::default(),
                    Text::default(),
                    ChildOf(row),
                ));
            }
        }
        root
    }

    fn bind_test_transport(
        mut commands: Commands,
        root: Single<Entity, Added<TestTransportRoot>>,
        tree: RetailTree,
    ) {
        let gauge_colors = TransportGaugeColors {
            allocation: Color::srgb_u8(0, 0, 255),
            remainder: Color::srgb_u8(128, 128, 128),
            partial: Color::WHITE,
            full: Color::BLACK,
        };
        let view = bind_transport_view(
            &mut commands,
            *root,
            &tree,
            (
                TextFont::default(),
                TextLayout::default(),
                LineHeight::default(),
                Color::WHITE,
                Color::BLACK,
            ),
            gauge_colors,
        );
        commands.entity(*root).insert(view);
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    #[test]
    fn transport_arrows_update_allocation_caption_and_gauge() {
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
        app.add_plugins((MinimalPlugins, AssetPlugin::default(), ScenePlugin))
            .insert_resource(GameSession::new(state))
            .add_systems(Update, (bind_test_transport, render_transport).chain());
        let root = spawn_transport_hierarchy(app.world_mut());
        app.update();

        let row = TRANSPORT_ROWS
            .iter()
            .zip(&app.world().get::<TransportView>(root).unwrap().rows)
            .find_map(|(candidate, row)| (candidate.tag == binding.tag).then_some(*row))
            .unwrap();

        activate(&mut app, row.increase);
        let after = app
            .world()
            .resource::<GameSession>()
            .game
            .transport_row_status(nation, binding.allocation);
        assert_eq!(after.allocated, before.allocated + 1);
        assert_eq!(
            app.world().get::<Text>(row.caption).unwrap().0,
            format!("{}  /  {}", after.allocated, after.available)
        );
        assert_eq!(
            app.world().get::<Node>(row.gauge.fill).unwrap().width,
            px(transport_gauge_width(after.allocated, after.available))
        );

        activate(&mut app, row.decrease);
        let restored = app
            .world()
            .resource::<GameSession>()
            .game
            .transport_row_status(nation, binding.allocation);
        assert_eq!(restored.allocated, before.allocated);
    }
}
