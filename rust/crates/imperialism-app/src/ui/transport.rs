use super::GameSession;
use super::RetailUiAssets;
use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::hover_help::HoverHelpText;
use super::retail::{
    RetailTransportGaugeKind, RetailTree, TransportGaugeParts, transport_gauge_width,
};
use super::retail_resources::ResourceKindRetailResources;
use super::retail_transport_gauge::{
    TRANSPORT_GAUGE_FULL_PALETTE, TRANSPORT_GAUGE_PARTIAL_PALETTE,
};
use crate::AppState;
use bevy::prelude::*;
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

#[derive(Component)]
struct TransportScreen;

#[derive(Clone, Copy)]
struct TransportGaugeView {
    fill: Entity,
    limit: Entity,
    caption: Entity,
    kind: RetailTransportGaugeKind,
}

#[derive(Clone, Copy)]
struct TransportRowView {
    row: Entity,
    decrease: Entity,
    increase: Entity,
    gauge: TransportGaugeView,
    money: Option<Entity>,
}

#[derive(Component)]
struct TransportView {
    capacity: TransportGaugeView,
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
            render_transport.run_if(in_state(AppState::Transport)),
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
    gauges: Query<&TransportGaugeParts>,
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
    // HoverHelpBar comes from codegen; curs text style is still binder-owned until a
    // recovered Transport DoPostCreate delta lands (same InitializeMapHint pair as prefs).
    let curs = tree.find(*root, fourcc!("curs"));
    let (cursor_font, cursor_layout, cursor_line_height, _) = assets
        .text_style(RetailTextStylePreset::explicit(1, 0, 12, 1))
        .expect("retail transport cursor text style");
    commands.entity(curs).insert((
        cursor_font,
        cursor_layout,
        cursor_line_height,
        TextColor(assets.palette_color(0x28)),
        TextShadow {
            offset: Vec2::ONE,
            color: assets.palette_color(0),
        },
    ));
    let view = bind_transport_view(&mut commands, *root, &tree, &gauges);
    commands.entity(*root).insert(view);
}

fn bind_gauge_view(
    tree: &RetailTree,
    gauges: &Query<&TransportGaugeParts>,
    entity: Entity,
) -> TransportGaugeView {
    let parts = *gauges
        .get(entity)
        .expect("bound transport gauge must exist");
    TransportGaugeView {
        fill: parts.fill,
        limit: parts.limit,
        caption: tree.find(entity, fourcc!("text")),
        kind: parts.kind,
    }
}

fn bind_transport_view(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    gauges: &Query<&TransportGaugeParts>,
) -> TransportView {
    let selected = tree.find(root, fourcc!("tran"));
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));
    let capacity = bind_gauge_view(tree, gauges, tree.find(root, fourcc!("tota")));
    let rows = std::array::from_fn(|index| {
        let binding = TRANSPORT_ROWS[index];
        let row = tree.find(root, binding.tag);
        commands.entity(row).insert(HoverHelpText(String::new()));
        let decrease = tree.find(row, fourcc!("left"));
        let increase = tree.find(row, fourcc!("rght"));
        commands.entity(decrease).observe(
            move |activate: On<Activate>,
                  disabled: Query<Has<InteractionDisabled>>,
                  mut session: ResMut<GameSession>| {
                if disabled.get(activate.entity).unwrap_or(false) {
                    return;
                }
                let nation = session.active_major_nation();
                session
                    .game
                    .step_transport_allocation(nation, binding.allocation, -1);
            },
        );
        commands.entity(increase).observe(
            move |activate: On<Activate>,
                  disabled: Query<Has<InteractionDisabled>>,
                  mut session: ResMut<GameSession>| {
                if disabled.get(activate.entity).unwrap_or(false) {
                    return;
                }
                let nation = session.active_major_nation();
                session
                    .game
                    .step_transport_allocation(nation, binding.allocation, 1);
            },
        );
        let money = match binding.allocation {
            TransportAllocation::GOLD | TransportAllocation::GEMS => {
                Some(tree.find(row, fourcc!("valu")))
            }
            _ => None,
        };
        TransportRowView {
            row,
            decrease,
            increase,
            gauge: bind_gauge_view(tree, gauges, row),
            money,
        }
    });
    TransportView { capacity, rows }
}

fn render_transport(
    session: Res<GameSession>,
    view: Single<Ref<TransportView>>,
    mut commands: Commands,
    mut texts: Query<&mut Text>,
    mut help: Query<&mut HoverHelpText>,
    mut nodes: Query<&mut Node>,
    mut backgrounds: Query<&mut BackgroundColor>,
    assets: RetailUiAssets,
) {
    if !session.is_changed() && !view.is_added() {
        return;
    }
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let economy = &major.economy;
    let partial = assets.palette_color(TRANSPORT_GAUGE_PARTIAL_PALETTE);
    let full = assets.palette_color(TRANSPORT_GAUGE_FULL_PALETTE);
    for (binding, row) in TRANSPORT_ROWS.iter().zip(&view.rows) {
        let status = session
            .game
            .transport_row_status(nation, binding.allocation);
        help.get_mut(row.row)
            .expect("bound transport hover help must exist")
            .0 = transport_hover_text(&assets, &session.game, nation, binding.allocation);
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
        write_transport_gauge(
            &row.gauge,
            status.allocated,
            status.available,
            status.limit,
            &mut nodes,
            &mut texts,
            &mut backgrounds,
            &mut commands,
            partial,
            full,
        );
    }
    let capacities = economy.capacities;
    write_transport_gauge(
        &view.capacity,
        capacities.reserved_transport,
        capacities.transport,
        None,
        &mut nodes,
        &mut texts,
        &mut backgrounds,
        &mut commands,
        partial,
        full,
    );
}

fn write_transport_gauge(
    gauge: &TransportGaugeView,
    current: i16,
    total: i16,
    limit: Option<i16>,
    nodes: &mut Query<&mut Node>,
    texts: &mut Query<&mut Text>,
    backgrounds: &mut Query<&mut BackgroundColor>,
    commands: &mut Commands,
    partial: Color,
    full: Color,
) {
    nodes
        .get_mut(gauge.fill)
        .expect("transport gauge fill")
        .width = Val::Px(transport_gauge_width(current, total));
    texts
        .get_mut(gauge.caption)
        .expect("transport gauge caption")
        .0 = format!("{current}  /  {total}");
    match gauge.kind {
        RetailTransportGaugeKind::Allocation => match limit {
            Some(limit) => {
                commands.entity(gauge.limit).insert(Visibility::Visible);
                backgrounds
                    .get_mut(gauge.limit)
                    .expect("transport gauge limit")
                    .0 = if current < limit { partial } else { full };
            }
            None => {
                commands.entity(gauge.limit).insert(Visibility::Hidden);
            }
        },
        RetailTransportGaugeKind::Capacity => {
            backgrounds
                .get_mut(gauge.fill)
                .expect("transport gauge fill colour")
                .0 = if total > 0 && current == total {
                full
            } else {
                partial
            };
        }
    }
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
        assets.string(resource.name_string())
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
    assets.get_string(0x2735, offset as u16)
}

fn allocation_amount(
    allocation: TransportAllocation,
    mut amount: impl FnMut(ResourceKind) -> i16,
) -> i16 {
    let (primary, secondary) = allocation.resources();
    amount(primary) + secondary.map_or(0, amount)
}

#[cfg(test)]
mod tests {
    use super::super::retail::{RetailTag, RetailTransportGaugeKind};
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
        let fill = world.spawn(Node::default()).id();
        let limit = world.spawn(Node::default()).id();
        let total = world
            .spawn((
                RetailTag(fourcc!("tota")),
                Node::default(),
                TransportGaugeParts {
                    kind: RetailTransportGaugeKind::Capacity,
                    fill,
                    limit,
                },
                ChildOf(root),
            ))
            .id();
        world.spawn((
            RetailTag(fourcc!("text")),
            Node::default(),
            Text::default(),
            ChildOf(total),
        ));
        for binding in TRANSPORT_ROWS {
            let fill = world.spawn(Node::default()).id();
            let limit = world.spawn(Node::default()).id();
            let row = world
                .spawn((
                    RetailTag(binding.tag),
                    Node::default(),
                    TransportGaugeParts {
                        kind: RetailTransportGaugeKind::Allocation,
                        fill,
                        limit,
                    },
                    ChildOf(root),
                ))
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
        gauges: Query<&TransportGaugeParts>,
    ) {
        let view = bind_transport_view(&mut commands, *root, &tree, &gauges);
        commands.entity(*root).insert(view);
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    #[test]
    fn transport_arrows_update_the_allocation() {
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
            .add_systems(Update, bind_test_transport);
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

        activate(&mut app, row.decrease);
        let restored = app
            .world()
            .resource::<GameSession>()
            .game
            .transport_row_status(nation, binding.allocation);
        assert_eq!(restored.allocated, before.allocated);
    }
}
