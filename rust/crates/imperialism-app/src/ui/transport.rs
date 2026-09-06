use super::GameSession;
use super::RetailUiAssets;
use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::hover_help::HoverHelpText;
use super::retail::{RetailTree, TransportGaugeParts, transport_gauge_width};
use super::retail_resources::ResourceKindRetailResources;
use super::retail_transport_gauge::{
    TRANSPORT_GAUGE_FULL_PALETTE, TRANSPORT_GAUGE_PARTIAL_PALETTE,
};
use crate::AppState;
use crate::ui::retail::Step;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
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
    track: Entity,
    fill: Entity,
    limit: Option<Entity>,
    caption: Entity,
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
        AppState::Transport,
    );

    let nation = session.active_major_nation();
    session.game.rebuild_nation_resource_yields(nation);
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);
    // HoverHelpBar + curs style come from codegen (same as other management screens).
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
        track: parts.track,
        fill: parts.fill,
        limit: parts.limit,
        caption: tree.find(entity, fourcc!("text")),
    }
}

fn bind_transport_view(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    gauges: &Query<&TransportGaugeParts>,
) -> TransportView {
    let capacity = bind_gauge_view(tree, gauges, tree.find(root, fourcc!("tota")));
    let rows = std::array::from_fn(|index| {
        let binding = TRANSPORT_ROWS[index];
        let row = tree.find(root, binding.tag);
        commands.entity(row).insert(HoverHelpText(String::new()));
        let [decrease, increase] =
            [(fourcc!("left"), -1), (fourcc!("rght"), 1)].map(|(tag, delta)| {
                let step = tree.find(row, tag);
                commands.entity(step).observe(
                    move |step_event: On<Step>,
                          disabled: Query<Has<InteractionDisabled>>,
                          mut session: ResMut<GameSession>| {
                        if disabled.get(step_event.entity).unwrap_or(false) {
                            return;
                        }
                        let nation = session.active_major_nation();
                        session
                            .game
                            .step_transport_allocation(nation, binding.allocation, delta);
                    },
                );
                step
            });
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
        write_allocation_gauge(
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
    write_capacity_gauge(
        &view.capacity,
        capacities.reserved_transport,
        capacities.transport,
        &mut nodes,
        &mut texts,
        &mut backgrounds,
        partial,
        full,
    );
}

fn write_allocation_gauge(
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
    let (visible, limit_visible) = allocation_gauge_visibility(total, limit.is_some());
    set_transport_visibility(commands, gauge.track, visible);
    set_transport_visibility(commands, gauge.fill, visible);
    if let Some(limit_entity) = gauge.limit {
        set_transport_visibility(commands, limit_entity, limit_visible);
        if let Some(limit) = limit.filter(|_| visible) {
            backgrounds
                .get_mut(limit_entity)
                .expect("transport gauge limit")
                .0 = if current < limit { partial } else { full };
        }
    }
}

fn write_capacity_gauge(
    gauge: &TransportGaugeView,
    current: i16,
    total: i16,
    nodes: &mut Query<&mut Node>,
    texts: &mut Query<&mut Text>,
    backgrounds: &mut Query<&mut BackgroundColor>,
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
    backgrounds
        .get_mut(gauge.fill)
        .expect("transport gauge fill colour")
        .0 = if total > 0 && current == total {
        full
    } else {
        partial
    };
}

fn set_transport_visibility(commands: &mut Commands, entity: Entity, visible: bool) {
    commands.entity(entity).insert(if visible {
        Visibility::Visible
    } else {
        Visibility::Hidden
    });
}

const fn allocation_gauge_visibility(total: i16, has_limit: bool) -> (bool, bool) {
    let chrome = total > 0;
    (chrome, chrome && has_limit)
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
    use super::*;
    #[test]
    fn zero_total_allocation_gauge_hides_all_chrome() {
        assert_eq!(allocation_gauge_visibility(0, true), (false, false));
        assert_eq!(allocation_gauge_visibility(10, true), (true, true));
        assert_eq!(allocation_gauge_visibility(10, false), (true, false));
    }
}
