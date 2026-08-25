use super::GameSession;
use super::RetailUiAssets;
use super::fill_brackets;
use super::format_currency;
use super::game_shell::{bind_game_status_display, bind_native_game_screen_nav};
use super::generated;
use super::retail_raster::IndexedRasterExt;
use crate::AppState;
use crate::RetailAssetsResource;
use bevy::picking::hover::Hovered;
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::Activate;
use imperialism_core::*;
use imperialism_formats::*;

#[derive(Clone, Copy)]
struct TransportRowControls {
    allocation: TransportAllocation,
    row: Entity,
    text: Entity,
    left: Entity,
    rght: Entity,
    valu: Option<Entity>,
}

fn transport_row(
    allocation: TransportAllocation,
    row: Entity,
    text: Entity,
    left: Entity,
    rght: Entity,
    valu: Option<Entity>,
) -> TransportRowControls {
    TransportRowControls {
        allocation,
        row,
        text,
        left,
        rght,
        valu,
    }
}

fn transport_2014_rows(ui: generated::Transport2014) -> [TransportRowControls; 18] {
    [
        transport_row(
            TransportAllocation::FISH_AND_LIVESTOCK,
            ui.fish,
            ui.fish_text,
            ui.fish_left,
            ui.fish_rght,
            None,
        ),
        transport_row(
            TransportAllocation::FRUIT,
            ui.prod,
            ui.prod_text,
            ui.prod_left,
            ui.prod_rght,
            None,
        ),
        transport_row(
            TransportAllocation::GRAIN,
            ui.grai,
            ui.grai_text,
            ui.grai_left,
            ui.grai_rght,
            None,
        ),
        transport_row(
            TransportAllocation::TIMBER,
            ui.timb,
            ui.timb_text,
            ui.timb_left,
            ui.timb_rght,
            None,
        ),
        transport_row(
            TransportAllocation::LUMBER,
            ui.lumb,
            ui.lumb_text,
            ui.lumb_left,
            ui.lumb_rght,
            None,
        ),
        transport_row(
            TransportAllocation::FURNITURE,
            ui.furn,
            ui.furn_text,
            ui.furn_left,
            ui.furn_rght,
            None,
        ),
        transport_row(
            TransportAllocation::COAL,
            ui.coal,
            ui.coal_text,
            ui.coal_left,
            ui.coal_rght,
            None,
        ),
        transport_row(
            TransportAllocation::IRON,
            ui.iron,
            ui.iron_text,
            ui.iron_left,
            ui.iron_rght,
            None,
        ),
        transport_row(
            TransportAllocation::STEEL,
            ui.stee,
            ui.stee_text,
            ui.stee_left,
            ui.stee_rght,
            None,
        ),
        transport_row(
            TransportAllocation::HARDWARE,
            ui.hard,
            ui.hard_text,
            ui.hard_left,
            ui.hard_rght,
            None,
        ),
        transport_row(
            TransportAllocation::COTTON_AND_WOOL,
            ui.cott,
            ui.cott_text,
            ui.cott_left,
            ui.cott_rght,
            None,
        ),
        transport_row(
            TransportAllocation::FABRIC,
            ui.fabr,
            ui.fabr_text,
            ui.fabr_left,
            ui.fabr_rght,
            None,
        ),
        transport_row(
            TransportAllocation::CLOTHING,
            ui.clot,
            ui.clot_text,
            ui.clot_left,
            ui.clot_rght,
            None,
        ),
        transport_row(
            TransportAllocation::OIL,
            ui.oil,
            ui.oil_text,
            ui.oil_left,
            ui.oil_rght,
            None,
        ),
        transport_row(
            TransportAllocation::FUEL,
            ui.fuel,
            ui.fuel_text,
            ui.fuel_left,
            ui.fuel_rght,
            None,
        ),
        transport_row(
            TransportAllocation::HORSES,
            ui.hors,
            ui.hors_text,
            ui.hors_left,
            ui.hors_rght,
            None,
        ),
        transport_row(
            TransportAllocation::GOLD,
            ui.gold,
            ui.gold_text,
            ui.gold_left,
            ui.gold_rght,
            Some(ui.gold_valu),
        ),
        transport_row(
            TransportAllocation::GEMS,
            ui.gems,
            ui.gems_text,
            ui.gems_left,
            ui.gems_rght,
            Some(ui.gems_valu),
        ),
    ]
}

const LEFT_TRANSPORT_ROW_COUNT: usize = 10;

#[derive(Component)]
struct TransportScreen;

#[derive(Component, Clone, Copy)]
struct TransportAdjust {
    allocation: TransportAllocation,
    delta: i16,
}

#[derive(Component, Clone, Copy)]
struct TransportHover(TransportAllocation);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportGaugeKind {
    Allocation(TransportAllocation),
    Capacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransportGaugeKey {
    value: i16,
    total: i16,
    limit: Option<i16>,
}

#[derive(Component)]
struct TransportGaugeVisual {
    kind: TransportGaugeKind,
    track_left: i32,
    base: IndexedPicture,
    rendered: Option<TransportGaugeKey>,
}

#[derive(Component)]
struct TransportCursor;

#[derive(Component, Clone, Copy)]
enum TransportDisplay {
    Row(TransportAllocation),
    RowCaption(TransportAllocation),
    CapacityCaption,
    Money {
        resource: ResourceKind,
        unit_value: i32,
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
                sync_transport_gauges,
                sync_transport_presence,
                sync_transport_cursor,
            )
                .run_if(in_state(AppState::Transport)),
        );
    }
}

fn enter_transport_screen(mut commands: Commands) {
    let ui = generated::spawn_transport_2014(&mut commands);
    commands
        .entity(ui.root)
        .insert((TransportScreen, ui, DespawnOnExit(AppState::Transport)));
}

fn bind_transport_screen(
    mut commands: Commands,
    ui: Single<&generated::Transport2014, Added<TransportScreen>>,
    mut assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
) {
    let ui = **ui;
    bind_native_game_screen_nav(
        &mut commands,
        ui.trad,
        ui.tran,
        ui.city,
        ui.dipl,
        Some(ui.end),
        Some(ui.quer),
    );

    let nation = session.active_major_nation();
    session.game.rebuild_nation_resource_yields(nation);
    bind_game_status_display(&mut commands, &mut assets, ui.seas, ui.trea);
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
    let rows = transport_2014_rows(ui);
    bind_transport_controls(
        &mut commands,
        ui.tran,
        ui.tota_text,
        ui.curs,
        rows,
        cursor_style,
    );
    for (index, row) in rows.into_iter().enumerate() {
        commands
            .entity(row.row)
            .insert(TransportHover(row.allocation));
        install_transport_gauge(
            &mut commands,
            &mut assets,
            row.row,
            TransportGaugeKind::Allocation(row.allocation),
            if index < LEFT_TRANSPORT_ROW_COUNT {
                0x61
            } else {
                0x5d
            },
            PictureId::new(4001 + index as i16),
        );
    }
    install_transport_gauge(
        &mut commands,
        &mut assets,
        ui.tota,
        TransportGaugeKind::Capacity,
        0x5d,
        PictureId::new(4019),
    );
}

fn bind_transport_controls(
    commands: &mut Commands,
    tran: Entity,
    tota_text: Entity,
    curs: Entity,
    rows: [TransportRowControls; 18],
    cursor_style: (TextFont, TextLayout, LineHeight, Color, Color),
) {
    commands.entity(tran).insert((Checked, InteractionDisabled));
    for row in rows {
        commands
            .entity(row.row)
            .insert((TransportDisplay::Row(row.allocation), Hovered::default()));
        commands
            .entity(row.left)
            .insert(TransportAdjust {
                allocation: row.allocation,
                delta: -1,
            })
            .observe(on_transport_arrow_activate);
        commands
            .entity(row.rght)
            .insert(TransportAdjust {
                allocation: row.allocation,
                delta: 1,
            })
            .observe(on_transport_arrow_activate);
        commands
            .entity(row.text)
            .insert(TransportDisplay::RowCaption(row.allocation));
        if let Some((resource, unit_value, valu)) = if row.allocation == TransportAllocation::GOLD {
            row.valu.map(|valu| (ResourceKind::Gold, 200, valu))
        } else if row.allocation == TransportAllocation::GEMS {
            row.valu.map(|valu| (ResourceKind::Gems, 500, valu))
        } else {
            None
        } {
            commands.entity(valu).insert(TransportDisplay::Money {
                resource,
                unit_value,
            });
        }
    }

    commands
        .entity(tota_text)
        .insert(TransportDisplay::CapacityCaption);
    let (cursor_font, cursor_layout, cursor_line_height, cursor_color, cursor_shadow) =
        cursor_style;
    commands.entity(curs).insert((
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
}

fn install_transport_gauge(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    kind: TransportGaugeKind,
    track_left: i32,
    picture_id: PictureId,
) {
    let base = assets
        .indexed_picture(picture_id)
        .expect("retail Transport picture must load");
    let palette = *assets.default_dib_palette();
    let image = assets.add_image(base.to_image(&palette));
    commands.entity(entity).insert((
        ImageNode::new(image),
        TransportGaugeVisual {
            kind,
            track_left,
            base,
            rendered: None,
        },
    ));
}

fn draw_transport_gauge(
    picture: &mut IndexedPicture,
    kind: TransportGaugeKind,
    track_left: i32,
    key: TransportGaugeKey,
) {
    let marker = track_left + transport_gauge_width(key.value, key.total) as i32;
    picture.fill_rect(IRect::new(marker, 0x0d, track_left + 0x71, 0x11), 0x3b);
    let fill = match kind {
        TransportGaugeKind::Allocation(_) => 0x3a,
        TransportGaugeKind::Capacity if key.value == key.total => 0x34,
        TransportGaugeKind::Capacity => 0x33,
    };
    picture.fill_rect(IRect::new(track_left, 0x0d, marker, 0x11), fill);
    if let Some(limit) = key.limit {
        picture.fill_rect(
            IRect::new(track_left - 1, 0x12, track_left + 0x72, 0x14),
            if key.value < limit { 0x33 } else { 0x34 },
        );
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
    let nation = session.active_major_nation();
    session
        .game
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
    let nation = session.active_major_nation();
    let major = session.game.nations().major(nation);
    let economy = &major.economy;
    for (display, mut text) in &mut texts {
        match *display {
            TransportDisplay::RowCaption(allocation) => {
                let status = session.game.transport_row_status(nation, allocation);
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
            _ => {}
        }
    }
}

fn sync_transport_gauges(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    screens: Query<(), Added<TransportScreen>>,
    mut gauges: Query<(&mut TransportGaugeVisual, &ImageNode)>,
) {
    if !session.is_changed() && screens.is_empty() {
        return;
    }
    let nation = session.active_major_nation();
    let economy = &session.game.nations().major(nation).economy;
    for (mut gauge, image_node) in &mut gauges {
        let key = match gauge.kind {
            TransportGaugeKind::Allocation(allocation) => {
                let status = session.game.transport_row_status(nation, allocation);
                TransportGaugeKey {
                    value: status.allocated,
                    total: status.available,
                    limit: status.limit,
                }
            }
            TransportGaugeKind::Capacity => TransportGaugeKey {
                value: economy.capacities.reserved_transport,
                total: economy.capacities.transport,
                limit: None,
            },
        };
        if gauge.rendered == Some(key) {
            continue;
        }
        let mut picture = gauge.base.clone();
        draw_transport_gauge(&mut picture, gauge.kind, gauge.track_left, key);
        if let Some(mut image) = images.get_mut(&image_node.image) {
            *image = picture.to_image(retail.assets().default_dib_palette());
            gauge.rendered = Some(key);
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
    let nation = session.active_major_nation();
    for (entity, display, mut visibility, disabled) in &mut rows {
        let allocation = match *display {
            TransportDisplay::Row(allocation) | TransportDisplay::RowCaption(allocation) => {
                allocation
            }
            TransportDisplay::Money { resource, .. } => match resource {
                ResourceKind::Gold => TransportAllocation::GOLD,
                ResourceKind::Gems => TransportAllocation::GEMS,
                _ => unreachable!("only gold and gems have transport money captions"),
            },
            _ => continue,
        };
        let status = session.game.transport_row_status(nation, allocation);
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
        let status = session.game.transport_row_status(nation, action.allocation);
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
    rows: Query<(&TransportHover, &Hovered)>,
    assets: RetailUiAssets,
    mut cursor: Query<&mut Text, With<TransportCursor>>,
) {
    if !session.is_changed() && screens.is_empty() && changed_rows.is_empty() {
        return;
    }
    let Ok(mut text) = cursor.single_mut() else {
        return;
    };
    let nation = session.active_major_nation();
    text.0 = rows
        .iter()
        .find_map(|(hover, hovered)| {
            hovered
                .get()
                .then(|| transport_hover_text(&assets, &session.game, nation, hover.0))
        })
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
    use super::super::retail_raster::indexed_picture;
    use super::*;
    use bevy::asset::AssetPlugin;
    use bevy::scene::ScenePlugin;

    #[derive(Component)]
    struct TestTransportRoot;

    const TEST_TRANSPORT_ALLOCATIONS: [TransportAllocation; 18] = [
        TransportAllocation::FISH_AND_LIVESTOCK,
        TransportAllocation::FRUIT,
        TransportAllocation::GRAIN,
        TransportAllocation::TIMBER,
        TransportAllocation::LUMBER,
        TransportAllocation::FURNITURE,
        TransportAllocation::COAL,
        TransportAllocation::IRON,
        TransportAllocation::STEEL,
        TransportAllocation::HARDWARE,
        TransportAllocation::COTTON_AND_WOOL,
        TransportAllocation::FABRIC,
        TransportAllocation::CLOTHING,
        TransportAllocation::OIL,
        TransportAllocation::FUEL,
        TransportAllocation::HORSES,
        TransportAllocation::GOLD,
        TransportAllocation::GEMS,
    ];

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

    fn spawn_child(world: &mut World, parent: Entity) -> Entity {
        world.spawn((Node::default(), ChildOf(parent))).id()
    }

    fn spawn_text(world: &mut World, parent: Entity) -> Entity {
        world
            .spawn((Node::default(), Text::default(), ChildOf(parent)))
            .id()
    }

    #[derive(Component)]
    struct TestTransportBindings {
        tran: Entity,
        tota_text: Entity,
        curs: Entity,
        rows: [TransportRowControls; 18],
    }

    fn spawn_transport_hierarchy(world: &mut World) {
        let root = world
            .spawn((TestTransportRoot, TransportScreen, Node::default()))
            .id();
        let tran = spawn_child(world, root);
        let curs = spawn_text(world, root);
        let tota_text = spawn_text(world, root);
        let rows = TEST_TRANSPORT_ALLOCATIONS.map(|allocation| {
            let row = spawn_child(world, root);
            transport_row(
                allocation,
                row,
                spawn_text(world, row),
                spawn_child(world, row),
                spawn_child(world, row),
                matches!(
                    allocation,
                    TransportAllocation::GOLD | TransportAllocation::GEMS
                )
                .then(|| spawn_text(world, row)),
            )
        });
        world.entity_mut(root).insert(TestTransportBindings {
            tran,
            tota_text,
            curs,
            rows,
        });
    }

    fn bind_test_transport(
        mut commands: Commands,
        root: Single<&TestTransportBindings, Added<TestTransportRoot>>,
    ) {
        bind_transport_controls(
            &mut commands,
            root.tran,
            root.tota_text,
            root.curs,
            root.rows,
            (
                TextFont::default(),
                TextLayout::default(),
                LineHeight::default(),
                Color::WHITE,
                Color::BLACK,
            ),
        );
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    #[test]
    fn activating_generated_arrows_updates_allocation_and_caption() {
        let state = fixture_state();
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
        let allocation = TEST_TRANSPORT_ALLOCATIONS
            .into_iter()
            .find(|&allocation| state.transport_row_status(nation, allocation).can_increase)
            .expect("retail beginning-of-game fixture has an adjustable transport row");
        let before = state.transport_row_status(nation, allocation);

        let mut app = App::new();
        app.add_plugins((MinimalPlugins, AssetPlugin::default(), ScenePlugin))
            .insert_resource(GameSession::new(state))
            .add_systems(
                Update,
                (
                    bind_test_transport,
                    sync_transport_text,
                    sync_transport_presence,
                )
                    .chain(),
            );
        spawn_transport_hierarchy(app.world_mut());
        app.update();

        let left = app
            .world_mut()
            .query::<(Entity, &TransportAdjust)>()
            .iter(app.world())
            .find_map(|(entity, action)| {
                (action.allocation == allocation && action.delta == -1).then_some(entity)
            })
            .unwrap();
        let right = app
            .world_mut()
            .query::<(Entity, &TransportAdjust)>()
            .iter(app.world())
            .find_map(|(entity, action)| {
                (action.allocation == allocation && action.delta == 1).then_some(entity)
            })
            .unwrap();
        assert_eq!(
            app.world_mut()
                .query::<&TransportAdjust>()
                .iter(app.world())
                .count(),
            TEST_TRANSPORT_ALLOCATIONS.len() * 2
        );

        activate(&mut app, right);

        let after = app
            .world()
            .resource::<GameSession>()
            .game
            .transport_row_status(nation, allocation);
        assert_eq!(after.allocated, before.allocated + 1);
        let caption = app
            .world_mut()
            .query::<(&TransportDisplay, &Text)>()
            .iter(app.world())
            .find_map(|(display, text)| match display {
                TransportDisplay::RowCaption(candidate) if *candidate == allocation => {
                    Some(text.0.clone())
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(
            caption,
            format!("{}  /  {}", after.allocated, after.available)
        );

        activate(&mut app, left);
        let restored = app
            .world()
            .resource::<GameSession>()
            .game
            .transport_row_status(nation, allocation);
        assert_eq!(restored.allocated, before.allocated);
        let caption = app
            .world_mut()
            .query::<(&TransportDisplay, &Text)>()
            .iter(app.world())
            .find_map(|(display, text)| match display {
                TransportDisplay::RowCaption(candidate) if *candidate == allocation => {
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

    #[test]
    fn transport_picture_draws_gauge_and_limit_into_its_own_raster() {
        let mut picture = indexed_picture(224, 30, 0);
        draw_transport_gauge(
            &mut picture,
            TransportGaugeKind::Allocation(TransportAllocation::GRAIN),
            0x61,
            TransportGaugeKey {
                value: 2,
                total: 4,
                limit: Some(3),
            },
        );

        let width = picture.width as usize;
        assert_eq!(picture.pixels[0x0d * width + 0x61], 0x3a);
        assert_eq!(picture.pixels[0x0d * width + 0x61 + 55], 0x3a);
        assert_eq!(picture.pixels[0x0d * width + 0x61 + 56], 0x3b);
        assert_eq!(picture.pixels[0x12 * width + 0x60], 0x33);

        draw_transport_gauge(
            &mut picture,
            TransportGaugeKind::Capacity,
            0x5d,
            TransportGaugeKey {
                value: 4,
                total: 4,
                limit: None,
            },
        );
        assert_eq!(picture.pixels[0x0d * width + 0x5d], 0x34);
        assert_eq!(picture.pixels[0x0d * width + 0x5d + 112], 0x34);
    }
}
