use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use crate::AppState;
use crate::RetailAssetsResource;
use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::format_currency;
use crate::ui::hover_help::HoverHelpText;
use crate::ui::map_help;
use crate::ui::query_floater::bind_query_floater_control;
use crate::ui::retail::RetailTree;
use crate::ui::strategic_map::{StrategicMapSession, StrategicSelection};
use bevy::prelude::*;
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::Activate;
use imperialism_core::TurnAlert;
use imperialism_formats::{FourCc, TRADE, fourcc};
use std::collections::VecDeque;

#[derive(Component)]
pub(crate) struct GameStatusView {
    date: Entity,
    treasury: Entity,
}

pub(crate) struct GameShellPlugin;

impl Plugin for GameShellPlugin {
    fn build(&self, app: &mut App) {
        map_help::register(app);
        app.add_systems(
            Update,
            render_game_status.run_if(resource_exists::<GameSession>),
        )
        .add_systems(
            Update,
            (
                sync_status_date_hover,
                spawn_turn_alerts_if_pending,
                bind_turn_alert_notice,
                bind_turn_summary_notice,
            )
                .chain()
                .run_if(in_state(AppState::StrategicMap)),
        );
    }
}

pub(crate) fn bind_game_status_display(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let (season_font, season_layout, season_line_height, _) = assets.text_style(
        imperialism_formats::RetailTextStylePreset::explicit(1, 0, 12, -2),
    );
    let (treasury_font, treasury_layout, treasury_line_height, _) = assets.text_style(
        imperialism_formats::RetailTextStylePreset::explicit(1, 0, 12, 1),
    );
    // Retail draws the nominal text first, then its offset "shadow" copy over it.
    // Bevy draws shadows behind text, so use the retail shadow as the visible face.
    let text_color = assets.palette_color(0x28);
    let shadow_color = assets.palette_color(0);
    let date = bind_status_text(
        commands,
        root,
        tree,
        fourcc!("seas"),
        season_font,
        season_layout,
        season_line_height,
        text_color,
        shadow_color,
    );
    let treasury = bind_status_text(
        commands,
        root,
        tree,
        fourcc!("trea"),
        treasury_font,
        treasury_layout,
        treasury_line_height,
        text_color,
        shadow_color,
    );
    commands
        .entity(root)
        .insert(GameStatusView { date, treasury });
}

fn render_game_status(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    views: Query<Ref<GameStatusView>>,
    mut texts: Query<&mut Text>,
) {
    let session_changed = session.is_changed();
    let date = {
        let season = retail.ui_string(10_000, (session.game.turn().economic_turn % 4) as u16);
        format!("{season}, {}", 1815 + session.game.turn().economic_turn / 4)
    };
    let nation = session.active_major_nation();
    let treasury = format_currency(session.game.nations().major(nation).common.treasury);
    for view in &views {
        if !session_changed && !view.is_added() {
            continue;
        }
        texts
            .get_mut(view.date)
            .expect("bound status date text")
            .0
            .clone_from(&date);
        texts
            .get_mut(view.treasury)
            .expect("bound status treasury text")
            .0 = treasury.clone();
    }
}

#[allow(clippy::too_many_arguments)]
fn bind_status_text(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    tag: FourCc,
    font: TextFont,
    layout: TextLayout,
    line_height: bevy::text::LineHeight,
    text_color: Color,
    shadow_color: Color,
) -> Entity {
    let entity = tree.find(root, tag);
    commands.entity(entity).insert((
        Text::default(),
        font,
        layout,
        line_height,
        TextColor(text_color),
        TextShadow {
            offset: Vec2::ONE,
            color: shadow_color,
        },
    ));
    entity
}

fn sync_status_date_hover(
    map: Res<StrategicMapSession>,
    assets: RetailUiAssets,
    mut views: Query<&GameStatusView>,
    mut texts: Query<&mut HoverHelpText>,
) {
    if !map.is_changed() {
        return;
    }
    let help = if matches!(map.selection, StrategicSelection::Army(_)) {
        assets.get_string(0x2732, 0x11)
    } else {
        format!(
            "{}, {}",
            assets.get_string(0x2730, 0x12),
            assets.get_string(0x2730, 8)
        )
    };
    for view in &mut views {
        texts
            .get_mut(view.date)
            .expect("bound status date text")
            .0
            .clone_from(&help);
    }
}

pub(crate) fn bind_native_game_screen_nav(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    toolbar_tag: FourCc,
    leave_toolbar_tag: Option<FourCc>,
    query_floater: bool,
    current: AppState,
) {
    if query_floater {
        bind_query_floater_control(commands, root, tree);
    }
    let toolbar = tree.find(root, toolbar_tag);
    let trade = tree.find(toolbar, TRADE);
    let transport = tree.find(toolbar, fourcc!("tran"));
    let city = tree.find(toolbar, fourcc!("city"));
    let diplomacy = tree.find(toolbar, fourcc!("dipl"));
    for (entity, destination) in [
        (trade, AppState::Trade),
        (transport, AppState::Transport),
        (city, AppState::City),
        (diplomacy, AppState::Diplomacy),
    ] {
        if destination == current {
            commands
                .entity(entity)
                .insert((Checked, InteractionDisabled));
            continue;
        }
        commands
            .entity(entity)
            .remove::<Checked>()
            .remove::<InteractionDisabled>()
            .observe(
                move |_: On<Activate>, mut next_state: ResMut<NextState<AppState>>| {
                    next_state.set(destination);
                },
            );
    }
    if let Some(leave_toolbar_tag) = leave_toolbar_tag {
        let toolbar = tree.find(root, leave_toolbar_tag);
        let leave = tree.find(toolbar, fourcc!("end "));
        commands
            .entity(leave)
            .remove::<InteractionDisabled>()
            .observe(
                move |_: On<Activate>,
                      state: Res<State<AppState>>,
                      mut next_state: ResMut<NextState<AppState>>| {
                    if AppState::StrategicMap != *state.get() {
                        next_state.set(AppState::StrategicMap);
                    }
                },
            );
    }
}

#[derive(Component)]
struct TurnAlertNotice(TurnAlert);

#[derive(Resource)]
pub(crate) struct TurnAlertQueue(pub(crate) VecDeque<TurnAlert>);

#[derive(Component)]
pub(crate) struct TurnSummaryNotice(pub(crate) String);

fn spawn_turn_alerts_if_pending(
    mut commands: Commands,
    queue: Option<Res<TurnAlertQueue>>,
    existing: Query<(), With<TurnAlertNotice>>,
) {
    let Some(alert) = queue.as_deref().and_then(|queue| queue.0.front()).copied() else {
        return;
    };
    if !existing.is_empty() {
        return;
    }
    spawn_linger_dialog(
        &mut commands,
        TurnAlertNotice(alert),
        AppState::StrategicMap,
    );
}

fn bind_turn_alert_notice(
    mut commands: Commands,
    notice: Option<Single<(Entity, &TurnAlertNotice), Added<TurnAlertNotice>>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    let Some(root) = notice else {
        return;
    };
    let (root, notice) = root.into_inner();
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    let [title_id, body_id] = turn_alert_strings(notice.0);
    let title = assets.string(title_id);
    let body = assets.string(body_id);
    linger.set_title(&mut commands, &mut assets, title);
    linger.set_body(&mut commands, &mut assets, body);
    commands
        .entity(linger.okay)
        .remove::<InteractionDisabled>()
        .observe(on_turn_alert_dismiss);
    commands.entity(linger.cancel).insert(Visibility::Hidden);
}

fn turn_alert_strings(alert: TurnAlert) -> [imperialism_formats::StringResourceId; 2] {
    use imperialism_formats::StringGroup;
    const TURN_ALERTS: StringGroup = StringGroup::new(0x2753);
    let (title, body) = match alert {
        TurnAlert::LandCapitolThreatened => (0x28, 0x29),
        TurnAlert::NavalCapitolThreatened => (0x2a, 0x2b),
        TurnAlert::Treasury { prompt_code } => ((prompt_code - 1) as u16, prompt_code as u16),
        TurnAlert::CommodityShortage => (0x46, 0x47),
        TurnAlert::TransportShortage => (0x22, 0x23),
        TurnAlert::Starvation => (0x20, 0x21),
    };
    [TURN_ALERTS.entry(title), TURN_ALERTS.entry(body)]
}

fn bind_turn_summary_notice(
    mut commands: Commands,
    notice: Option<Single<(Entity, &TurnSummaryNotice), Added<TurnSummaryNotice>>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    let Some(notice) = notice else {
        return;
    };
    let (root, notice) = notice.into_inner();
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    linger.set_title(&mut commands, &mut assets, "Imperialism");
    linger.set_body(&mut commands, &mut assets, &notice.0);
    commands.entity(linger.okay).remove::<InteractionDisabled>();
    commands.entity(linger.cancel).insert(Visibility::Hidden);
}

fn on_turn_alert_dismiss(_activate: On<Activate>, mut queue: ResMut<TurnAlertQueue>) {
    queue
        .0
        .pop_front()
        .expect("turn-alert dismissal requires a pending alert");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::retail::RetailTag;

    #[test]
    fn management_nav_marks_only_the_current_screen_checked() {
        #[derive(Component)]
        struct TestNavRoot;

        fn bind_city_nav(
            mut commands: Commands,
            root: Single<Entity, Added<TestNavRoot>>,
            tree: RetailTree,
        ) {
            bind_native_game_screen_nav(
                &mut commands,
                *root,
                &tree,
                fourcc!("topB"),
                None,
                false,
                AppState::City,
            );
        }

        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_systems(Update, bind_city_nav);
        let root = app.world_mut().spawn((TestNavRoot, Node::default())).id();
        let toolbar = app
            .world_mut()
            .spawn((RetailTag(fourcc!("topB")), Node::default(), ChildOf(root)))
            .id();
        for tag in [TRADE, fourcc!("tran"), fourcc!("city"), fourcc!("dipl")] {
            app.world_mut()
                .spawn((RetailTag(tag), Node::default(), ChildOf(toolbar)));
        }
        app.update();

        let mut checked = Vec::new();
        let mut enabled = Vec::new();
        let nav_tags = [TRADE, fourcc!("tran"), fourcc!("city"), fourcc!("dipl")];
        for (tag, has_checked, disabled) in app
            .world_mut()
            .query::<(&RetailTag, Has<Checked>, Has<InteractionDisabled>)>()
            .iter(app.world())
        {
            if !nav_tags.contains(&tag.0) {
                continue;
            }
            if has_checked {
                checked.push(tag.0);
            }
            if !disabled {
                enabled.push(tag.0);
            }
        }
        assert_eq!(checked, vec![fourcc!("city")]);
        assert_eq!(enabled.len(), 3);
        assert!(!enabled.contains(&fourcc!("city")));
    }
}
