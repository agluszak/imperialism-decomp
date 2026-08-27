use super::generated;
use super::retail::{RetailTree, ancestor_with};
use super::{RetailUiAssets, fill_brackets};
use crate::{AppState, RetailAssetsResource};
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, Button as UiButton};
use imperialism_formats::{FourCc, RetailTextStylePreset, fourcc};

const TERRAIN_HELP_SETS: [i16; 5] = [0x0bc2, 0x0bcc, 0x0c94, 0x0c9e, 0x0ca8];
const CITY_HELP_SETS: [i16; 3] = [0x0bd6, 0x0c44, 0x0c4e];
const TRADE_HELP_SETS: [i16; 2] = [0x0bea, 0x0bf4];
const DIPLOMACY_HELP_SETS: [i16; 2] = [0x0bfe, 0x0c26];
const TRANSPORT_HELP_SETS: [i16; 1] = [0x0c3a];
const TECHNOLOGY_HELP_SETS: [i16; 1] = [0x0c08];
const TACTICAL_HELP_SETS: [i16; 1] = [0x0c76];
const TOPICS: [FourCc; 5] = [
    fourcc!("nam1"),
    fourcc!("nam2"),
    fourcc!("nam3"),
    fourcc!("nam4"),
    fourcc!("nam5"),
];
const LINK_BLUE: Color = Color::srgb(0.05, 0.08, 0.65);

#[derive(Component)]
struct MapHelpRoot {
    context: HelpContext,
    set: usize,
    topic: Option<usize>,
}

#[derive(Clone, Copy)]
enum HelpContext {
    TerrainMap,
    City,
    Trade,
    Diplomacy,
    Transport,
    TechnologyStore,
    LandBattle,
}

impl HelpContext {
    const fn for_app_state(state: AppState) -> Option<Self> {
        match state {
            AppState::StrategicMap => Some(Self::TerrainMap),
            AppState::City => Some(Self::City),
            AppState::Trade => Some(Self::Trade),
            AppState::Diplomacy => Some(Self::Diplomacy),
            AppState::Transport => Some(Self::Transport),
            AppState::TechnologyStore => Some(Self::TechnologyStore),
            AppState::LandBattle => Some(Self::LandBattle),
            _ => None,
        }
    }

    const fn sets(self) -> &'static [i16] {
        match self {
            Self::TerrainMap => &TERRAIN_HELP_SETS,
            Self::City => &CITY_HELP_SETS,
            Self::Trade => &TRADE_HELP_SETS,
            Self::Diplomacy => &DIPLOMACY_HELP_SETS,
            Self::Transport => &TRANSPORT_HELP_SETS,
            Self::TechnologyStore => &TECHNOLOGY_HELP_SETS,
            Self::LandBattle => &TACTICAL_HELP_SETS,
        }
    }

    const fn event_code(self) -> i16 {
        match self {
            Self::TerrainMap => 0x07dd,
            Self::City => 0x07db,
            Self::Trade => 0x07d9,
            Self::Diplomacy => 0x07d8,
            Self::Transport => 0x07de,
            Self::TechnologyStore => 0x08fc,
            Self::LandBattle => 0x07e0,
        }
    }

    const fn topic_count(self, set: usize) -> usize {
        match self {
            Self::TerrainMap
            | Self::City
            | Self::Diplomacy
            | Self::Transport
            | Self::LandBattle => 5,
            Self::Trade if set == 1 => 4,
            Self::Trade => 5,
            Self::TechnologyStore => 4,
        }
    }

    const fn app_state(self) -> AppState {
        match self {
            Self::TerrainMap => AppState::StrategicMap,
            Self::City => AppState::City,
            Self::Trade => AppState::Trade,
            Self::Diplomacy => AppState::Diplomacy,
            Self::Transport => AppState::Transport,
            Self::TechnologyStore => AppState::TechnologyStore,
            Self::LandBattle => AppState::LandBattle,
        }
    }
}

#[derive(Component, Clone, Copy)]
enum MapHelpAction {
    Topic(usize),
    Topics,
    Previous,
    Next,
}

pub(crate) fn register(app: &mut App) {
    app.add_systems(Update, bind_added_help);
}

pub(crate) fn spawn(commands: &mut Commands, state: AppState) {
    let context = HelpContext::for_app_state(state).expect("game screen has a retail help context");
    spawn_for_context(commands, context);
}

pub(crate) fn spawn_technology(commands: &mut Commands) {
    spawn_for_context(commands, HelpContext::TechnologyStore);
}

fn spawn_for_context(commands: &mut Commands, context: HelpContext) {
    let root = commands.spawn_scene(generated::linger_3000()).id();
    commands.entity(root).insert((
        MapHelpRoot {
            context,
            set: 0,
            topic: None,
        },
        DespawnOnExit(context.app_state()),
    ));
}

fn bind_added_help(
    mut commands: Commands,
    roots: Query<(Entity, &MapHelpRoot), Added<MapHelpRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    retail: Res<RetailAssetsResource>,
) {
    for (root, state) in &roots {
        let view = tree.view(root);
        let context = state.context;
        let title = fill_brackets(
            &retail.get_string(0x2749, 6),
            &[&retail.get_string(0x2749, context.event_code() as u16)],
        );
        set_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("titl")),
            &title,
            12,
            1,
            Color::BLACK,
        );
        set_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("subj")),
            "",
            12,
            1,
            Color::BLACK,
        );
        set_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("swin")),
            "",
            12,
            3,
            Color::BLACK,
        );
        for (index, tag) in TOPICS.into_iter().enumerate() {
            spawn_link_button(&mut commands, view.find(tag), MapHelpAction::Topic(index));
        }
        for (tag, action) in [
            (fourcc!("togl"), MapHelpAction::Topics),
            (fourcc!("prev"), MapHelpAction::Previous),
            (fourcc!("next"), MapHelpAction::Next),
        ] {
            spawn_link_button(&mut commands, view.find(tag), action);
        }
        commands
            .entity(view.find(fourcc!("more")))
            .insert(Visibility::Hidden);
        let topics_label = assets.ui_string(0x2749, 9);
        set_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("togl")),
            &topics_label,
            12,
            3,
            LINK_BLUE,
        );

        show_topic_list_raw(root, context, 0, &tree, &retail, &mut commands);
    }
}

fn on_action(
    activate: On<Activate>,
    actions: Query<&MapHelpAction>,
    parents: Query<&ChildOf>,
    mut roots: Query<&mut MapHelpRoot>,
    assets: Res<RetailAssetsResource>,
    tree: RetailTree,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity).copied() else {
        return;
    };
    let Some(root) = ancestor_with(activate.entity, &parents, &roots) else {
        return;
    };
    let mut state = roots
        .get_mut(root)
        .expect("help action belongs to help root");
    apply_action(action, root, &mut state, &assets, &tree, &mut commands);
}

fn apply_action(
    action: MapHelpAction,
    root: Entity,
    state: &mut MapHelpRoot,
    assets: &RetailAssetsResource,
    tree: &RetailTree,
    commands: &mut Commands,
) {
    match action {
        MapHelpAction::Topic(topic) => {
            let view = tree.view(root);
            let group = state.context.sets()[state.set];
            state.topic = Some(topic);
            commands
                .entity(view.find(fourcc!("subj")))
                .insert(Text::new(assets.ui_string(group as u16, topic as u16 + 2)));
            commands.entity(view.find(fourcc!("swin"))).insert((
                Text::new(assets.text(group as u16 + topic as u16 + 1)),
                TextColor(Color::BLACK),
                Visibility::Visible,
            ));
            for tag in TOPICS {
                commands.entity(view.find(tag)).insert(Visibility::Hidden);
            }
            for tag in [fourcc!("prev"), fourcc!("next")] {
                commands.entity(view.find(tag)).insert(Visibility::Hidden);
            }
            commands
                .entity(view.find(fourcc!("togl")))
                .insert(Visibility::Visible);
        }
        MapHelpAction::Topics => {
            state.topic = None;
            show_topic_list_raw(root, state.context, state.set, tree, assets, commands);
        }
        MapHelpAction::Previous => {
            state.set = state.set.saturating_sub(1);
            state.topic = None;
            show_topic_list_raw(root, state.context, state.set, tree, assets, commands);
        }
        MapHelpAction::Next => {
            state.set = (state.set + 1).min(state.context.sets().len() - 1);
            state.topic = None;
            show_topic_list_raw(root, state.context, state.set, tree, assets, commands);
        }
    }
}

fn spawn_link_button(commands: &mut Commands, label: Entity, action: MapHelpAction) {
    commands
        .entity(label)
        .insert((UiButton, Pickable::default(), action))
        .observe(on_action);
}

fn show_topic_list_raw(
    root: Entity,
    context: HelpContext,
    set: usize,
    tree: &RetailTree,
    assets: &RetailAssetsResource,
    commands: &mut Commands,
) {
    let view = tree.view(root);
    let group = context.sets()[set];
    commands
        .entity(view.find(fourcc!("subj")))
        .insert(Text::new(assets.ui_string(group as u16, 1)));
    commands
        .entity(view.find(fourcc!("swin")))
        .insert(Visibility::Hidden);
    for (index, tag) in TOPICS.into_iter().enumerate() {
        commands.entity(view.find(tag)).insert((
            Text::new(assets.ui_string(group as u16, index as u16 + 2)),
            TextColor(LINK_BLUE),
            Underline,
            if index < context.topic_count(set) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            },
        ));
    }
    for (tag, index, visible) in [
        (fourcc!("prev"), 14, set > 0),
        (fourcc!("next"), 15, set + 1 < context.sets().len()),
    ] {
        commands.entity(view.find(tag)).insert((
            Text::new(assets.ui_string(0x2749, index)),
            TextColor(LINK_BLUE),
            Underline,
            if visible {
                Visibility::Visible
            } else {
                Visibility::Hidden
            },
        ));
    }
    commands
        .entity(view.find(fourcc!("togl")))
        .insert(Visibility::Hidden);
}

fn set_text(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    text: &str,
    size: i32,
    font_family: i32,
    color: Color,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset::explicit(font_family, 0, size, -2))
        .expect("retail map-help text style");
    commands
        .entity(entity)
        .insert((Text::new(text), font, layout, line_height, TextColor(color)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn game_screens_select_the_recovered_help_mgr_sets() {
        for (state, event_code, sets, topic_counts) in [
            (
                AppState::StrategicMap,
                0x07dd,
                TERRAIN_HELP_SETS.as_slice(),
                &[5, 5, 5, 5, 5][..],
            ),
            (
                AppState::City,
                0x07db,
                CITY_HELP_SETS.as_slice(),
                &[5, 5, 5][..],
            ),
            (
                AppState::Trade,
                0x07d9,
                TRADE_HELP_SETS.as_slice(),
                &[5, 4][..],
            ),
            (
                AppState::Diplomacy,
                0x07d8,
                DIPLOMACY_HELP_SETS.as_slice(),
                &[5, 5][..],
            ),
            (
                AppState::Transport,
                0x07de,
                TRANSPORT_HELP_SETS.as_slice(),
                &[5][..],
            ),
            (
                AppState::TechnologyStore,
                0x08fc,
                TECHNOLOGY_HELP_SETS.as_slice(),
                &[4][..],
            ),
        ] {
            let context = HelpContext::for_app_state(state).unwrap();
            assert_eq!(context.event_code(), event_code);
            assert_eq!(context.sets(), sets);
            assert_eq!(
                (0..sets.len())
                    .map(|set| context.topic_count(set))
                    .collect::<Vec<_>>(),
                topic_counts
            );
        }
    }
}
