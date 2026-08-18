use super::generated;
use super::retail::{ModalDialog, RetailTree, ancestor_with};
use super::{RetailUiAssets, fill_brackets};
use crate::{AppState, RetailAssetsResource};
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, ActivateOnPress, Button as UiButton};
use imperialism_formats::{FourCc, RetailTextStylePreset, fourcc};

const TERRAIN_HELP_SETS: [i16; 5] = [0x0bc2, 0x0bcc, 0x0c94, 0x0c9e, 0x0ca8];
const TECHNOLOGY_HELP_SETS: [i16; 1] = [0x0c08];
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
    context: MapHelpContext,
    set: usize,
    topic: Option<usize>,
}

#[derive(Clone, Copy)]
enum MapHelpContext {
    TerrainMap,
    TechnologyStore,
}

impl MapHelpContext {
    const fn sets(self) -> &'static [i16] {
        match self {
            Self::TerrainMap => &TERRAIN_HELP_SETS,
            Self::TechnologyStore => &TECHNOLOGY_HELP_SETS,
        }
    }

    const fn event_code(self) -> i16 {
        match self {
            Self::TerrainMap => 0x07dd,
            Self::TechnologyStore => 0x08fc,
        }
    }

    const fn topic_count(self) -> usize {
        match self {
            Self::TerrainMap => 5,
            Self::TechnologyStore => 4,
        }
    }

    const fn app_state(self) -> AppState {
        match self {
            Self::TerrainMap => AppState::StrategicMap,
            Self::TechnologyStore => AppState::TechnologyStore,
        }
    }
}

#[derive(Component, Clone, Copy)]
enum MapHelpAction {
    Topic(usize),
    Topics,
    Previous,
    Next,
    Close,
}

pub(crate) fn register(app: &mut App) {
    app.add_systems(Update, bind_added_help);
}

pub(crate) fn spawn(commands: &mut Commands) {
    spawn_for_context(commands, MapHelpContext::TerrainMap);
}

pub(crate) fn spawn_technology(commands: &mut Commands) {
    spawn_for_context(commands, MapHelpContext::TechnologyStore);
}

fn spawn_for_context(commands: &mut Commands, context: MapHelpContext) {
    let root = commands.spawn_scene(generated::linger_3000()).id();
    commands.entity(root).insert((
        MapHelpRoot {
            context,
            set: 0,
            topic: None,
        },
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(30),
        DespawnOnExit(context.app_state()),
    ));
}

fn bind_added_help(
    mut commands: Commands,
    roots: Query<(Entity, &MapHelpRoot), Added<MapHelpRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    retail: Res<RetailAssetsResource>,
    mut nodes: Query<&mut Node>,
) {
    for (root, state) in &roots {
        let view = tree.view(root);
        let window = view.find(fourcc!("WIND"));
        nodes.get_mut(window).expect("help window node").height = px(339);
        nodes
            .get_mut(view.find(fourcc!("DLOG")))
            .expect("help dialog node")
            .top = px(24);
        let context = state.context;
        let title = fill_brackets(
            &retail.get_string(0x2749, 6),
            &[&retail.get_string(0x2749, context.event_code())],
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
        let topics_label = assets.string(0x2749, 9).expect("retail show-topics label");
        set_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("togl")),
            &topics_label,
            12,
            3,
            LINK_BLUE,
        );

        let (close_font, close_layout, close_line_height, _) = assets
            .text_style(RetailTextStylePreset {
                font_family: 1,
                face_flags: 0,
                point_size: 12,
                alignment: 1,
            })
            .expect("retail help close-box style");

        commands.entity(window).with_children(|parent| {
            parent
                .spawn((
                    Node {
                        position_type: PositionType::Absolute,
                        left: px(0),
                        top: px(0),
                        width: px(390),
                        height: px(24),
                        border: UiRect::all(px(2)),
                        ..default()
                    },
                    BackgroundColor(Color::srgb(0.52, 0.52, 0.52)),
                    BorderColor::all(Color::WHITE),
                    Pickable::IGNORE,
                ))
                .with_children(|title| {
                    title
                        .spawn((
                            Node {
                                position_type: PositionType::Absolute,
                                right: px(4),
                                top: px(3),
                                width: px(18),
                                height: px(17),
                                border: UiRect::all(px(1)),
                                justify_content: JustifyContent::Center,
                                align_items: AlignItems::Center,
                                ..default()
                            },
                            UiButton,
                            ActivateOnPress,
                            MapHelpAction::Close,
                            ZIndex(1),
                            BackgroundColor(Color::srgb(0.82, 0.82, 0.82)),
                            BorderColor::all(Color::srgb(0.25, 0.25, 0.25)),
                        ))
                        .observe(on_action)
                        .with_child((
                            Text::new("×"),
                            close_font.clone(),
                            close_layout,
                            close_line_height,
                            TextColor(Color::BLACK),
                            Pickable::IGNORE,
                        ));
                });
        });
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
    if matches!(action, MapHelpAction::Close) {
        commands.entity(root).despawn();
        return;
    }
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
                .insert(Text::new(
                    assets
                        .string(group, topic as i16 + 2)
                        .expect("retail map-help topic"),
                ));
            commands.entity(view.find(fourcc!("swin"))).insert((
                Text::new(
                    assets
                        .text(group as u16 + topic as u16 + 1)
                        .expect("retail map-help body"),
                ),
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
        MapHelpAction::Close => unreachable!(),
    }
}

fn spawn_link_button(commands: &mut Commands, label: Entity, action: MapHelpAction) {
    commands
        .entity(label)
        .insert((UiButton, Pickable::default(), ActivateOnPress, action))
        .observe(on_action);
}

fn show_topic_list_raw(
    root: Entity,
    context: MapHelpContext,
    set: usize,
    tree: &RetailTree,
    assets: &RetailAssetsResource,
    commands: &mut Commands,
) {
    let view = tree.view(root);
    let group = context.sets()[set];
    commands
        .entity(view.find(fourcc!("subj")))
        .insert(Text::new(
            assets.string(group, 1).expect("retail map-help subject"),
        ));
    commands
        .entity(view.find(fourcc!("swin")))
        .insert(Visibility::Hidden);
    for (index, tag) in TOPICS.into_iter().enumerate() {
        commands.entity(view.find(tag)).insert((
            Text::new(
                assets
                    .string(group, index as i16 + 2)
                    .expect("retail map-help topic"),
            ),
            TextColor(LINK_BLUE),
            Underline,
            if index < context.topic_count() {
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
            Text::new(
                assets
                    .string(0x2749, index)
                    .expect("retail map-help navigation label"),
            ),
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
        .text_style(RetailTextStylePreset {
            font_family,
            face_flags: 0,
            point_size: size,
            alignment: -2,
        })
        .expect("retail map-help text style");
    commands
        .entity(entity)
        .insert((Text::new(text), font, layout, line_height, TextColor(color)));
}
