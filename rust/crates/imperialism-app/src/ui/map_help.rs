use super::generated;
use super::retail::RetailTree;
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
const TOPIC_TAGS: [FourCc; 5] = [
    fourcc!("nam1"),
    fourcc!("nam2"),
    fourcc!("nam3"),
    fourcc!("nam4"),
    fourcc!("nam5"),
];
const LINK_BLUE: Color = Color::srgb(0.05, 0.08, 0.65);

#[derive(Component)]
struct MapHelpView {
    context: HelpContext,
    set: usize,
    topic: Option<usize>,
    subject: Entity,
    body: Entity,
    topics: [Entity; 5],
    previous: Entity,
    next: Entity,
    toggle: Entity,
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

pub(crate) fn register(app: &mut App) {
    app.add_systems(Update, (bind_added_help, project_map_help));
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
    // Bind inserts MapHelpView once the scene is ready.
    commands
        .entity(root)
        .insert(DespawnOnExit(context.app_state()))
        .insert(PendingMapHelp(context));
}

#[derive(Component)]
struct PendingMapHelp(HelpContext);

fn bind_added_help(
    mut commands: Commands,
    pending: Query<(Entity, &PendingMapHelp), Added<PendingMapHelp>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    retail: Res<RetailAssetsResource>,
) {
    for (root, PendingMapHelp(context)) in &pending {
        let context = *context;
        let title = fill_brackets(
            &retail.get_string(0x2749, 6),
            &[&retail.get_string(0x2749, context.event_code() as u16)],
        );
        set_text(
            &mut commands,
            &mut assets,
            tree.find(root, fourcc!("titl")),
            &title,
            12,
            1,
            Color::BLACK,
        );
        let subject = tree.find(root, fourcc!("subj"));
        let body = tree.find(root, fourcc!("swin"));
        set_text(&mut commands, &mut assets, subject, "", 12, 1, Color::BLACK);
        set_text(&mut commands, &mut assets, body, "", 12, 3, Color::BLACK);

        let topics = TOPIC_TAGS.map(|tag| tree.find(root, tag));
        let previous = tree.find(root, fourcc!("prev"));
        let next = tree.find(root, fourcc!("next"));
        let toggle = tree.find(root, fourcc!("togl"));
        for entity in topics {
            commands.entity(entity).insert((
                UiButton,
                Pickable::default(),
                Text::default(),
                TextColor(LINK_BLUE),
                Underline,
            ));
        }
        for entity in [previous, next] {
            commands.entity(entity).insert((
                UiButton,
                Pickable::default(),
                Text::default(),
                TextColor(LINK_BLUE),
                Underline,
            ));
        }
        let topics_label = assets.ui_string(0x2749, 9);
        set_text(
            &mut commands,
            &mut assets,
            toggle,
            &topics_label,
            12,
            3,
            LINK_BLUE,
        );
        commands
            .entity(toggle)
            .insert((UiButton, Pickable::default()));

        let view = MapHelpView {
            context,
            set: 0,
            topic: None,
            subject,
            body,
            topics,
            previous,
            next,
            toggle,
        };

        for (index, entity) in topics.into_iter().enumerate() {
            commands.entity(entity).observe(
                move |_: On<Activate>, mut views: Query<&mut MapHelpView>| {
                    let Ok(mut view) = views.get_mut(root) else {
                        return;
                    };
                    view.topic = Some(index);
                },
            );
        }
        commands.entity(toggle).observe(
            move |_: On<Activate>, mut views: Query<&mut MapHelpView>| {
                let Ok(mut view) = views.get_mut(root) else {
                    return;
                };
                view.topic = None;
            },
        );
        for (entity, step) in [(previous, -1i8), (next, 1)] {
            commands.entity(entity).observe(
                move |_: On<Activate>, mut views: Query<&mut MapHelpView>| {
                    let Ok(mut view) = views.get_mut(root) else {
                        return;
                    };
                    if step < 0 {
                        view.set = view.set.saturating_sub(1);
                    } else {
                        view.set = (view.set + 1).min(view.context.sets().len() - 1);
                    }
                    view.topic = None;
                },
            );
        }

        commands
            .entity(tree.find(root, fourcc!("more")))
            .insert(Visibility::Hidden);
        commands
            .entity(root)
            .insert(view)
            .remove::<PendingMapHelp>();
    }
}

fn project_map_help(
    views: Query<Ref<MapHelpView>>,
    assets: Res<RetailAssetsResource>,
    mut texts: Query<&mut Text>,
    mut visibilities: Query<&mut Visibility>,
) {
    let Ok(view_ref) = views.single() else {
        return;
    };
    if !view_ref.is_added() && !view_ref.is_changed() {
        return;
    }
    let view = view_ref.into_inner();
    if let Some(topic) = view.topic {
        let group = view.context.sets()[view.set];
        texts.get_mut(view.subject).expect("bound help subject").0 =
            assets.ui_string(group as u16, topic as u16 + 2);
        texts.get_mut(view.body).expect("bound help body").0 =
            assets.text(group as u16 + topic as u16 + 1);
        *visibilities.get_mut(view.body).expect("bound help body") = Visibility::Visible;
        for entity in view.topics {
            *visibilities.get_mut(entity).expect("bound help topic") = Visibility::Hidden;
        }
        for entity in [view.previous, view.next] {
            *visibilities.get_mut(entity).expect("bound help nav") = Visibility::Hidden;
        }
        *visibilities
            .get_mut(view.toggle)
            .expect("bound help toggle") = Visibility::Visible;
        return;
    }

    let group = view.context.sets()[view.set];
    texts.get_mut(view.subject).expect("bound help subject").0 = assets.ui_string(group as u16, 1);
    *visibilities.get_mut(view.body).expect("bound help body") = Visibility::Hidden;
    for (index, entity) in view.topics.into_iter().enumerate() {
        texts.get_mut(entity).expect("bound help topic").0 =
            assets.ui_string(group as u16, index as u16 + 2);
        *visibilities.get_mut(entity).expect("bound help topic") =
            if index < view.context.topic_count(view.set) {
                Visibility::Visible
            } else {
                Visibility::Hidden
            };
    }
    for (entity, index, visible) in [
        (view.previous, 14, view.set > 0),
        (view.next, 15, view.set + 1 < view.context.sets().len()),
    ] {
        texts.get_mut(entity).expect("bound help nav").0 = assets.ui_string(0x2749, index);
        *visibilities.get_mut(entity).expect("bound help nav") = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
    }
    *visibilities
        .get_mut(view.toggle)
        .expect("bound help toggle") = Visibility::Hidden;
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
    let (font, layout, line_height, _) =
        assets.text_style(RetailTextStylePreset::explicit(font_family, 0, size, -2));
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
