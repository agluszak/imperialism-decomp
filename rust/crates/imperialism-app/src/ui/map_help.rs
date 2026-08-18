use super::RetailUiAssets;
use super::generated;
use super::retail::{ModalDialog, RetailTree, ancestor_with};
use crate::AppState;
use crate::RetailAssetsResource;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_formats::{FourCc, RetailTextStylePreset, fourcc};

const TOPICS: [FourCc; 5] = [
    fourcc!("nam1"),
    fourcc!("nam2"),
    fourcc!("nam3"),
    fourcc!("nam4"),
    fourcc!("nam5"),
];
const BODIES: [&str; 5] = [
    "Your civilian units work to expand the pool of available resources on the Terrain Map.\n\nProspectors look for minerals in barren hills and mountains. Later, they can search for oil.\nMiners open mines after the minerals are found.\nFarmers improve the output of fruit, grain, and cotton.\nForesters improve the output of timber\nRanchers improve the output of livestock and wool.\n\nUnlike these units, Engineers are used to connect the resources to a transport network so they may be used to feed your workers and supply your industries. If a terrain tile is within one tile of a connected rail depot, a port, or the capital city, the resources in that tile are available to the transport network.",
    "Whenever a civilian is selected you will see a white flashing outline around him, and his picture will be shown in the toolbar.\n\nIn the toolbar you see a picture of the selected civilian along with information about him. On the map you see your civilian units, a variety of terrain, towns, and defensive military encampments (small tents).\n\nThere are nine types of terrain that always supply a resource: fertile hills(wool), plantations(cotton), open range(livestock), farms(grain), orchards(fruit), hardwood forest(timber), dry plains(grain), ranches(horses), and scrub forests(timber). The last three types cannot be improved to produce more than one unit per turn.\n\nThere are two types of terrain that might conceal mineral resources: barren hills(coal or iron), and mountains (coal, iron, gold, gems).\n\nSome of the other types of terrain on the map become valuable later in the game, like deserts and tundra.\n\n",
    "As you move your cursor across the map it will alter according to what will happen if you click in that location. You can safely experiment because any order you give can be canceled at no cost.\n\nOnce you give an order to a civilian a question mark will appear when you place the cursor over the ordered unit. Click on the unit and a dialog box informs you what he is doing and lets you cancel or confirm his orders.\n\nYou can be sure a civilian is working when the unit animates.",
    "Cursors tell you what will happen if you send your civilian to that terrain tile. For most units, a hammer cursor appears over spaces where that unit could move and do work.\n\nThe Prospector has a special cursor, an eye that appears over places he can search for minerals. The Engineer also has a special cursor, the railroad track cursor which appears over spaces to which he could build rail. When the hammer cursor appears over the Engineer, it indicates that he could construct a depot, port or fort in his current space.\n\nIf you see a green arrow, the civilian can move there, but he will accomplish no work this turn.",
    "You may cycle through your units using the next unit button on the toolbar (a small arrow).\n\nIf you wish to select a civilian unit without waiting for it in the cycle, move the cursor over a unit on the map. When the cursor becomes a small hammer with a flag, click to select the unit.\n\nThis allows you to select units that are not currently in the automatic cycle, or to command units in a different order than presented by the cycle.",
];

#[derive(Component)]
struct MapHelpRoot;

#[derive(Component, Clone, Copy)]
enum MapHelpAction {
    Topic(usize),
    Topics,
    Close,
}

#[derive(Component)]
struct MapHelpBody;

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        bind_added_help.run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind(commands: &mut Commands, control: Entity) {
    commands
        .entity(control)
        .insert(ActivateOnPress)
        .observe(open_help);
}

fn open_help(
    _activate: On<Activate>,
    existing: Query<(), With<MapHelpRoot>>,
    modals: Query<(), With<ModalDialog>>,
    mut commands: Commands,
) {
    if !existing.is_empty() || !modals.is_empty() {
        return;
    }
    let root = commands.spawn_scene(generated::linger_3000()).id();
    commands.entity(root).insert((
        MapHelpRoot,
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(30),
        DespawnOnExit(AppState::StrategicMap),
    ));
}

fn bind_added_help(
    mut commands: Commands,
    roots: Query<Entity, Added<MapHelpRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    for root in &roots {
        let view = tree.view(root);
        set_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("titl")),
            "Help from your\nForeign Minister",
            12,
        );
        let subject = assets.string(0x0bc2, 1).expect("retail map help subject");
        set_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("subj")),
            &subject,
            12,
        );
        for (index, tag) in TOPICS.into_iter().enumerate() {
            let label = assets
                .string(0x0bc2, index as i16 + 2)
                .expect("retail map help topic");
            let entity = view.find(tag);
            set_text(&mut commands, &mut assets, entity, &label, 12);
            commands
                .entity(entity)
                .insert((Button, ActivateOnPress, MapHelpAction::Topic(index)))
                .observe(on_action);
        }
        let body = view.find(fourcc!("swin"));
        set_text(&mut commands, &mut assets, body, "", 12);
        commands
            .entity(body)
            .insert((MapHelpBody, Visibility::Hidden));
        commands
            .entity(view.find(fourcc!("togl")))
            .insert((
                Button,
                ActivateOnPress,
                MapHelpAction::Topics,
                Visibility::Hidden,
            ))
            .observe(on_action);
        let topics_label = assets.string(0x2749, 9).expect("retail show-topics label");
        set_text(
            &mut commands,
            &mut assets,
            view.find(fourcc!("togl")),
            &topics_label,
            12,
        );
        for tag in [fourcc!("prev"), fourcc!("next"), fourcc!("more")] {
            commands.entity(view.find(tag)).insert(Visibility::Hidden);
        }
        commands
            .spawn((
                Node {
                    position_type: PositionType::Absolute,
                    left: px(365),
                    top: px(4),
                    width: px(20),
                    height: px(20),
                    ..default()
                },
                Button,
                Text::new("×"),
                ActivateOnPress,
                MapHelpAction::Close,
                ChildOf(view.find(fourcc!("DLOG"))),
            ))
            .observe(on_action);
    }
}

#[allow(clippy::too_many_arguments)]
fn on_action(
    activate: On<Activate>,
    actions: Query<&MapHelpAction>,
    parents: Query<&ChildOf>,
    roots: Query<(), With<MapHelpRoot>>,
    bodies: Query<Entity, With<MapHelpBody>>,
    assets: Res<RetailAssetsResource>,
    mut texts: Query<&mut Text>,
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
    let view = tree.view(root);
    let Ok(body) = bodies.single() else {
        return;
    };
    match action {
        MapHelpAction::Topic(index) => {
            texts
                .get_mut(view.find(fourcc!("subj")))
                .expect("map help has a subject")
                .0 = assets
                .string(0x0bc2, index as i16 + 2)
                .expect("retail map help topic");
            commands
                .entity(body)
                .insert((Text::new(BODIES[index]), Visibility::Visible));
            for tag in TOPICS {
                commands.entity(view.find(tag)).insert(Visibility::Hidden);
            }
            commands
                .entity(view.find(fourcc!("togl")))
                .insert(Visibility::Visible);
        }
        MapHelpAction::Topics => {
            texts
                .get_mut(view.find(fourcc!("subj")))
                .expect("map help has a subject")
                .0 = assets.string(0x0bc2, 1).expect("retail map help subject");
            commands.entity(body).insert(Visibility::Hidden);
            for tag in TOPICS {
                commands.entity(view.find(tag)).insert(Visibility::Visible);
            }
            commands
                .entity(view.find(fourcc!("togl")))
                .insert(Visibility::Hidden);
        }
        MapHelpAction::Close => unreachable!(),
    }
}

fn set_text(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    text: &str,
    size: i32,
) {
    let (font, layout, line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 0,
            point_size: size,
            alignment: -2,
        })
        .expect("retail map help text style");
    commands.entity(entity).insert((
        Text::new(text),
        font,
        layout,
        line_height,
        TextColor(Color::BLACK),
    ));
}
