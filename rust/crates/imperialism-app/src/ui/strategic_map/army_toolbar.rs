//! Right-hand army command page (`uarm` / `TArmyToolbar`).

use super::super::retail::{
    NumberedArrowAction, NumberedArrowClick, RetailCountedPicture, RetailNumberedArrow, RetailTree,
    RetailUiAssets, install_numbered_arrow,
};
use super::map_interaction::StrategicMapSession;
use super::map_modals::{spawn_army_roster, spawn_garrison};
use crate::AppState;
use crate::ui::GameSession;
use bevy::prelude::*;
use bevy::ui_widgets::ActivateOnPress;
use imperialism_core::*;
use imperialism_formats::*;

const PAGE_TAG: FourCc = fourcc!("uarm");
const ARMY_PAGE_VISIBLE: Vec2 = Vec2::new(0.0, 0x92 as f32);
const PAGE_PARKED: Vec2 = Vec2::new(-1000.0, -1000.0);

fn placard_picture_id(
    counts: ArmyToolbarCounts,
    nation: MajorNationId,
    state: &GameState,
    category: ArmyUnitCategory,
) -> i16 {
    let kind = state.technology().selected_capability_slots[nation][category];
    let mut picture = 0x4c4 + i16::from(kind.retail());
    if counts.totals[category] <= 0 {
        picture += 0x1e;
    }
    picture
}

#[derive(Component)]
pub(super) struct ArmyToolbarPage;

#[derive(Component, Clone, Copy)]
struct ArmyPlacard(ArmyUnitCategory);

#[derive(Component, Clone, Copy)]
struct ArmyArrow(ArmyUnitCategory);

#[derive(Component, Clone, Copy)]
enum ArmyCommand {
    Defend,
    Later,
    Done,
    Garrison,
}

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        sync_army_toolbar.run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_army_toolbar(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let page = tree.find(root, PAGE_TAG);
    commands.entity(page).insert((
        ArmyToolbarPage,
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(PAGE_PARKED.x),
            top: Val::Px(PAGE_PARKED.y),
            width: Val::Px(120.0),
            height: Val::Px(307.0),
            ..default()
        },
    ));
    for category in ArmyUnitCategory::all() {
        let pic = tree.child(page, placard_tag(category));
        commands
            .entity(pic)
            .insert((ArmyPlacard(category), RetailCountedPicture { value: None }));
        let arrow = tree.child(page, arrow_tag(category));
        install_numbered_arrow(commands, arrow, assets);
        let category_capture = category;
        commands
            .entity(arrow)
            .insert((ArmyArrow(category), Visibility::Hidden))
            .remove::<bevy::ui_widgets::Button>()
            .observe(
                move |click: On<NumberedArrowClick>,
                      mut session: ResMut<GameSession>,
                      map: Res<StrategicMapSession>| {
                    let Some(province) = map.selection.army() else {
                        return;
                    };
                    match click.action {
                        NumberedArrowAction::Upper => {
                            session
                                .game
                                .activate_first_active_unit_by_category(province, category_capture);
                        }
                        NumberedArrowAction::Lower => {
                            session
                                .game
                                .activate_first_idle_unit_by_category(province, category_capture);
                        }
                    }
                },
            );
    }
    for (tag, command) in [
        (fourcc!("dfnd"), ArmyCommand::Defend),
        (fourcc!("latr"), ArmyCommand::Later),
        (fourcc!("done"), ArmyCommand::Done),
        (fourcc!("garr"), ArmyCommand::Garrison),
    ] {
        commands
            .entity(tree.child(page, tag))
            .insert((command, ActivateOnPress))
            .observe(on_army_command);
    }
}

#[allow(clippy::type_complexity)]
fn sync_army_toolbar(
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    mut assets: RetailUiAssets,
    mut pages: Query<&mut Node, With<ArmyToolbarPage>>,
    mut placards: Query<(
        Entity,
        &ArmyPlacard,
        &mut ImageNode,
        &mut RetailCountedPicture,
    )>,
    mut arrows: Query<(
        Entity,
        &ArmyArrow,
        &mut Visibility,
        &mut RetailNumberedArrow,
    )>,
    mut garrisons: Query<(&ArmyCommand, &mut ImageNode), Without<ArmyPlacard>>,
) {
    let Ok(mut page) = pages.single_mut() else {
        return;
    };
    let Some(province) = map.selection.army() else {
        page.left = Val::Px(PAGE_PARKED.x);
        page.top = Val::Px(PAGE_PARKED.y);
        hide_empty_toolbar(&mut assets, &session.game, &mut placards, &mut arrows);
        return;
    };
    page.left = Val::Px(ARMY_PAGE_VISIBLE.x);
    page.top = Val::Px(ARMY_PAGE_VISIBLE.y);
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("army toolbar requires an active major nation");
    let counts_state = session.game.army_toolbar_counts(province);
    for (_, placard, mut image, mut counted) in &mut placards {
        let picture_id = placard_picture_id(counts_state, nation, &session.game, placard.0);
        image.image = assets
            .picture(PictureId::new(picture_id))
            .expect("retail army placard picture must load");
        counted.value =
            (counts_state.totals[placard.0] != 0).then_some(counts_state.totals[placard.0]);
    }
    for (_, arrow, mut visibility, mut numbered) in &mut arrows {
        if counts_state.totals[arrow.0] != 0 && arrow.0 != ArmyUnitCategory::Garrison {
            *visibility = Visibility::Visible;
            numbered.value = counts_state.available[arrow.0];
        } else {
            *visibility = Visibility::Hidden;
            numbered.value = 0;
        }
    }
    for (command, mut image) in &mut garrisons {
        if matches!(*command, ArmyCommand::Garrison) {
            image.image = assets
                .picture(PictureId::new(if counts_state.can_upgrade {
                    0x24d5
                } else {
                    0x04b5
                }))
                .expect("retail garrison picture must load");
        }
    }
}

#[allow(clippy::type_complexity)]
fn hide_empty_toolbar(
    assets: &mut RetailUiAssets,
    state: &GameState,
    placards: &mut Query<(
        Entity,
        &ArmyPlacard,
        &mut ImageNode,
        &mut RetailCountedPicture,
    )>,
    arrows: &mut Query<(
        Entity,
        &ArmyArrow,
        &mut Visibility,
        &mut RetailNumberedArrow,
    )>,
) {
    let Some(nation) = MajorNationId::from_nation(state.turn().active_nation) else {
        return;
    };
    let empty = ArmyToolbarCounts::default();
    for (_, placard, mut image, mut counted) in placards.iter_mut() {
        let picture_id = placard_picture_id(empty, nation, state, placard.0);
        image.image = assets
            .picture(PictureId::new(picture_id))
            .expect("retail army placard picture must load");
        counted.value = None;
    }
    for (_, _, mut visibility, mut numbered) in arrows.iter_mut() {
        *visibility = Visibility::Hidden;
        numbered.value = 0;
    }
}

fn on_army_command(
    activate: On<bevy::ui_widgets::Activate>,
    command_query: Query<&ArmyCommand>,
    keys: Res<ButtonInput<KeyCode>>,
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    mut map: ResMut<StrategicMapSession>,
) {
    let Ok(command) = command_query.get(activate.entity) else {
        return;
    };
    let Some(province) = map.selection.army() else {
        return;
    };
    match *command {
        ArmyCommand::Defend => {
            session
                .game
                .set_idle_unit_orders_on_province(province, ArmyIdleOrderMode::Sleep);
            map.cycle_selection(&mut session.game);
        }
        ArmyCommand::Later => {
            session
                .game
                .set_idle_unit_orders_on_province(province, ArmyIdleOrderMode::Latr);
            map.cycle_selection(&mut session.game);
        }
        ArmyCommand::Done => {
            session
                .game
                .set_idle_unit_orders_on_province(province, ArmyIdleOrderMode::Done);
            map.cycle_selection(&mut session.game);
        }
        ArmyCommand::Garrison => {
            if keys.pressed(KeyCode::ControlLeft) || keys.pressed(KeyCode::ControlRight) {
                spawn_army_roster(&mut commands);
            } else {
                spawn_garrison(&mut commands, province);
            }
        }
    }
}

fn placard_tag(category: ArmyUnitCategory) -> FourCc {
    match category {
        ArmyUnitCategory::Garrison => fourcc!("pic0"),
        ArmyUnitCategory::LightInfantry => fourcc!("pic1"),
        ArmyUnitCategory::LineInfantry => fourcc!("pic2"),
        ArmyUnitCategory::EliteInfantry => fourcc!("pic3"),
        ArmyUnitCategory::LightCavalry => fourcc!("pic4"),
        ArmyUnitCategory::HeavyCavalry => fourcc!("pic5"),
        ArmyUnitCategory::FieldArtillery => fourcc!("pic6"),
        ArmyUnitCategory::SiegeArtillery => fourcc!("pic7"),
        ArmyUnitCategory::Engineers => fourcc!("pic8"),
        ArmyUnitCategory::Generals => fourcc!("pic9"),
    }
}

fn arrow_tag(category: ArmyUnitCategory) -> FourCc {
    match category {
        ArmyUnitCategory::Garrison => fourcc!("arr0"),
        ArmyUnitCategory::LightInfantry => fourcc!("arr1"),
        ArmyUnitCategory::LineInfantry => fourcc!("arr2"),
        ArmyUnitCategory::EliteInfantry => fourcc!("arr3"),
        ArmyUnitCategory::LightCavalry => fourcc!("arr4"),
        ArmyUnitCategory::HeavyCavalry => fourcc!("arr5"),
        ArmyUnitCategory::FieldArtillery => fourcc!("arr6"),
        ArmyUnitCategory::SiegeArtillery => fourcc!("arr7"),
        ArmyUnitCategory::Engineers => fourcc!("arr8"),
        ArmyUnitCategory::Generals => fourcc!("arr9"),
    }
}
