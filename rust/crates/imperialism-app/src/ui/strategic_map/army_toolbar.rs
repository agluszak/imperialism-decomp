//! Right-hand army command page (`uarm` / `TArmyToolbar`).

use super::super::retail::{
    ArmyPlacardParts, NumberedArrowParts, RetailTree, RetailUiAssets,
};
use super::map_interaction::StrategicMapSession;
use super::map_modals::{spawn_army_roster, spawn_garrison};
use crate::AppState;
use crate::ui::GameSession;
use bevy::prelude::*;
use bevy::ui_widgets::{Activate, ActivateOnPress};
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

#[derive(Clone, Copy)]
struct PlacardBinding {
    root: Entity,
    text: Entity,
}

#[derive(Clone, Copy)]
struct ArrowBinding {
    root: Entity,
    count: Entity,
}

#[derive(Component)]
struct ArmyToolbarView {
    placards: ArmyCategoryTable<PlacardBinding>,
    arrows: ArmyCategoryTable<ArrowBinding>,
    garrison: Entity,
}

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        sync_army_toolbar.run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_army_toolbar(
    commands: &mut Commands,
    _assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    arrow_parts: &Query<&NumberedArrowParts>,
    placard_parts: &Query<&ArmyPlacardParts>,
) {
    let page = tree.find(root, PAGE_TAG);
    let mut placards =
        ArmyCategoryTable::from_array([PlacardBinding {
            root: Entity::PLACEHOLDER,
            text: Entity::PLACEHOLDER,
        }; ArmyUnitCategory::LENGTH]);
    let mut arrows = ArmyCategoryTable::from_array([ArrowBinding {
        root: Entity::PLACEHOLDER,
        count: Entity::PLACEHOLDER,
    }; ArmyUnitCategory::LENGTH]);
    for category in ArmyUnitCategory::all() {
        let pic = tree.child(page, placard_tag(category));
        let ArmyPlacardParts { text } = placard_parts
            .get(pic)
            .expect("army placard parts")
            .clone();
        placards[category] = PlacardBinding { root: pic, text };
        let arrow = tree.child(page, arrow_tag(category));
        let NumberedArrowParts {
            upper,
            lower,
            count,
        } = arrow_parts
            .get(arrow)
            .expect("army arrow parts")
            .clone();
        arrows[category] = ArrowBinding {
            root: arrow,
            count,
        };
        let category_capture = category;
        commands.entity(arrow).insert(Visibility::Hidden);
        commands.entity(upper).observe(
            move |_: On<Activate>,
                  mut session: ResMut<GameSession>,
                  map: Res<StrategicMapSession>| {
                let Some(province) = map.selection.army() else {
                    return;
                };
                session
                    .game
                    .activate_first_active_unit_by_category(province, category_capture);
            },
        );
        commands.entity(lower).observe(
            move |_: On<Activate>,
                  mut session: ResMut<GameSession>,
                  map: Res<StrategicMapSession>| {
                let Some(province) = map.selection.army() else {
                    return;
                };
                session
                    .game
                    .activate_first_idle_unit_by_category(province, category_capture);
            },
        );
    }
    let garrison = tree.child(page, fourcc!("garr"));
    commands.entity(page).insert((
        ArmyToolbarView {
            placards,
            arrows,
            garrison,
        },
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(PAGE_PARKED.x),
            top: Val::Px(PAGE_PARKED.y),
            width: Val::Px(120.0),
            height: Val::Px(307.0),
            ..default()
        },
    ));
    for (tag, mode) in [
        (fourcc!("dfnd"), ArmyIdleOrderMode::Sleep),
        (fourcc!("latr"), ArmyIdleOrderMode::Latr),
        (fourcc!("done"), ArmyIdleOrderMode::Done),
    ] {
        commands
            .entity(tree.child(page, tag))
            .insert(ActivateOnPress)
            .observe(
                move |_: On<Activate>,
                      mut session: ResMut<GameSession>,
                      mut map: ResMut<StrategicMapSession>| {
                    let Some(province) = map.selection.army() else {
                        return;
                    };
                    session
                        .game
                        .set_idle_unit_orders_on_province(province, mode);
                    map.cycle_selection(&mut session.game);
                },
            );
    }
    commands.entity(garrison).insert(ActivateOnPress).observe(
        |_: On<Activate>,
         keys: Res<ButtonInput<KeyCode>>,
         mut commands: Commands,
         map: Res<StrategicMapSession>| {
            let Some(province) = map.selection.army() else {
                return;
            };
            if keys.pressed(KeyCode::ControlLeft) || keys.pressed(KeyCode::ControlRight) {
                spawn_army_roster(&mut commands);
            } else {
                spawn_garrison(&mut commands, province);
            }
        },
    );
}

fn sync_army_toolbar(
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    mut assets: RetailUiAssets,
    mut pages: Query<(&mut Node, &ArmyToolbarView)>,
    mut images: Query<&mut ImageNode>,
    mut visibility: Query<&mut Visibility>,
    mut texts: Query<&mut Text>,
) {
    if !session.is_changed() && !map.is_changed() {
        return;
    }
    let Ok((mut page, view)) = pages.single_mut() else {
        return;
    };
    let Some(province) = map.selection.army() else {
        page.left = Val::Px(PAGE_PARKED.x);
        page.top = Val::Px(PAGE_PARKED.y);
        hide_empty_toolbar(
            &mut assets,
            &session.game,
            view,
            &mut images,
            &mut visibility,
            &mut texts,
        );
        return;
    };
    page.left = Val::Px(ARMY_PAGE_VISIBLE.x);
    page.top = Val::Px(ARMY_PAGE_VISIBLE.y);
    let nation = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("army toolbar requires an active major nation");
    let counts_state = session.game.army_toolbar_counts(province);
    for category in ArmyUnitCategory::all() {
        let picture_id = placard_picture_id(counts_state, nation, &session.game, category);
        let placard = view.placards[category];
        images
            .get_mut(placard.root)
            .expect("army placard")
            .image = assets
            .picture(PictureId::new(picture_id))
            .expect("retail army placard picture must load");
        texts.get_mut(placard.text).expect("army placard text").0 =
            if counts_state.totals[category] != 0 {
                counts_state.totals[category].to_string()
            } else {
                String::new()
            };
        let arrow = view.arrows[category];
        if counts_state.totals[category] != 0 && category != ArmyUnitCategory::Garrison {
            *visibility.get_mut(arrow.root).expect("army arrow") = Visibility::Visible;
            texts.get_mut(arrow.count).expect("army arrow count").0 =
                counts_state.available[category].to_string();
        } else {
            *visibility.get_mut(arrow.root).expect("army arrow") = Visibility::Hidden;
            texts.get_mut(arrow.count).expect("army arrow count").0 = String::new();
        }
    }
    images.get_mut(view.garrison).expect("garrison").image = assets
        .picture(PictureId::new(if counts_state.can_upgrade {
            0x24d5
        } else {
            0x04b5
        }))
        .expect("retail garrison picture must load");
}

fn hide_empty_toolbar(
    assets: &mut RetailUiAssets,
    state: &GameState,
    view: &ArmyToolbarView,
    images: &mut Query<&mut ImageNode>,
    visibility: &mut Query<&mut Visibility>,
    texts: &mut Query<&mut Text>,
) {
    let Some(nation) = MajorNationId::from_nation(state.turn().active_nation) else {
        return;
    };
    let empty = ArmyToolbarCounts::default();
    for category in ArmyUnitCategory::all() {
        let picture_id = placard_picture_id(empty, nation, state, category);
        let placard = view.placards[category];
        images
            .get_mut(placard.root)
            .expect("army placard")
            .image = assets
            .picture(PictureId::new(picture_id))
            .expect("retail army placard picture must load");
        texts.get_mut(placard.text).expect("army placard text").0 = String::new();
        let arrow = view.arrows[category];
        *visibility.get_mut(arrow.root).expect("army arrow") = Visibility::Hidden;
        texts.get_mut(arrow.count).expect("army arrow count").0 = String::new();
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
