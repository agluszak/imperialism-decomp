use super::*;

pub(super) fn on_diplomacy_offer_activate(
    activate: On<Activate>,
    actions: Query<&DiplomacyAction>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<RetailAssetsResource>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let accept = match *action {
        DiplomacyAction::AcceptOffer => true,
        DiplomacyAction::RejectOffer => false,
        _ => return,
    };
    if session.game.current_diplomacy_offer().is_none()
        && session.game.current_diplomacy_war_join().is_none()
    {
        return;
    }
    let story_ids = crate::ui::session::news_story_ids(assets.as_deref());
    let stop = if session.game.current_diplomacy_offer().is_some() {
        session
            .game
            .answer_current_diplomacy_offer(accept, story_ids)
    } else {
        session
            .game
            .answer_current_diplomacy_war_join(accept, story_ids)
    };
    match stop {
        TurnStop::DiplomacyOffer => {
            let prompt = session
                .game
                .current_diplomacy_offer()
                .expect("diplomacy offer stop requires a current offer");
            let mut screen = screens
                .single_mut()
                .expect("Diplomacy offer answer has one open Diplomacy screen");
            pose_diplomacy_offer(&mut screen, prompt);
        }
        TurnStop::DiplomacyWarJoin => {
            let prompt = session
                .game
                .current_diplomacy_war_join()
                .expect("diplomacy war-join stop requires a current war-join prompt");
            let mut screen = screens
                .single_mut()
                .expect("Diplomacy war-join answer has one open Diplomacy screen");
            pose_diplomacy_war_join(&mut screen, prompt);
        }
        stop => apply_turn_stop(stop, &mut next_state),
    }
}
pub(super) fn player_diplomacy_rejection(
    result: PlayerDiplomacyOrderResult,
) -> Option<PlayerDiplomacyRejection> {
    match result {
        PlayerDiplomacyOrderResult::Rejected(rejection) => Some(rejection),
        PlayerDiplomacyOrderResult::Applied
        | PlayerDiplomacyOrderResult::SelectedNation
        | PlayerDiplomacyOrderResult::NeedsEntanglementConfirmation => None,
    }
}
pub(super) fn on_diplomacy_notice_activate(
    activate: On<Activate>,
    parents: Query<&ChildOf>,
    notices: Query<(), With<DiplomacyNotice>>,
    mut commands: Commands,
) {
    let mut entity = activate.entity;
    loop {
        if notices.contains(entity) {
            commands.entity(entity).despawn();
            return;
        }
        entity = parents
            .get(entity)
            .expect("diplomacy notice close belongs to its dialog")
            .parent();
    }
}

pub(super) fn open_diplomacy_rejection_notice(
    request: On<OpenDiplomacyRejectionNotice>,
    mut commands: Commands,
) {
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        DiplomacyNotice(request.rejection),
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::Diplomacy),
    ));
}

pub(super) fn bind_diplomacy_notice(
    mut commands: Commands,
    notice: Single<(Entity, &DiplomacyNotice), Added<DiplomacyNotice>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let (root, notice) = *notice;
    let notice_color = TextColor(assets.palette_color(0));
    let title = find_descendant(root, fourcc!("titl"), &children, &tags);
    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail diplomacy notice title style");
    commands.entity(title).insert((
        Text::new("Report from your\nForeign Minister\n\n"),
        title_font,
        title_layout,
        title_line_height,
        notice_color,
    ));
    let body = find_descendant(root, fourcc!("info"), &children, &tags);
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail diplomacy notice body style");
    commands.entity(body).insert((
        Text::new(get_string(&assets, 0x2754, notice.0.proposal_mode() - 1)),
        body_font,
        body_layout,
        body_line_height,
        notice_color,
    ));
    let coat = find_descendant(root, fourcc!("coat"), &children, &tags);
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let coat_picture = PictureId::new(9500 + i16::from(source.get()));
    if let Ok(image) = assets.picture(coat_picture) {
        commands.entity(coat).insert(ImageNode::new(image));
    }
    let okay = find_descendant(root, fourcc!("okay"), &children, &tags);
    commands
        .entity(okay)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_notice_activate);
    let cancel = find_descendant(root, fourcc!("cncl"), &children, &tags);
    commands.entity(cancel).insert(Visibility::Hidden);
}

pub(super) fn open_diplomacy_entanglement_notice(
    request: On<OpenDiplomacyEntanglementNotice>,
    mut commands: Commands,
) {
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        DiplomacyEntanglementNotice {
            target: request.target,
            policy: request.policy,
        },
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::Diplomacy),
    ));
}

pub(super) fn bind_diplomacy_entanglement_notice(
    mut commands: Commands,
    notice: Single<(Entity, &DiplomacyEntanglementNotice), Added<DiplomacyEntanglementNotice>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    let (root, notice) = *notice;
    let notice_color = TextColor(assets.palette_color(0));
    let title = find_descendant(root, fourcc!("titl"), &children, &tags);
    let (title_font, title_layout, title_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail diplomacy entanglement title style");
    commands.entity(title).insert((
        Text::new(get_string(&assets, 0x275d, 5)),
        title_font,
        title_layout,
        title_line_height,
        notice_color,
    ));
    let body = find_descendant(root, fourcc!("info"), &children, &tags);
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail diplomacy entanglement body style");
    commands.entity(body).insert((
        Text::new(diplomacy_entanglement_body(
            &session.game,
            &assets,
            notice.target,
            notice.policy,
        )),
        body_font,
        body_layout,
        body_line_height,
        notice_color,
    ));
    let coat = find_descendant(root, fourcc!("coat"), &children, &tags);
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let coat_picture = PictureId::new(9500 + i16::from(source.get()));
    if let Ok(image) = assets.picture(coat_picture) {
        commands.entity(coat).insert(ImageNode::new(image));
    }
    let okay = find_descendant(root, fourcc!("okay"), &children, &tags);
    commands
        .entity(okay)
        .insert(DiplomacyEntanglementAction::Confirm)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_entanglement_activate);
    let cancel = find_descendant(root, fourcc!("cncl"), &children, &tags);
    commands
        .entity(cancel)
        .insert(DiplomacyEntanglementAction::Dismiss)
        .remove::<InteractionDisabled>()
        .observe(on_diplomacy_entanglement_activate);
}
pub(super) fn on_diplomacy_entanglement_activate(
    activate: On<Activate>,
    actions: Query<&DiplomacyEntanglementAction>,
    parents: Query<&ChildOf>,
    notices: Query<(Entity, &DiplomacyEntanglementNotice)>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let mut entity = activate.entity;
    let notice = loop {
        if let Ok(notice) = notices.get(entity) {
            break notice;
        }
        entity = parents
            .get(entity)
            .expect("diplomacy entanglement close belongs to its dialog")
            .parent();
    };
    let (root, notice) = notice;
    let target = notice.target;
    let policy = notice.policy;
    commands.entity(root).despawn();
    if !matches!(*action, DiplomacyEntanglementAction::Confirm) {
        return;
    }
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    if let Some(rejection) = player_diplomacy_rejection(
        session
            .game
            .toggle_player_diplomacy_policy(source, target, policy, true),
    ) {
        commands.trigger(OpenDiplomacyRejectionNotice { rejection });
    }
}

pub(super) fn diplomacy_entanglement_body(
    state: &GameState,
    assets: &RetailUiAssets,
    target: NationId,
    policy: DiplomacyPolicy,
) -> String {
    let target_name = state.nations().display_name(target).unwrap_or("");
    let intro_index = if policy == DiplomacyPolicy::Alliance {
        0
    } else {
        4
    };
    let intro = fill_brackets(&get_string(assets, 0x275d, intro_index), &[target_name]);
    let mut names = String::new();
    for major in MajorNationId::all() {
        if state.diplomacy().relationships[target][major.nation()] != DiplomaticRelationship::War {
            continue;
        }
        let Some(name) = state.nations().display_name(major.nation()) else {
            continue;
        };
        names.push_str("   ");
        names.push_str(name);
        names.push('\n');
    }
    format!("{intro}\n{names}")
}

pub(super) fn pose_diplomacy_offer(screen: &mut DiplomacyScreen, prompt: DiplomacyOfferPrompt) {
    screen.mode = DiplomacyMode::Offers;
    screen.framed_nation = prompt.source;
}

pub(super) fn pose_diplomacy_war_join(
    screen: &mut DiplomacyScreen,
    prompt: DiplomacyWarJoinPrompt,
) {
    screen.mode = DiplomacyMode::Offers;
    screen.framed_nation = prompt.target;
}

pub(super) fn nation_label(state: &GameState, nation: NationId) -> String {
    state
        .nations()
        .display_name(nation)
        .unwrap_or("")
        .to_string()
}

pub(super) fn major_at_war(state: &GameState, first: NationId, second: NationId) -> bool {
    state.diplomacy().relationships[first][second] == DiplomaticRelationship::War
}

pub(super) fn offer_has_alliance_entanglements(
    state: &GameState,
    source: NationId,
    target: NationId,
) -> bool {
    MajorNationId::all().any(|nation| {
        let other = nation.nation();
        other != source
            && other != target
            && major_at_war(state, other, target)
            && !major_at_war(state, source, other)
    })
}

pub(super) fn offer_has_peace_entanglements(
    state: &GameState,
    source: NationId,
    target: NationId,
) -> bool {
    MajorNationId::all().any(|nation| {
        let other = nation.nation();
        other != source
            && other != target
            && state.diplomacy().relationships[source][other] == DiplomaticRelationship::Alliance
            && major_at_war(state, other, target)
    })
}

pub(super) fn war_join_adds_entanglements(
    state: &GameState,
    prompt: DiplomacyWarJoinPrompt,
) -> bool {
    let human = prompt.nation.nation();
    match prompt.kind {
        DiplomacyWarJoinKind::DefendMinor | DiplomacyWarJoinKind::AnnexMinor => {
            MajorNationId::all().any(|nation| {
                let other = nation.nation();
                other != prompt.source
                    && major_at_war(state, other, prompt.target)
                    && !major_at_war(state, other, human)
            })
        }
        DiplomacyWarJoinKind::JoinTargetAlly => MajorNationId::all().any(|nation| {
            let other = nation.nation();
            state.diplomacy().relationships[prompt.source][other]
                == DiplomaticRelationship::Alliance
                && !major_at_war(state, other, human)
        }),
        DiplomacyWarJoinKind::JoinSourceAlly => false,
    }
}

pub(super) fn diplomacy_offer_message(
    state: &GameState,
    assets: &RetailAssetsResource,
) -> Option<String> {
    let prompt = state.current_diplomacy_offer()?;
    let target = nation_label(state, prompt.source);
    let (group, index) = match prompt.policy {
        DiplomacyPolicy::JoinEmpire => (0x274a, 0),
        DiplomacyPolicy::Alliance
            if offer_has_alliance_entanglements(state, prompt.nation.nation(), prompt.source) =>
        {
            (0x274a, 8)
        }
        DiplomacyPolicy::Alliance => (0x274a, 1),
        DiplomacyPolicy::NonAggressionPact => (0x274a, 2),
        DiplomacyPolicy::PeaceTreaty
            if offer_has_peace_entanglements(state, prompt.nation.nation(), prompt.source) =>
        {
            (0x274a, 9)
        }
        DiplomacyPolicy::PeaceTreaty => (0x274a, 3),
        DiplomacyPolicy::JoinEmpireWithWarEntanglements => (0x274a, 4),
        _ => return None,
    };
    Some(fill_brackets(
        &assets.get_string(group, index),
        &[&target, &target],
    ))
}

pub(super) fn diplomacy_war_join_message(
    state: &GameState,
    assets: &RetailAssetsResource,
) -> Option<String> {
    let prompt = state.current_diplomacy_war_join()?;
    let minor = nation_label(state, prompt.target);
    let enemy = nation_label(state, prompt.source);
    let entangled = war_join_adds_entanglements(state, prompt);
    let (index, args): (i16, [&str; 4]) = match prompt.kind {
        DiplomacyWarJoinKind::DefendMinor => {
            (if entangled { 4 } else { 0 }, [&enemy, &minor, &enemy, ""])
        }
        DiplomacyWarJoinKind::JoinTargetAlly => (
            if entangled { 5 } else { 1 },
            [&enemy, &minor, &minor, &enemy],
        ),
        DiplomacyWarJoinKind::JoinSourceAlly => (2, [&enemy, &minor, &enemy, &minor]),
        DiplomacyWarJoinKind::AnnexMinor => (
            if entangled { 8 } else { 3 },
            [&minor, &enemy, &minor, &minor],
        ),
    };
    Some(fill_brackets(&assets.get_string(0x2729, index), &args))
}
pub(super) fn locate_offer_sheet(node: &mut Node, visible: bool) {
    if visible {
        node.left = Val::Px(OFFER_SHEET_LEFT);
        node.top = Val::Px(OFFER_SHEET_TOP);
    } else {
        node.left = Val::Px(OFFER_SHEET_OFFSCREEN);
        node.top = Val::Px(OFFER_SHEET_OFFSCREEN);
    }
}

pub(super) fn sync_diplomacy_offer_sheet(
    mut commands: Commands,
    session: Res<GameSession>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut sheets: Query<&mut Node, (With<DiplomacyOfferSheet>, Without<DiplomacyOfferWait>)>,
    mut waits: Query<&mut Node, (With<DiplomacyOfferWait>, Without<DiplomacyOfferSheet>)>,
    controls: Query<(Entity, &DiplomacyAction)>,
) {
    let mut screen = screens
        .single_mut()
        .expect("Diplomacy state has one Diplomacy screen");
    if let Some(prompt) = session.game.current_diplomacy_offer() {
        if screen.mode != DiplomacyMode::Offers || screen.framed_nation != prompt.source {
            pose_diplomacy_offer(&mut screen, prompt);
        }
    } else if let Some(prompt) = session.game.current_diplomacy_war_join()
        && (screen.mode != DiplomacyMode::Offers || screen.framed_nation != prompt.target)
    {
        pose_diplomacy_war_join(&mut screen, prompt);
    }
    if !session.is_changed() && !screen.is_changed() && !screen.is_added() {
        return;
    }
    let posing = session.game.current_diplomacy_offer().is_some()
        || session.game.current_diplomacy_war_join().is_some();
    for mut node in &mut sheets {
        locate_offer_sheet(&mut node, posing);
    }
    for mut node in &mut waits {
        locate_offer_sheet(&mut node, false);
    }
    for (entity, action) in &controls {
        match *action {
            DiplomacyAction::AcceptOffer | DiplomacyAction::RejectOffer => {
                if posing {
                    commands.entity(entity).remove::<InteractionDisabled>();
                } else {
                    commands.entity(entity).insert(InteractionDisabled);
                }
            }
            DiplomacyAction::Topic(_) => {
                if posing {
                    commands.entity(entity).insert(InteractionDisabled);
                } else {
                    commands.entity(entity).remove::<InteractionDisabled>();
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../../fixtures/retail/beginning_of_game.imp");

    fn fixture_parts() -> GameStateParts {
        let selected_nation = peek_save_header(BEGINNING_OF_GAME)
            .and_then(|header| NationId::try_new(header.active_nation))
            .unwrap_or(NationId::new(0));
        LegacySaveV62::parse(BEGINNING_OF_GAME).game_state_parts(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 0,
            selected_nation,
        })
    }

    fn rebuild_nations(
        parts: &mut GameStateParts,
        mutate: impl Fn(MajorNationId, &mut MajorNation),
    ) {
        let majors = MajorNationTable::from_fn(|id| {
            let mut major = parts.nations.major(id).clone();
            mutate(id, &mut major);
            major
        });
        let minors = MinorNationTable::from_array(std::array::from_fn(|index| {
            parts
                .nations
                .minor(MinorNationId::new(MajorNationId::COUNT + index as u8))
                .cloned()
        }));
        parts.nations = Nations::new(majors, minors);
    }

    fn alliance_offer_state() -> GameState {
        let mut parts = fixture_parts();
        let player = MajorNationId::from_nation(parts.turn.active_nation)
            .expect("beginning-of-game fixture names a major nation");
        let computer = MajorNationId::new(if player.get() == 0 { 1 } else { 0 });
        rebuild_nations(&mut parts, |id, major| {
            if id != computer {
                return;
            }
            major.auto = Some(AutoGreatPowerState::default());
            major.economy.diplomacy_policy_by_nation[player.nation()] =
                Some(DiplomacyPolicy::Alliance);
        });
        let mut state = GameState::from_parts(parts);
        let TurnStop::DiplomacyOffer = state.finish_player_orders(true, &[]) else {
            panic!("alliance offer must stop for the diplomacy-offer dialog");
        };
        state
    }

    fn war_join_state() -> GameState {
        let mut parts = fixture_parts();
        let player = MajorNationId::from_nation(parts.turn.active_nation)
            .expect("beginning-of-game fixture names a major nation");
        let computer = MajorNationId::new(if player.get() == 0 { 1 } else { 0 });
        let minor = NationId::new(7);
        rebuild_nations(&mut parts, |id, major| {
            if id != computer {
                return;
            }
            major.auto = Some(AutoGreatPowerState::default());
            major.economy.diplomacy_policy_by_nation[minor] = Some(DiplomacyPolicy::DeclareWar);
        });
        parts.diplomacy.mission_levels[player.nation()][minor] = DiplomaticMissionLevel::Embassy;
        parts.diplomacy.mission_levels[minor][player.nation()] = DiplomaticMissionLevel::Embassy;
        parts.diplomacy.standings[player.nation()][minor] = 0xff;
        parts.diplomacy.standings[minor][player.nation()] = 0xff;
        for other in MajorNationId::all() {
            if other == player {
                continue;
            }
            parts.diplomacy.mission_levels[minor][other.nation()] = DiplomaticMissionLevel::None;
            parts.diplomacy.standings[minor][other.nation()] = 0x5a;
        }
        let mut state = GameState::from_parts(parts);
        state.set_country_status(minor, CountryStatus::Independent);
        let TurnStop::DiplomacyWarJoin = state.finish_player_orders(true, &[]) else {
            panic!("declare-war on the favorite's minor must stop for the war-join dialog");
        };
        state
    }

    fn dialog_app(state: GameState) -> (App, Entity, Entity) {
        let framed = state
            .current_diplomacy_offer()
            .map(|prompt| prompt.source)
            .or_else(|| {
                state
                    .current_diplomacy_war_join()
                    .map(|prompt| prompt.target)
            })
            .expect("dialog app requires a posed diplomacy continuation");
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_resource(GameSession { game: state })
            .insert_state(AppState::Diplomacy)
            .add_observer(on_diplomacy_offer_activate);
        app.world_mut().spawn(DiplomacyScreen {
            framed_nation: framed,
            mode: DiplomacyMode::Offers,
        });
        let accept = app.world_mut().spawn(DiplomacyAction::AcceptOffer).id();
        let reject = app.world_mut().spawn(DiplomacyAction::RejectOffer).id();
        (app, accept, reject)
    }

    fn activate(app: &mut App, entity: Entity) {
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
    }

    #[test]
    fn accepting_a_diplomacy_offer_calls_the_core_offer_answer() {
        let state = alliance_offer_state();
        let prompt = state
            .current_diplomacy_offer()
            .expect("alliance fixture poses an offer");
        let (mut app, accept, _) = dialog_app(state);
        activate(&mut app, accept);
        let game = &app.world().resource::<GameSession>().game;
        assert!(game.current_diplomacy_offer().is_none());
        assert_eq!(
            game.diplomacy().relationships[prompt.nation.nation()][prompt.source],
            DiplomaticRelationship::Alliance
        );
    }

    #[test]
    fn rejecting_a_war_join_calls_the_core_war_join_answer() {
        let state = war_join_state();
        assert!(state.current_diplomacy_war_join().is_some());
        let (mut app, _, reject) = dialog_app(state);
        activate(&mut app, reject);
        let game = &app.world().resource::<GameSession>().game;
        assert!(game.current_diplomacy_war_join().is_none());
        assert!(game.current_diplomacy_offer().is_none());
    }
}
