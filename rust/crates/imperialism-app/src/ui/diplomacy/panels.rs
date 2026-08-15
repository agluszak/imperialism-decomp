use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn bind_diplomacy_controls(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    pictures: DiplomacyBracketPictures,
    styles: DiplomacyTextStyles,
    icon_atlas: Handle<Image>,
    assets: &mut RetailUiAssets,
    session: &GameSession,
) -> Entity {
    let posing = session.game.current_diplomacy_offer().is_some()
        || session.game.current_diplomacy_war_join().is_some();
    if !posing {
        bind_native_game_screen_nav(
            commands,
            root,
            children,
            tags,
            fourcc!("topB"),
            Some(fourcc!("too3")),
        );
    }
    let top = find_descendant(root, fourcc!("topB"), children, tags);
    let selected = find_descendant(top, fourcc!("dipl"), children, tags);
    commands
        .entity(selected)
        .insert((Checked, InteractionDisabled));

    let main = find_descendant(root, fourcc!("main"), children, tags);
    let information = find_child(main, fourcc!("info"), children, tags);
    let treaties = find_child(main, fourcc!("trty"), children, tags);
    let grants = find_child(main, fourcc!("gran"), children, tags);
    let trade = find_child(main, fourcc!("trad"), children, tags);
    let council = find_child(main, fourcc!("coun"), children, tags);
    let offers = find_child(main, fourcc!("offr"), children, tags);
    let trade_cluster = find_descendant(trade, fourcc!("clus"), children, tags);

    for topic in [
        DiplomacyTopic::Information,
        DiplomacyTopic::Treaties,
        DiplomacyTopic::Grants,
        DiplomacyTopic::Trade,
        DiplomacyTopic::Council,
        DiplomacyTopic::Offers,
    ] {
        let panel = match topic {
            DiplomacyTopic::Information => information,
            DiplomacyTopic::Treaties => treaties,
            DiplomacyTopic::Grants => grants,
            DiplomacyTopic::Trade => trade,
            DiplomacyTopic::Council => council,
            DiplomacyTopic::Offers => offers,
        };
        commands.entity(panel).insert(DiplomacyPanel(topic));
    }

    for (tag, topic) in [
        (fourcc!("inft"), DiplomacyTopic::Information),
        (fourcc!("trtt"), DiplomacyTopic::Treaties),
        (fourcc!("grat"), DiplomacyTopic::Grants),
        (fourcc!("trat"), DiplomacyTopic::Trade),
        (fourcc!("cout"), DiplomacyTopic::Council),
    ] {
        let control = find_descendant(root, tag, children, tags);
        let mut entity = commands.entity(control);
        entity.insert(DiplomacyAction::Topic(topic));
        if posing {
            entity.insert(InteractionDisabled);
        } else {
            entity.remove::<InteractionDisabled>();
        }
    }
    for (index, tag) in [
        fourcc!("doc0"),
        fourcc!("doc1"),
        fourcc!("doc2"),
        fourcc!("doc3"),
        fourcc!("doc4"),
        fourcc!("doc5"),
        fourcc!("doc6"),
        fourcc!("doc7"),
    ]
    .into_iter()
    .enumerate()
    {
        let control = find_descendant(root, tag, children, tags);
        commands.entity(control).insert(DiplomacyAction::Grant {
            row: index / 2,
            recurring: index % 2 != 0,
        });
    }
    for (index, tag) in [
        fourcc!("traa"),
        fourcc!("trab"),
        fourcc!("trac"),
        fourcc!("trad"),
        fourcc!("trae"),
        fourcc!("traf"),
        fourcc!("trag"),
    ]
    .into_iter()
    .enumerate()
    {
        let control = find_descendant(trade_cluster, tag, children, tags);
        commands
            .entity(control)
            .insert(DiplomacyAction::Trade(index));
    }
    for (index, tag) in [
        fourcc!("ovr0"),
        fourcc!("ovr1"),
        fourcc!("ovr2"),
        fourcc!("ovr4"),
    ]
    .into_iter()
    .enumerate()
    {
        let overlay = [0_u8, 1, 2, 4][index];
        let control = find_descendant(root, tag, children, tags);
        commands
            .entity(control)
            .insert(DiplomacyAction::Overlay(overlay))
            .remove::<InteractionDisabled>();
    }
    for (index, tag) in [
        fourcc!("scr0"),
        fourcc!("scr1"),
        fourcc!("scr2"),
        fourcc!("scr3"),
        fourcc!("scr4"),
        fourcc!("scr5"),
        fourcc!("scr6"),
    ]
    .into_iter()
    .enumerate()
    {
        let control = find_descendant(root, tag, children, tags);
        commands
            .entity(control)
            .insert(DiplomacyAction::Treaty(index))
            .remove::<InteractionDisabled>();
    }
    commands
        .entity(find_descendant(
            trade_cluster,
            fourcc!("link"),
            children,
            tags,
        ))
        .insert(DiplomacyAction::ColonyBoycott)
        .remove::<InteractionDisabled>();
    for (tag, action) in [
        (fourcc!("acce"), DiplomacyAction::AcceptOffer),
        (fourcc!("reje"), DiplomacyAction::RejectOffer),
    ] {
        let control = find_descendant(root, tag, children, tags);
        commands
            .entity(control)
            .insert((action, ActivateOnPress))
            .remove::<InteractionDisabled>();
    }
    for (tag, checked) in [
        (fourcc!("ovr0"), true),
        (fourcc!("ovr1"), false),
        (fourcc!("ovr2"), false),
        (fourcc!("ovr4"), false),
        (fourcc!("scr0"), false),
        (fourcc!("scr1"), false),
        (fourcc!("scr2"), false),
        (fourcc!("scr3"), false),
        (fourcc!("scr4"), false),
        (fourcc!("scr5"), true),
        (fourcc!("scr6"), false),
    ] {
        let control = find_descendant(root, tag, children, tags);
        if checked {
            commands.entity(control).insert(Checked);
        } else {
            commands.entity(control).remove::<Checked>();
        }
    }
    commands
        .entity(find_descendant(
            trade_cluster,
            fourcc!("link"),
            children,
            tags,
        ))
        .remove::<Checked>();

    let map = commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(MAP_LEFT),
                top: Val::Px(MAP_TOP),
                width: Val::Px(MAP_WIDTH),
                height: Val::Px(MAP_HEIGHT),
                ..default()
            },
            BackgroundColor(Color::NONE),
            UiButton,
            RelativeCursorPosition::default(),
            DiplomacyMapPicture,
            ZIndex(1),
            ChildOf(main),
        ))
        .id();
    spawn_diplomacy_map_labels(commands, map, &styles, icon_atlas);
    spawn_diplomacy_panel_text(
        commands,
        root,
        children,
        tags,
        information,
        treaties,
        grants,
        trade,
        council,
        &styles,
        assets,
    );

    let shee = find_descendant(root, fourcc!("shee"), children, tags);
    let wait = find_descendant(root, fourcc!("wait"), children, tags);
    let prop = find_descendant(root, fourcc!("prop"), children, tags);
    commands.entity(shee).insert(DiplomacyOfferSheet);
    commands.entity(wait).insert(DiplomacyOfferWait);
    let offer_layout = styles.row_layout.with_justify(Justify::Center);
    let entity = spawn_shadowed_text(
        commands,
        prop,
        "",
        0.0,
        12.0,
        291.0,
        &styles.row_font,
        &offer_layout,
        styles.row_line_height,
        styles.foreground,
        styles.shadow,
    );
    commands.entity(entity).insert(DiplomacyText::Offer);

    let treasury = find_descendant(root, fourcc!("trea"), children, tags);
    commands.entity(treasury).insert(DiplomacyText::Treasury);
    let left = find_descendant(root, fourcc!("ltab"), children, tags);
    commands.entity(left).insert(DiplomacyTopicBracket {
        left: true,
        pictures: pictures.clone(),
    });
    let right = find_descendant(root, fourcc!("rtab"), children, tags);
    commands.entity(right).insert(DiplomacyTopicBracket {
        left: false,
        pictures,
    });
    map
}
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_diplomacy_panel_text(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    information: Entity,
    treaties: Entity,
    grants: Entity,
    trade: Entity,
    council: Entity,
    styles: &DiplomacyTextStyles,
    assets: &mut RetailUiAssets,
) {
    spawn_shadowed_text(
        commands,
        information,
        "Information:",
        15.0,
        13.0,
        95.0,
        &styles.title_font,
        &styles.title_layout,
        styles.title_line_height,
        styles.foreground,
        styles.shadow,
    );
    let entity = spawn_shadowed_text(
        commands,
        information,
        "",
        110.0,
        13.0,
        120.0,
        &styles.title_font,
        &styles.title_layout,
        styles.title_line_height,
        styles.foreground,
        styles.shadow,
    );
    commands
        .entity(entity)
        .insert(DiplomacyText::Info(DiplomacyInfoField::Name));
    for (row, top) in [54.0, 71.0, 88.0].into_iter().enumerate() {
        let entity = spawn_shadowed_text(
            commands,
            information,
            "",
            15.0,
            top,
            95.0,
            &styles.row_font,
            &styles.row_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert(DiplomacyText::Info(DiplomacyInfoField::Label(row as u8)));
        let entity = spawn_shadowed_text(
            commands,
            information,
            "",
            110.0,
            top,
            120.0,
            &styles.row_font,
            &styles.row_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert(DiplomacyText::Info(DiplomacyInfoField::Value(row as u8)));
    }

    let map_key = find_descendant(information, fourcc!("mkey"), children, tags);
    commands.entity(map_key).insert(DiplomacyMapKey {
        owner: assets
            .picture(PictureId::new(0x1393))
            .expect("retail diplomacy owner map key must load"),
        relationship_type: assets
            .picture(PictureId::new(0x1395))
            .expect("retail diplomacy relationship-type map key must load"),
        relationship_notch: assets
            .picture(PictureId::new(0x1396))
            .expect("retail diplomacy relationship-notch map key must load"),
        trade: assets
            .picture(PictureId::new(0x1397))
            .expect("retail diplomacy trade map key must load"),
    });
    let key_label_layout = styles.key_layout.with_justify(Justify::Left);
    spawn_shadowed_text(
        commands,
        map_key,
        "Map Key",
        106.0,
        12.0,
        100.0,
        &styles.key_font,
        &key_label_layout,
        styles.key_line_height,
        styles.foreground,
        styles.shadow,
    );
    spawn_shadowed_text(
        commands,
        map_key,
        "Minor Nation",
        153.0,
        108.0,
        100.0,
        &styles.key_font,
        &key_label_layout,
        styles.key_line_height,
        styles.foreground,
        styles.shadow,
    );
    for (major, tag) in MajorNationId::all().zip(DIPLOMACY_MAP_KEY_MAJOR_NAME_TAGS) {
        commands
            .entity(find_descendant(root, tag, children, tags))
            .insert((DiplomacyText::MapKeyMajorName(major), Visibility::Inherited));
    }

    for (text, left, top, title) in [
        ("Foreign Grants", 15.0, 13.0, true),
        ("Relationship:", 174.0, 13.0, false),
        ("Bad", 276.0, 30.0, false),
        ("Good", 440.0, 30.0, false),
        ("$1,000", 37.0, 115.0, false),
        ("$3,000", 175.0, 115.0, false),
        ("$5,000", 314.0, 115.0, false),
        ("$10,000", 446.0, 115.0, false),
    ] {
        let (font, layout, line_height) = if title {
            (
                &styles.title_font,
                &styles.title_layout,
                styles.title_line_height,
            )
        } else {
            (&styles.row_font, &styles.row_layout, styles.row_line_height)
        };
        spawn_shadowed_text(
            commands,
            grants,
            text,
            left,
            top,
            100.0,
            font,
            layout,
            line_height,
            styles.foreground,
            styles.shadow,
        );
    }
    let entity = spawn_shadowed_text(
        commands,
        grants,
        "",
        15.0,
        37.0,
        180.0,
        &styles.row_font,
        &styles.row_layout,
        styles.row_line_height,
        styles.foreground,
        styles.shadow,
    );
    commands.entity(entity).insert(DiplomacyText::GrantTotal);

    for (text, left, top, title) in [
        ("Trade Policies", 15.0, 13.0, true),
        ("5%", 25.0, 85.0, false),
        ("10%", 74.0, 34.0, false),
        ("25%", 125.0, 85.0, false),
        ("50%", 177.0, 34.0, false),
        ("75%", 228.0, 85.0, false),
        ("100%", 275.0, 34.0, false),
    ] {
        let (font, layout, line_height) = if title {
            (
                &styles.title_font,
                &styles.title_layout,
                styles.title_line_height,
            )
        } else {
            (&styles.row_font, &styles.row_layout, styles.row_line_height)
        };
        spawn_shadowed_text(
            commands,
            trade,
            text,
            left,
            top,
            100.0,
            font,
            layout,
            line_height,
            styles.foreground,
            styles.shadow,
        );
    }
    let centered_layout = styles.row_layout.with_justify(Justify::Center);
    for (text, center) in [
        ("Subsidies", 156.0),
        ("Boycott", 380.0),
        ("Colony Boycott", 473.0),
    ] {
        spawn_shadowed_text(
            commands,
            trade,
            text,
            center - 50.0,
            108.0,
            100.0,
            &styles.row_font,
            &centered_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
    }

    spawn_shadowed_text(
        commands,
        treaties,
        &get_string(assets, 0x2733, 0x20),
        15.0,
        13.0,
        200.0,
        &styles.title_font,
        &styles.title_layout,
        styles.title_line_height,
        styles.foreground,
        styles.shadow,
    );
    let treaty_layout = styles.map_layout.with_justify(Justify::Center);
    for (index, (center, top)) in TREATY_LABEL_CENTERS.into_iter().enumerate() {
        spawn_shadowed_text(
            commands,
            treaties,
            &get_string(assets, 0x2733, index as i16 + 6),
            center - 50.0,
            top,
            100.0,
            &styles.map_font,
            &treaty_layout,
            styles.map_line_height,
            styles.foreground,
            styles.shadow,
        );
    }

    let council_title_layout = styles.title_layout.with_justify(Justify::Center);
    let entity = spawn_shadowed_text(
        commands,
        council,
        "",
        0.0,
        36.0,
        518.0,
        &styles.title_font,
        &council_title_layout,
        styles.title_line_height,
        styles.foreground,
        styles.shadow,
    );
    commands
        .entity(entity)
        .insert((DiplomacyText::Council(0), Visibility::Inherited));
    let council_label_layout = styles.row_layout.with_justify(Justify::Right);
    for row in 0..3_u8 {
        let top = 60.0 + f32::from(row) * 16.0;
        let entity = spawn_shadowed_text(
            commands,
            council,
            "",
            0.0,
            top,
            259.0,
            &styles.row_font,
            &council_label_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert((DiplomacyText::Council(1 + row * 2), Visibility::Inherited));
        let entity = spawn_shadowed_text(
            commands,
            council,
            "",
            263.0,
            top,
            100.0,
            &styles.row_font,
            &styles.row_layout,
            styles.row_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert((DiplomacyText::Council(2 + row * 2), Visibility::Inherited));
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_shadowed_text(
    commands: &mut Commands,
    parent: Entity,
    text: &str,
    left: f32,
    top: f32,
    width: f32,
    font: &TextFont,
    layout: &TextLayout,
    line_height: LineHeight,
    foreground: Color,
    shadow: Color,
) -> Entity {
    commands
        .spawn((
            Node {
                position_type: PositionType::Absolute,
                left: Val::Px(left),
                top: Val::Px(top),
                width: Val::Px(width),
                ..default()
            },
            Text::new(text),
            font.clone(),
            *layout,
            line_height,
            TextColor(foreground),
            TextShadow {
                offset: Vec2::new(-1.0, -1.0),
                color: shadow,
            },
            Pickable::IGNORE,
            ChildOf(parent),
        ))
        .id()
}
pub(super) fn sync_diplomacy_controls(
    mut commands: Commands,
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    mut panels: Query<(&DiplomacyPanel, &mut Node)>,
    controls: Query<(Entity, &DiplomacyAction, Option<&Checked>)>,
    mut brackets: Query<(&DiplomacyTopicBracket, &mut ImageNode, &mut Visibility)>,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    for (panel, mut node) in &mut panels {
        node.top = Val::Px(if panel.0 == screen.topic() {
            PANEL_TOP
        } else {
            PANEL_OFFSCREEN_TOP
        });
    }
    for (entity, action, checked) in &controls {
        let selected = match (*action, screen.mode) {
            (
                DiplomacyAction::Grant { row, recurring },
                DiplomacyMode::Grants {
                    row: selected_row,
                    recurring: selected_recurring,
                },
            ) => row == selected_row && recurring == selected_recurring,
            (
                DiplomacyAction::Trade(row),
                DiplomacyMode::Trade {
                    row: selected_row,
                    colony_boycott: false,
                },
            ) => row == selected_row,
            (DiplomacyAction::Treaty(row), DiplomacyMode::Treaties { row: selected_row }) => {
                row == selected_row
            }
            (DiplomacyAction::Overlay(mode), DiplomacyMode::Information { overlay }) => {
                overlay == mode
            }
            (
                DiplomacyAction::ColonyBoycott,
                DiplomacyMode::Trade {
                    colony_boycott: true,
                    ..
                },
            ) => true,
            (
                DiplomacyAction::Topic(_)
                | DiplomacyAction::AcceptOffer
                | DiplomacyAction::RejectOffer,
                _,
            ) => continue,
            _ => false,
        };
        set_checked(&mut commands, entity, checked.is_some(), selected);
    }
    for (bracket, mut image, mut visibility) in &mut brackets {
        let visible = bracket.left
            == matches!(
                screen.topic(),
                DiplomacyTopic::Information | DiplomacyTopic::Council
            );
        *visibility = if visible {
            Visibility::Visible
        } else {
            Visibility::Hidden
        };
        let picture = match screen.topic() {
            DiplomacyTopic::Information => &bracket.pictures.information,
            DiplomacyTopic::Treaties => &bracket.pictures.treaties,
            DiplomacyTopic::Grants => &bracket.pictures.grants,
            DiplomacyTopic::Trade => &bracket.pictures.trade,
            DiplomacyTopic::Council => &bracket.pictures.council,
            // Offers uses the sheet overlay, not a topic-bracket picture.
            DiplomacyTopic::Offers => {
                *visibility = Visibility::Hidden;
                continue;
            }
        };
        image.image = picture.clone();
    }
}
#[allow(clippy::type_complexity)]
pub(super) fn project_diplomacy_text(
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    assets: Res<RetailAssetsResource>,
    mut texts: Query<
        (
            &DiplomacyText,
            &mut Text,
            Option<&mut Node>,
            Option<&mut Visibility>,
        ),
        Without<DiplomacyNationIcon>,
    >,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let state = &session.game;
    let source = MajorNationId::from_nation(state.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let major = state.nations().major(source);
    let (name, labels_by_row, values_by_row) = diplomacy_information(state, screen.framed_nation);
    let offer = diplomacy_offer_message(state, &assets)
        .or_else(|| diplomacy_war_join_message(state, &assets));
    let show_map_key_names = match screen.mode {
        DiplomacyMode::Information { overlay } => overlay == 0,
        _ => true,
    };
    let council = council_panel_text(state, &assets);
    for (kind, mut text, mut node, mut visibility) in &mut texts {
        match *kind {
            DiplomacyText::Treasury => text.0 = format_currency(major.common.treasury),
            DiplomacyText::GrantTotal => {
                text.0 = format!(
                    "Promised Grants: {}",
                    format_currency(major.economy.grant_total_cost)
                );
            }
            DiplomacyText::Offer => {
                if let Some(message) = &offer {
                    text.0.clone_from(message);
                }
            }
            DiplomacyText::Info(DiplomacyInfoField::Name) => text.0.clone_from(&name),
            DiplomacyText::Info(DiplomacyInfoField::Label(row)) => {
                text.0.clone_from(&labels_by_row[usize::from(row)]);
            }
            DiplomacyText::Info(DiplomacyInfoField::Value(row)) => {
                text.0.clone_from(&values_by_row[usize::from(row)]);
            }
            DiplomacyText::MapKeyMajorName(major) => {
                text.0.clear();
                text.0
                    .push_str(state.nations().display_name(major.nation()).unwrap_or(""));
                if let Some(visibility) = visibility.as_mut() {
                    **visibility = if show_map_key_names {
                        Visibility::Visible
                    } else {
                        Visibility::Hidden
                    };
                }
            }
            DiplomacyText::Council(0) => {
                text.0.clone_from(&council.title);
                if let Some(visibility) = visibility.as_mut() {
                    **visibility = Visibility::Visible;
                }
            }
            DiplomacyText::Council(index) => {
                let row = usize::from((index - 1) / 2);
                let is_value = index % 2 == 0;
                if let Some(rows) = &council.rows {
                    text.0
                        .clone_from(if is_value { &rows[row].1 } else { &rows[row].0 });
                    if let Some(visibility) = visibility.as_mut() {
                        **visibility = Visibility::Visible;
                    }
                } else {
                    text.0.clear();
                    if let Some(visibility) = visibility.as_mut() {
                        **visibility = Visibility::Hidden;
                    }
                }
            }
            DiplomacyText::NationName(nation) => {
                let Some(visibility) = visibility.as_mut() else {
                    continue;
                };
                let Some(anchor) = representative_tile_for_nation(state, nation) else {
                    **visibility = Visibility::Hidden;
                    continue;
                };
                let Some(display_name) = state.nations().display_name(nation) else {
                    **visibility = Visibility::Hidden;
                    continue;
                };
                if display_name.is_empty() {
                    **visibility = Visibility::Hidden;
                    continue;
                }
                if let Some(node) = node.as_mut() {
                    let (row, column) = state.map().geometry().row_column(anchor);
                    let offset = f32::from(MajorNationId::from_nation(nation).is_none());
                    node.left = Val::Px(f32::from(column) * 5.0 - 45.0 + offset);
                    node.top = Val::Px(f32::from(row) * 5.0 - 6.0 + offset);
                }
                text.0.clear();
                text.0.push_str(display_name);
                **visibility = Visibility::Visible;
            }
        }
    }
}

pub(super) fn sync_diplomacy_information(
    session: Res<GameSession>,
    screens: Query<Ref<DiplomacyScreen>>,
    mut map_keys: Query<(&DiplomacyMapKey, &mut ImageNode), Without<DiplomacyNationIcon>>,
    mut icons: Query<
        (
            &DiplomacyNationIcon,
            &mut ImageNode,
            &mut Node,
            &mut Visibility,
        ),
        Without<DiplomacyText>,
    >,
) {
    let screen = screens
        .single()
        .expect("Diplomacy state has one Diplomacy screen");
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let state = &session.game;
    for (map_key, mut image) in &mut map_keys {
        image.image = match screen.mode {
            DiplomacyMode::Information { overlay: 1 } => map_key.relationship_notch.clone(),
            DiplomacyMode::Information { overlay: 2 } => map_key.trade.clone(),
            DiplomacyMode::Information { overlay: 4 } => map_key.relationship_type.clone(),
            _ => map_key.owner.clone(),
        };
    }

    let mode = screen.interaction_mode();
    let show_compat = matches!(mode, 1 | 2 | 4);
    let framed_major = MajorNationId::from_nation(screen.framed_nation);
    let framed_trade = state.nation(screen.framed_nation);
    for (icon, mut image, mut node, mut visibility) in &mut icons {
        let (anchor, atlas_offset, left_offset, top_offset) = match icon.kind {
            DiplomacyNationIconKind::Compatibility => {
                let level = state.diplomacy().mission_levels[screen.framed_nation][icon.nation];
                let atlas_offset = if !show_compat {
                    None
                } else {
                    match level {
                        DiplomaticMissionLevel::None => None,
                        DiplomaticMissionLevel::TradeConsulate => Some(0x170),
                        DiplomaticMissionLevel::Embassy => Some(0x180),
                    }
                };
                (
                    state.nations().home_tile(icon.nation),
                    atlas_offset,
                    0.0,
                    -8.0,
                )
            }
            DiplomacyNationIconKind::Order => {
                let atlas_offset = match mode {
                    4 => framed_major.and_then(|major| {
                        state
                            .nations()
                            .major(major)
                            .economy
                            .diplomacy_policy_by_nation[icon.nation]
                            .and_then(diplomacy_policy_icon_offset)
                    }),
                    2 => framed_trade.and_then(|common| {
                        let policy = common.trade_policy_by_nation[icon.nation];
                        let colony_boycott = framed_major.is_some_and(|major| {
                            state.nations().major(major).economy.colony_boycott_flags[icon.nation]
                                != 0
                        });
                        if policy == TradePolicyScore::BOYCOTT && colony_boycott {
                            Some(0x190)
                        } else {
                            trade_policy_icon_offset(policy)
                        }
                    }),
                    1 => framed_major.and_then(|major| {
                        state
                            .nations()
                            .major(major)
                            .economy
                            .diplomacy_grants_by_nation[icon.nation]
                            .and_then(diplomacy_grant_icon_offset)
                    }),
                    _ => None,
                };
                (
                    representative_tile_for_nation(state, icon.nation),
                    atlas_offset,
                    0.0,
                    8.0,
                )
            }
            DiplomacyNationIconKind::Boycott => {
                let mut offset_overlay = false;
                let show = mode == 2
                    && framed_major.is_some_and(|major| {
                        state.nations().major(major).economy.colony_boycott_flags[icon.nation] != 0
                    })
                    && !framed_trade.is_some_and(|common| {
                        common.trade_policy_by_nation[icon.nation] == TradePolicyScore::BOYCOTT
                    });
                let atlas_offset = if show {
                    offset_overlay = framed_trade.is_some_and(|common| {
                        common.trade_policy_by_nation[icon.nation] != TradePolicyScore::NEUTRAL
                    });
                    Some(0xc0)
                } else {
                    None
                };
                (
                    representative_tile_for_nation(state, icon.nation),
                    atlas_offset,
                    if offset_overlay { 16.0 } else { 0.0 },
                    8.0,
                )
            }
        };
        let Some(anchor) = anchor else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let Some(atlas_offset) = atlas_offset else {
            *visibility = Visibility::Hidden;
            continue;
        };
        let (row, column) = state.map().geometry().row_column(anchor);
        node.left = Val::Px(f32::from(column) * 5.0 - 8.0 + left_offset);
        node.top = Val::Px(f32::from(row) * 5.0 + top_offset);
        image.rect = Some(Rect::new(
            atlas_offset as f32,
            0.0,
            (atlas_offset + 16) as f32,
            16.0,
        ));
        *visibility = Visibility::Visible;
    }
}
pub(super) fn diplomacy_information(
    state: &GameState,
    nation: NationId,
) -> (String, [String; 3], [String; 3]) {
    let name = state
        .nations()
        .display_name(nation)
        .unwrap_or_default()
        .to_owned();
    let mut labels = ["Provinces:".to_owned(), String::new(), String::new()];
    let mut values = [
        state
            .nations()
            .owned_region_count(nation)
            .unwrap_or_default()
            .to_string(),
        String::new(),
        String::new(),
    ];
    match state.nations().country_status(nation) {
        Some(CountryStatus::ColonyOf(master)) => {
            let master = state.nations().display_name(master).unwrap_or_default();
            labels[1] = format!("Colony of {master}");
        }
        Some(CountryStatus::ProtectorateOf(_)) => labels[1] = "Anarchy".to_owned(),
        Some(CountryStatus::Independent) => {
            if let Some(major) = MajorNationId::from_nation(nation) {
                labels[1] = "Military:".to_owned();
                labels[2] = "Industry:".to_owned();
                values[1] = INFORMATION_BAND_NAMES
                    [usize::from(state.diplomacy_military_power_band(major))]
                .to_owned();
                values[2] = INFORMATION_BAND_NAMES
                    [usize::from(state.diplomacy_industry_band(major))]
                .to_owned();
            } else {
                let minor = MinorNationId::new(nation.get());
                labels[1] = "Most Favored".to_owned();
                labels[2] = "Trading Nation:".to_owned();
                values[2] = state
                    .favorite_trade_partner(minor)
                    .and_then(|partner| state.nations().display_name(partner.nation()))
                    .unwrap_or("None")
                    .to_owned();
            }
        }
        None => {}
    }
    (name, labels, values)
}

pub(super) fn diplomacy_grant_icon_offset(grant: DiplomacyGrant) -> Option<usize> {
    let row = GRANT_AMOUNTS
        .iter()
        .position(|amount| *amount == grant.amount)?;
    Some((if grant.recurring { 17 + row } else { 13 + row }) * 16)
}

pub(super) fn diplomacy_policy_icon_offset(policy: DiplomacyPolicy) -> Option<usize> {
    Some(match policy {
        DiplomacyPolicy::JoinEmpire | DiplomacyPolicy::JoinEmpireWithWarEntanglements => 0x40,
        DiplomacyPolicy::Alliance => 0x30,
        DiplomacyPolicy::NonAggressionPact => 0x20,
        DiplomacyPolicy::PeaceTreaty => 0x00,
        DiplomacyPolicy::DeclareWar => 0x10,
        DiplomacyPolicy::BuildConsulate => 0x150,
        DiplomacyPolicy::BuildEmbassy => 0x160,
    })
}

pub(super) fn trade_policy_icon_offset(policy: TradePolicyScore) -> Option<usize> {
    TRADE_POLICY_SCORES
        .iter()
        .position(|candidate| *candidate == policy)
        .map(|row| (row + 5) * 16)
}
struct CouncilPanelText {
    title: String,
    rows: Option<[(String, String); 3]>,
}

fn council_panel_text(state: &GameState, assets: &RetailAssetsResource) -> CouncilPanelText {
    let congress = &state.diplomacy().congress;
    if let (Some(chairman), Some(counterpart)) = (congress.chairman, congress.counterpart) {
        let decade = (state.turn().economic_turn / 4) / 10 * 10 + 1815;
        CouncilPanelText {
            title: fill_brackets(&assets.get_string(0x2733, 0x35), &[&decade.to_string()]),
            rows: Some([
                (
                    format!(
                        "{}:",
                        state
                            .nations()
                            .display_name(chairman.nation())
                            .unwrap_or("")
                    ),
                    congress.chairman_support.to_string(),
                ),
                (
                    format!(
                        "{}:",
                        state
                            .nations()
                            .display_name(counterpart.nation())
                            .unwrap_or("")
                    ),
                    congress.counterpart_support.to_string(),
                ),
                (
                    assets.get_string(0x2733, 0x36),
                    congress.neutral_support.to_string(),
                ),
            ]),
        }
    } else {
        CouncilPanelText {
            title: assets.get_string(0x2733, 0x34),
            rows: None,
        }
    }
}

pub(super) fn set_checked(
    commands: &mut Commands,
    entity: Entity,
    currently_checked: bool,
    should_be_checked: bool,
) {
    if currently_checked == should_be_checked {
        return;
    }
    if should_be_checked {
        commands.entity(entity).insert(Checked);
    } else {
        commands.entity(entity).remove::<Checked>();
    }
}
