use super::*;

pub(super) fn spawn_diplomacy_map_labels(
    commands: &mut Commands,
    map: Entity,
    styles: &DiplomacyTextStyles,
    icon_atlas: Handle<Image>,
) {
    for nation in NationId::all() {
        let entity = spawn_shadowed_text(
            commands,
            map,
            "",
            -45.0,
            -20.0,
            90.0,
            &styles.map_font,
            &styles.map_layout,
            styles.map_line_height,
            styles.foreground,
            styles.shadow,
        );
        commands
            .entity(entity)
            .insert((DiplomacyText::NationName(nation), Visibility::Hidden));
        for kind in [
            DiplomacyNationIconKind::Compatibility,
            DiplomacyNationIconKind::Order,
            DiplomacyNationIconKind::Boycott,
        ] {
            commands.spawn((
                Node {
                    position_type: PositionType::Absolute,
                    width: Val::Px(16.0),
                    height: Val::Px(16.0),
                    ..default()
                },
                ImageNode::new(icon_atlas.clone()),
                Visibility::Hidden,
                Pickable::IGNORE,
                ChildOf(map),
                DiplomacyNationIcon { nation, kind },
            ));
        }
    }
}

pub(super) fn apply_diplomacy_atlas_transparency(image: &mut Image, transparent_rgb: [u8; 3]) {
    let Some(pixels) = image.data.as_mut() else {
        return;
    };
    for pixel in pixels.chunks_exact_mut(4) {
        if pixel[..3] == transparent_rgb {
            pixel[3] = 0;
        }
    }
}
pub(super) fn on_diplomacy_map_click(
    click: On<Pointer<Click>>,
    maps: Query<&RelativeCursorPosition, With<DiplomacyMapPicture>>,
    modals: Query<(), With<ModalDialog>>,
    mut screens: Query<&mut DiplomacyScreen>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok(cursor) = maps.get(click.entity) else {
        return;
    };
    if !cursor.cursor_over() {
        return;
    }
    let Some(normalized) = cursor.normalized else {
        return;
    };
    let Some(tile) = tile_at_diplomacy_position(normalized) else {
        return;
    };
    let Some(target) = session.game.map()[tile]
        .owner_nation
        .and_then(TileOwnerTag::nation)
    else {
        return;
    };
    let mut screen = screens
        .single_mut()
        .expect("Diplomacy map has one open Diplomacy screen");
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let rejection = match screen.mode {
        DiplomacyMode::Information { .. } => {
            if screen.framed_nation != target {
                screen.framed_nation = target;
            }
            None
        }
        DiplomacyMode::Council | DiplomacyMode::Offers => None,
        DiplomacyMode::Treaties { row } => {
            let Some(policy) = TREATY_POLICIES.get(row).copied() else {
                return;
            };
            match session
                .game
                .toggle_player_diplomacy_policy(source, target, policy, false)
            {
                PlayerDiplomacyOrderResult::NeedsEntanglementConfirmation => {
                    commands.trigger(OpenDiplomacyEntanglementNotice { target, policy });
                    None
                }
                other => player_diplomacy_rejection(other),
            }
        }
        DiplomacyMode::Grants { row, recurring } => {
            player_diplomacy_rejection(session.game.toggle_player_diplomacy_grant(
                source,
                target,
                DiplomacyGrant {
                    amount: GRANT_AMOUNTS[row],
                    recurring,
                },
            ))
        }
        DiplomacyMode::Trade {
            row,
            colony_boycott,
        } => {
            if colony_boycott {
                player_diplomacy_rejection(
                    session.game.toggle_player_colony_boycott(source, target),
                )
            } else {
                player_diplomacy_rejection(session.game.toggle_player_trade_policy(
                    source,
                    target,
                    TRADE_POLICY_SCORES[row],
                ))
            }
        }
    };
    if let Some(rejection) = rejection {
        commands.trigger(OpenDiplomacyRejectionNotice { rejection });
    }
}
pub(super) fn tile_at_diplomacy_position(normalized: Vec2) -> Option<TileId> {
    let column_pixel = ((normalized.x + 0.5) * MAP_WIDTH).floor();
    let row_pixel = ((normalized.y + 0.5) * MAP_HEIGHT).floor();
    if !(0.0..MAP_WIDTH).contains(&column_pixel) || !(0.0..MAP_HEIGHT).contains(&row_pixel) {
        return None;
    }
    let row = row_pixel as u16 / MAP_TILE_SCALE;
    let odd_offset = MAP_ODD_ROW_OFFSET * (row & 1);
    let column = (column_pixel as u16).checked_sub(odd_offset)? / MAP_TILE_SCALE;
    MapGeometry::new(MapTopology::Bounded).tile(row, column)
}

pub(super) fn sync_diplomacy_map_cursor(
    maps: Query<&RelativeCursorPosition, With<DiplomacyMapPicture>>,
    modals: Query<(), With<ModalDialog>>,
    screens: Query<&DiplomacyScreen>,
    session: Res<GameSession>,
    mut requested: ResMut<RequestedCursor>,
) {
    if !modals.is_empty() {
        request_arrow_cursor(&mut requested);
        return;
    }
    let Ok(screen) = screens.single() else {
        request_arrow_cursor(&mut requested);
        return;
    };
    let Ok(cursor) = maps.single() else {
        request_arrow_cursor(&mut requested);
        return;
    };
    if !cursor.cursor_over() {
        request_arrow_cursor(&mut requested);
        return;
    }
    let Some(normalized) = cursor.normalized else {
        request_turn_event_cursor(&mut requested, DIPLOMACY_IDLE_CURSOR);
        return;
    };
    let source = MajorNationId::from_nation(session.game.turn().active_nation)
        .expect("Diplomacy screen requires an active major nation");
    let Some(target) = tile_at_diplomacy_position(normalized).and_then(|tile| {
        session.game.map()[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
    }) else {
        request_turn_event_cursor(&mut requested, DIPLOMACY_IDLE_CURSOR);
        return;
    };
    let mut action = screen.cursor_action();
    if action != DiplomacyMapAction::InspectNation && target == source.nation() {
        action = DiplomacyMapAction::SelectedNation;
    }
    let valid = session
        .game
        .player_diplomacy_map_action_is_valid(source, target, action);
    request_turn_event_cursor(
        &mut requested,
        diplomacy_map_cursor_resource_id(true, action, screen.cursor_row(), valid),
    );
}

pub(super) fn reset_diplomacy_cursor(mut requested: ResMut<RequestedCursor>) {
    request_arrow_cursor(&mut requested);
}

/// `TDiplomacyMapView::HandleCursorHoverSelectionByChildHitTestAndFallback` cursor id.
pub(super) fn diplomacy_map_cursor_resource_id(
    nation_hit: bool,
    action: DiplomacyMapAction,
    grant_row: usize,
    valid: bool,
) -> u16 {
    if !nation_hit || !valid {
        return DIPLOMACY_IDLE_CURSOR;
    }
    let mut resource_id = DIPLOMACY_CURSOR_BY_ACTION[action];
    if matches!(
        action,
        DiplomacyMapAction::TradeSubsidy
            | DiplomacyMapAction::OneTimeGrant
            | DiplomacyMapAction::RecurringGrant
    ) {
        resource_id += u16::try_from(grant_row).expect("diplomacy grant row fits u16");
    }
    resource_id
}
pub(super) fn render_diplomacy_map(
    mut commands: Commands,
    session: Res<GameSession>,
    mut assets: RetailUiAssets,
    screen: Single<Ref<DiplomacyScreen>>,
    map: Single<(Entity, Option<&ImageNode>), With<DiplomacyMapPicture>>,
) {
    if !session.is_changed() && !screen.is_added() && !screen.is_changed() {
        return;
    }
    let (entity, image_node) = map.into_inner();
    let state = &session.game;
    let framed = screen.framed_nation;
    let pixels = match screen.interaction_mode() {
        1 => compose_owner_preview_indices_with_fill(
            |tile| state.map()[tile].owner_nation,
            framed,
            |nation| {
                RELATIONSHIP_NOTCH_PALETTES
                    [usize::from(state.diplomacy_relationship_notch(framed, nation))]
            },
        ),
        4 => compose_owner_preview_indices_with_fill(
            |tile| state.map()[tile].owner_nation,
            framed,
            |nation| diplomacy_relationship_fill(state, framed, nation),
        ),
        _ => compose_owner_preview_indices(|tile| state.map()[tile].owner_nation, framed),
    };
    let image = preview_image_from_indices(&pixels, assets.default_dib_palette());
    if let Some(image_node) = image_node {
        assets.replace_image(&image_node.image, image);
    } else {
        let handle = assets.add_image(image);
        commands.entity(entity).insert(ImageNode::new(handle));
    }
}
pub(super) fn diplomacy_relationship_fill(
    state: &GameState,
    framed: NationId,
    nation: NationId,
) -> u8 {
    if nation == framed {
        return RELATIONSHIP_SELF_PALETTE;
    }
    relationship_type_palette(state.diplomacy().relationships[framed][nation])
}

pub(super) fn relationship_type_palette(relationship: DiplomaticRelationship) -> u8 {
    // Mode-4 fills use `g_aDiplomacyRelationPaletteColorCodes` through `TViewMgr::GetColor`.
    match relationship {
        DiplomaticRelationship::Alliance => 0x1b,
        DiplomaticRelationship::NonAggressionPact => 0x21,
        DiplomaticRelationship::Peace => 0x29,
        DiplomaticRelationship::JoinedEmpire => 0x22,
        DiplomaticRelationship::War => 0x17,
    }
}
pub(super) fn representative_tile_for_nation(
    state: &GameState,
    nation: NationId,
) -> Option<TileId> {
    let home_region_class = state
        .nations()
        .home_tile(nation)
        .and_then(|tile| state.map()[tile].province)
        .and_then(|province| state.map().provinces[province].region_class);
    let geometry = state.map().geometry();
    let mut column_sum = 0_u32;
    let mut row_sum = 0_u32;
    let mut tile_count = 0_u32;
    let mut west_count = 0_u32;
    let mut east_count = 0_u32;
    let mut fallback = None;

    for tile in TileId::all() {
        if state.map()[tile]
            .owner_nation
            .and_then(TileOwnerTag::nation)
            != Some(nation)
        {
            continue;
        }
        fallback = Some(tile);
        if let Some(home_region_class) = home_region_class
            && state.map()[tile]
                .province
                .and_then(|province| state.map().provinces[province].region_class)
                != Some(home_region_class)
        {
            continue;
        }
        let (row, column) = geometry.row_column(tile);
        if column < 25 {
            west_count += 1;
        }
        if column > 83 {
            east_count += 1;
        }
        column_sum += u32::from(column);
        row_sum += u32::from(row);
        tile_count += 1;
    }

    if tile_count == 0 {
        return (state
            .nations()
            .owned_region_count(nation)
            .unwrap_or_default()
            > 0)
        .then_some(fallback)
        .flatten();
    }
    if west_count != 0 && east_count != 0 {
        column_sum += west_count * u32::from(STRATEGIC_MAP_WIDTH);
    }
    let column = (column_sum / tile_count) % u32::from(STRATEGIC_MAP_WIDTH);
    let row = row_sum / tile_count;
    Some(TileId::new(
        (row * u32::from(STRATEGIC_MAP_WIDTH) + column) as u16,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationship_type_fill_uses_get_color_of_retail_relation_codes() {
        assert_eq!(
            relationship_type_palette(DiplomaticRelationship::Alliance),
            0x1b
        );
        assert_eq!(
            relationship_type_palette(DiplomaticRelationship::NonAggressionPact),
            0x21
        );
        assert_eq!(
            relationship_type_palette(DiplomaticRelationship::Peace),
            0x29
        );
        assert_eq!(
            relationship_type_palette(DiplomaticRelationship::JoinedEmpire),
            0x22
        );
        assert_eq!(relationship_type_palette(DiplomaticRelationship::War), 0x17);
    }

    #[test]
    fn idle_cursor_when_the_pointer_is_not_over_a_nation() {
        assert_eq!(
            diplomacy_map_cursor_resource_id(false, DiplomacyMapAction::DeclareWar, 0, true),
            DIPLOMACY_IDLE_CURSOR
        );
    }

    #[test]
    fn invalid_target_uses_the_idle_diplomacy_cursor() {
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::Alliance, 0, false),
            DIPLOMACY_IDLE_CURSOR
        );
    }

    #[test]
    fn inspect_and_treaty_actions_use_the_retail_cursor_ids() {
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::InspectNation, 0, true),
            0x3f3
        );
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::DeclareWar, 0, true),
            0x405
        );
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::BuildEmbassy, 0, true),
            0x41a
        );
    }

    #[test]
    fn grant_and_subsidy_rows_offset_the_base_cursor_id() {
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::OneTimeGrant, 3, true),
            0x414
        );
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::RecurringGrant, 1, true),
            0x416
        );
        assert_eq!(
            diplomacy_map_cursor_resource_id(true, DiplomacyMapAction::TradeSubsidy, 2, true),
            0x40b
        );
    }
}
