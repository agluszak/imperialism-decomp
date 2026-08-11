use super::*;

pub(in crate::ui::city) fn on_city_amount_bar_click(
    mut click: On<Pointer<Click>>,
    bars: Query<(&RelativeCursorPosition, &CityIndustryAmountBar)>,
    modals: Query<(), With<ModalDialog>>,
    dialogs: Query<Entity, With<CityBuildingDialog>>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    session: Option<ResMut<GameSession>>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok((cursor, bar)) = bars.get(click.entity) else {
        return;
    };
    let Some(normalized) = cursor.normalized.filter(|_| cursor.cursor_over()) else {
        return;
    };
    if dialogs.get(bar.dialog).is_err() {
        return;
    }
    let mut session =
        session.expect("city amount bar activated without an authoritative game session");
    click.propagate(false);
    let x = (((normalized.x + 0.5) * f32::from(INDUSTRY_BAR_WIDTH)).floor() as i16)
        .clamp(0, INDUSTRY_BAR_WIDTH - 1);
    let city = session.0.nations().major(bar.nation).city();
    let capacity = city.production_orders[bar.slot];
    let previous = match bar.order {
        CityOrderId::Item(output) => {
            city.orders.items[output.resource()]
                .as_ref()
                .expect("industry amount bar has a retail item order")
                .progress
                .quantity
        }
        _ => unreachable!("industry amount bar has an item order"),
    };
    let mut quantity = if capacity > 0
        && i32::from(x) < i32::from(INDUSTRY_BAR_WIDTH) / (i32::from(capacity) * 2)
    {
        0
    } else if capacity > 0 {
        (i32::from(x) * i32::from(capacity) / i32::from(INDUSTRY_BAR_WIDTH) + 1) as i16
    } else {
        1
    };
    if quantity == 0 && x != 0 && previous == 0 {
        quantity = 1;
    }
    if !session
        .0
        .set_city_order_quantity(bar.nation, bar.order, quantity)
        .applied()
        || quantity == previous
    {
        return;
    }
    for dialog in &dialogs {
        commands.entity(dialog).insert(CityDialogNeedsSync);
    }
    for root in &screen_roots {
        commands.entity(root).insert(CityScreenNeedsSync);
    }
}

pub(in crate::ui::city) fn on_armory_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<(Entity, &ArmoryRowChoice, Has<Checked>)>,
    modals: Query<(), With<ModalDialog>>,
    mut selections: Query<&mut ArmorySelection>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    if !change.value {
        return;
    }
    let Ok((_, row, _)) = rows.get(change.source) else {
        return;
    };
    let Ok(mut selection) = selections.get_mut(row.dialog) else {
        return;
    };
    selection.category = row.category;
    for (entity, candidate, checked) in &rows {
        if candidate.dialog != row.dialog {
            continue;
        }
        let should_check = candidate.category == row.category;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
    commands.entity(row.dialog).insert(CityDialogNeedsSync);
}

pub(in crate::ui::city) fn select_university_row(
    dialog: Entity,
    kind: CivilianUnitKind,
    selections: &mut Query<&mut UniversitySelection>,
    rows: &Query<(Entity, &UniversityRowChoice, Has<Checked>)>,
    commands: &mut Commands,
) {
    let Ok(mut selection) = selections.get_mut(dialog) else {
        return;
    };
    selection.kind = kind;
    for (entity, candidate, checked) in rows.iter() {
        if candidate.dialog != dialog {
            continue;
        }
        let should_check = candidate.kind == kind;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
    commands.entity(dialog).insert(CityDialogNeedsSync);
}

pub(in crate::ui::city) fn on_university_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<(Entity, &UniversityRowChoice, Has<Checked>)>,
    modals: Query<(), With<ModalDialog>>,
    mut selections: Query<&mut UniversitySelection>,
    mut commands: Commands,
) {
    if !modals.is_empty() || !change.value {
        return;
    }
    let Ok((_, row, _)) = rows.get(change.source) else {
        return;
    };
    select_university_row(row.dialog, row.kind, &mut selections, &rows, &mut commands);
}

pub(in crate::ui::city) fn select_shipyard_row(
    dialog: Entity,
    slot: ShipOrderSlot,
    selections: &mut Query<&mut ShipyardSelection>,
    rows: &Query<(Entity, &ShipyardRowChoice, Has<Checked>)>,
    commands: &mut Commands,
) {
    if !rows
        .iter()
        .any(|(_, row, _)| row.dialog == dialog && row.slot == slot)
    {
        return;
    }
    let Ok(mut selection) = selections.get_mut(dialog) else {
        return;
    };
    selection.slot = slot;
    for (entity, candidate, checked) in rows.iter() {
        if candidate.dialog != dialog {
            continue;
        }
        let should_check = candidate.slot == slot;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
    commands.entity(dialog).insert(CityDialogNeedsSync);
}

pub(in crate::ui::city) fn on_shipyard_row_selected(
    change: On<ValueChange<bool>>,
    rows: Query<(Entity, &ShipyardRowChoice, Has<Checked>)>,
    modals: Query<(), With<ModalDialog>>,
    mut selections: Query<&mut ShipyardSelection>,
    mut commands: Commands,
) {
    if !modals.is_empty() || !change.value {
        return;
    }
    let Ok((_, row, _)) = rows.get(change.source) else {
        return;
    };
    select_shipyard_row(row.dialog, row.slot, &mut selections, &rows, &mut commands);
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ui::city) fn on_city_order_adjust(
    activate: On<Activate>,
    actions: Query<&CityOrderAdjust>,
    modals: Query<(), With<ModalDialog>>,
    dialogs: Query<Entity, With<CityBuildingDialog>>,
    mut armory_selections: Query<&mut ArmorySelection>,
    armory_rows: Query<(Entity, &ArmoryRowChoice, Has<Checked>)>,
    mut university_selections: Query<&mut UniversitySelection>,
    university_rows: Query<(Entity, &UniversityRowChoice, Has<Checked>)>,
    mut shipyard_selections: Query<&mut ShipyardSelection>,
    shipyard_rows: Query<(Entity, &ShipyardRowChoice, Has<Checked>)>,
    screen_roots: Query<Entity, With<CityScreenRoot>>,
    session: Option<ResMut<GameSession>>,
    mut commands: Commands,
) {
    if !modals.is_empty() {
        return;
    }
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    if dialogs.get(action.dialog).is_err() {
        return;
    }
    let mut session =
        session.expect("city order control activated without an authoritative game session");
    if let CityOrderId::MilitaryRecruit(category) = action.order
        && let Ok(mut selection) = armory_selections.get_mut(action.dialog)
    {
        selection.category = category;
        commands.entity(action.dialog).insert(CityDialogNeedsSync);
        for (entity, row, checked) in &armory_rows {
            if row.dialog != action.dialog {
                continue;
            }
            let should_check = row.category == category;
            if should_check && !checked {
                commands.entity(entity).insert(Checked);
            } else if !should_check && checked {
                commands.entity(entity).remove::<Checked>();
            }
        }
    }
    if let CityOrderId::CivilianRecruit(kind) = action.order {
        select_university_row(
            action.dialog,
            kind,
            &mut university_selections,
            &university_rows,
            &mut commands,
        );
    }
    if let CityOrderId::Ship(slot) = action.order {
        select_shipyard_row(
            action.dialog,
            slot,
            &mut shipyard_selections,
            &shipyard_rows,
            &mut commands,
        );
    }
    if !session
        .0
        .adjust_city_order(action.nation, action.order, action.delta)
        .applied()
    {
        return;
    }
    for dialog in &dialogs {
        commands.entity(dialog).insert(CityDialogNeedsSync);
    }
    for root in &screen_roots {
        commands.entity(root).insert(CityScreenNeedsSync);
    }
}
