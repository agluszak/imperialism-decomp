use imperialism_core::{PendingActionProgress, PendingActionState};

pub fn pending_action_from_retail(status: i8, payload: i16) -> PendingActionState {
    let progress = match status {
        0 => PendingActionProgress::None,
        0x32 => PendingActionProgress::Queued,
        0x33 => PendingActionProgress::Handled,
        0x34..=0x39 => PendingActionProgress::RewardLevel(i16::from(status - 0x33)),
        _ => panic!("unrecovered pending action status {status:#04x}"),
    };
    PendingActionState::new(progress, (payload != -1).then_some(payload))
}

pub fn pending_action_to_retail(state: PendingActionState) -> (i8, i16) {
    let status = match state.progress() {
        PendingActionProgress::None => 0,
        PendingActionProgress::Queued => 0x32,
        PendingActionProgress::Handled => 0x33,
        PendingActionProgress::RewardLevel(level) => 0x33_i8.saturating_add(level as i8),
    };
    (status, state.payload().unwrap_or(-1))
}
