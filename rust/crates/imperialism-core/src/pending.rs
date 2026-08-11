use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingActionState {
    status: PendingActionStatus,
    payload: Option<i16>,
}

impl PendingActionState {
    pub const fn new(status: PendingActionStatus, payload: Option<i16>) -> Self {
        Self { status, payload }
    }
    pub(crate) const fn status(self) -> PendingActionStatus {
        self.status
    }
    pub const fn payload(self) -> Option<i16> {
        self.payload
    }
    pub(crate) fn queue(&mut self, payload: i16) {
        self.status = PendingActionStatus::Queued;
        self.payload = Some(payload);
    }
    pub(crate) const fn level(self) -> Option<i16> {
        match self.status {
            PendingActionStatus::Queued => None,
            PendingActionStatus::None | PendingActionStatus::Level3 => Some(0),
            PendingActionStatus::Level4 => Some(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingActionStatus {
    #[default]
    None,
    Queued,
    Level3,
    Level4,
}
impl PendingActionStatus {
    pub(crate) fn has_reached(self, other: Self) -> bool {
        self >= other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_action_level_is_derived_from_status_not_payload() {
        assert_eq!(
            PendingActionState::new(PendingActionStatus::None, None).level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Queued, Some(6)).level(),
            None
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Level3, Some(6)).level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Level4, Some(6)).level(),
            Some(1)
        );
    }
}
