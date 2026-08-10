use crate::*;

impl PendingWorkState {
    /// Retail's shared news list places a newly copied record at the front for
    /// the observed phase-six producer path. Newspaper selection traverses this
    /// stored order, so the semantic queue must preserve that LIFO behavior.
    pub(crate) fn queue_newspaper_event(&mut self, event: PendingNewspaperEvent) {
        self.newspaper_events.insert(0, event);
    }

    /// Retail concatenates consulate and embassy stories by the major nation
    /// that established them. A later target joins the existing nation mask;
    /// the first target creates a new record at the front of the shared queue.
    pub(crate) fn queue_diplomatic_mission_event(
        &mut self,
        event: InterNationNewsKind,
        subject: MajorNationId,
        counterpart: NationId,
    ) {
        for pending in &mut self.newspaper_events {
            if let PendingNewspaperEvent::InterNation {
                event: pending_event,
                subject: pending_subject,
                related_nations,
            } = pending
                && *pending_event == event
                && *pending_subject == subject
            {
                related_nations[counterpart] = true;
                return;
            }
        }

        let mut related_nations = NationTable::default();
        related_nations[counterpart] = true;
        self.queue_newspaper_event(PendingNewspaperEvent::InterNation {
            event,
            subject,
            related_nations,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined_war(counterpart: MajorNationId) -> PendingNewspaperEvent {
        let mut related_nations = NationTable::default();
        related_nations[counterpart.nation()] = true;
        PendingNewspaperEvent::InterNation {
            event: InterNationNewsKind::NationJoinedWar,
            subject: MajorNationId::new(0),
            related_nations,
        }
    }

    #[test]
    fn phase_six_news_records_use_the_retail_lifo_order() {
        let first = joined_war(MajorNationId::new(1));
        let second = joined_war(MajorNationId::new(2));
        let mut pending = PendingWorkState::default();

        pending.queue_newspaper_event(first.clone());
        assert_eq!(pending.newspaper_events, vec![first.clone()]);
        pending.queue_newspaper_event(second.clone());

        assert_eq!(pending.newspaper_events, vec![second, first]);
    }
}
