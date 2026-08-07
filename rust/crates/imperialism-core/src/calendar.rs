/// Imperialism advances its economic calendar in four quarter turns per year.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnCalendar {
    starting_year: i16,
    economic_turn: i16,
}

impl TurnCalendar {
    pub const TURNS_PER_YEAR: i16 = 4;

    pub const fn new(starting_year: i16, economic_turn: i16) -> Self {
        Self {
            starting_year,
            economic_turn,
        }
    }

    pub const fn starting_year(self) -> i16 {
        self.starting_year
    }

    pub const fn economic_turn(self) -> i16 {
        self.economic_turn
    }

    pub fn year(self) -> i16 {
        self.starting_year
            .wrapping_add(self.economic_turn.div_euclid(Self::TURNS_PER_YEAR))
    }

    pub fn quarter(self) -> u8 {
        self.economic_turn.rem_euclid(Self::TURNS_PER_YEAR) as u8
    }

    /// Mirrors `TSimMgr::AdvanceSeason`: only the signed 16-bit turn counter changes.
    pub fn advance(&mut self) {
        self.economic_turn = self.economic_turn.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advances_four_quarters_per_year() {
        let mut calendar = TurnCalendar::new(1914, 1);
        assert_eq!((calendar.year(), calendar.quarter()), (1914, 1));
        calendar.advance();
        calendar.advance();
        calendar.advance();
        assert_eq!((calendar.year(), calendar.quarter()), (1915, 0));
    }

    #[test]
    fn retail_increment_wraps_like_a_short() {
        let mut calendar = TurnCalendar::new(1914, i16::MAX);
        calendar.advance();
        assert_eq!(calendar.economic_turn(), i16::MIN);
    }
}
