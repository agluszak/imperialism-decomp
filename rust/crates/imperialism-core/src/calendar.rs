/// Imperialism advances its economic calendar in four quarter turns per year.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnCalendar {
    starting_year: i32,
    economic_turn: i32,
}

impl TurnCalendar {
    pub const TURNS_PER_YEAR: i32 = 4;

    pub const fn new(starting_year: i32, economic_turn: i32) -> Self {
        Self {
            starting_year,
            economic_turn,
        }
    }

    pub const fn starting_year(self) -> i32 {
        self.starting_year
    }

    pub const fn economic_turn(self) -> i32 {
        self.economic_turn
    }

    pub fn year(self) -> i32 {
        self.starting_year + self.economic_turn.div_euclid(Self::TURNS_PER_YEAR)
    }

    pub fn quarter(self) -> u8 {
        self.economic_turn.rem_euclid(Self::TURNS_PER_YEAR) as u8
    }

    /// Advances one economic quarter.
    pub fn advance(&mut self) {
        self.economic_turn += 1;
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
    fn advances_without_a_storage_width_boundary() {
        let mut calendar = TurnCalendar::new(1914, 99_999);
        calendar.advance();
        assert_eq!(calendar.economic_turn(), 100_000);
    }
}
