//! Retail `scores.dat`: ten `(i32 score, 32-byte NUL-terminated name)` records.
//!
//! `TSimMgr::UpdatePersistentTopTenNationScores` (0x00581510) inserts the active
//! nation's `GenerateGameScore` total at the first index where `score > stored`.
//! Equal scores rank lower.

pub const HIGH_SCORE_COUNT: usize = 10;
pub const HIGH_SCORE_NAME_LENGTH: usize = 0x20;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HighScoreEntry {
    pub score: i32,
    pub name: String,
}

pub type HighScoreTable = [HighScoreEntry; HIGH_SCORE_COUNT];

pub fn empty_high_score_table() -> HighScoreTable {
    std::array::from_fn(|_| HighScoreEntry::default())
}

pub fn read_scores_dat(bytes: &[u8]) -> HighScoreTable {
    let mut table = empty_high_score_table();
    let mut offset = 0;
    for entry in &mut table {
        if offset + 4 + HIGH_SCORE_NAME_LENGTH > bytes.len() {
            break;
        }
        entry.score = i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let name = &bytes[offset..offset + HIGH_SCORE_NAME_LENGTH];
        offset += HIGH_SCORE_NAME_LENGTH;
        let length = name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(name.len());
        entry.name = String::from_utf8_lossy(&name[..length]).into_owned();
    }
    table
}

pub fn write_scores_dat(table: &HighScoreTable) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HIGH_SCORE_COUNT * (4 + HIGH_SCORE_NAME_LENGTH));
    for entry in table {
        bytes.extend_from_slice(&entry.score.to_le_bytes());
        let mut name = [0_u8; HIGH_SCORE_NAME_LENGTH];
        let encoded = entry.name.as_bytes();
        let copy = encoded.len().min(HIGH_SCORE_NAME_LENGTH - 1);
        name[..copy].copy_from_slice(&encoded[..copy]);
        bytes.extend_from_slice(&name);
    }
    bytes
}

/// Insert `score`/`name` at the first index where `score > stored`. Equals rank lower.
pub fn insert_high_score(table: &mut HighScoreTable, score: i32, name: &str) -> Option<usize> {
    let rank = table.iter().position(|entry| score > entry.score)?;
    table[rank..].rotate_right(1);
    table[rank] = HighScoreEntry {
        score,
        name: name.to_string(),
    };
    Some(rank)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bytes_fill_remaining_slots_with_zero() {
        let table = read_scores_dat(&[]);
        assert!(
            table
                .iter()
                .all(|entry| entry.score == 0 && entry.name.is_empty())
        );
    }

    #[test]
    fn insert_first_middle_and_last() {
        let mut table = empty_high_score_table();
        for score in [90, 80, 70, 60, 50, 40, 30, 20, 10] {
            insert_high_score(&mut table, score, &format!("n{score}"));
        }
        assert_eq!(insert_high_score(&mut table, 100, "first"), Some(0));
        assert_eq!(table[0].name, "first");
        assert_eq!(insert_high_score(&mut table, 55, "mid"), Some(5));
        assert_eq!(table[5].name, "mid");
        assert_eq!(table[9].score, 20);
        assert_eq!(insert_high_score(&mut table, 21, "last"), Some(9));
        assert_eq!(table[9].name, "last");
    }

    #[test]
    fn equal_scores_rank_lower() {
        let mut table = empty_high_score_table();
        insert_high_score(&mut table, 50, "a");
        insert_high_score(&mut table, 50, "b");
        assert_eq!(table[0].name, "a");
        assert_eq!(table[1].name, "b");
    }

    #[test]
    fn below_all_ten_is_rejected() {
        let mut table = std::array::from_fn(|index| HighScoreEntry {
            score: 10 - index as i32,
            name: format!("{index}"),
        });
        assert_eq!(insert_high_score(&mut table, 0, "no"), None);
        assert_eq!(table[9].name, "9");
    }

    #[test]
    fn round_trip_preserves_nul_terminated_name() {
        let mut table = empty_high_score_table();
        insert_high_score(&mut table, 12, "France");
        let bytes = write_scores_dat(&table);
        assert_eq!(bytes.len(), HIGH_SCORE_COUNT * (4 + HIGH_SCORE_NAME_LENGTH));
        let loaded = read_scores_dat(&bytes);
        assert_eq!(loaded[0].score, 12);
        assert_eq!(loaded[0].name, "France");
    }
}
