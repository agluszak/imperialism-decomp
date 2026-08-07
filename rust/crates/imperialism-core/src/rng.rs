use crate::RngState;

const VC5_CRT_RAND_MULTIPLIER: u32 = 214_013;
const VC5_CRT_RAND_ADDEND: u32 = 2_531_011;

impl RngState {
    /// Mirrors VC5 libcmt's `srand`: the supplied value becomes the complete
    /// thread-local CRT random state without an eager transition.
    pub fn seed_crt(&mut self, seed: u32) {
        self.crt_rand = seed;
    }

    /// Mirrors the `rand.obj` shipped with VC5 libcmt. The object updates a
    /// 32-bit LCG state and returns bits 16..30 of the new state.
    pub fn next_crt_rand(&mut self) -> i32 {
        self.crt_rand = self
            .crt_rand
            .wrapping_mul(VC5_CRT_RAND_MULTIPLIER)
            .wrapping_add(VC5_CRT_RAND_ADDEND);
        ((self.crt_rand >> 16) & 0x7fff) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(crt_rand: u32) -> RngState {
        RngState {
            crt_rand,
            map_generation: 0x1122_3344,
            zone_status: 0x5566_7788,
        }
    }

    #[test]
    fn reproduces_the_vc5_seed_one_sequence() {
        let mut rng = state(0);
        rng.seed_crt(1);
        let actual: Vec<i32> = (0..8).map(|_| rng.next_crt_rand()).collect();
        assert_eq!(
            actual,
            vec![41, 18_467, 6_334, 26_500, 19_169, 15_724, 11_478, 29_358]
        );
        assert_eq!(rng.crt_rand, 1_924_036_713);
        assert_eq!(rng.map_generation, 0x1122_3344);
        assert_eq!(rng.zone_status, 0x5566_7788);
    }

    #[test]
    fn wraps_the_full_unsigned_state_before_extracting_the_result() {
        let mut rng = state(u32::MAX);
        assert_eq!(rng.next_crt_rand(), 35);
        assert_eq!(rng.crt_rand, 2_316_998);
    }
}
