use crate::RetailLcg;
use serde::{Deserialize, Serialize};

pub const COARSE_MAP_WIDTH: usize = 27;
pub const COARSE_MAP_HEIGHT: usize = 15;
pub const COARSE_MAP_CELL_COUNT: usize = COARSE_MAP_WIDTH * COARSE_MAP_HEIGHT;
pub const RANDOM_MAP_CLASS_COUNT: usize = 23;
pub const EXPANDED_MAP_WIDTH: usize = 108;
pub const EXPANDED_MAP_HEIGHT: usize = 60;

const UNASSIGNED: i8 = -1;
const DISCONNECTED_OCEAN: i8 = 100;
const PLAINS: i8 = 0;
const WATER: i8 = 5;
const COLUMN_OFFSETS_EVEN: [i32; 6] = [1, 1, 1, 0, -1, 0];
const COLUMN_OFFSETS_ODD: [i32; 6] = [0, 1, 0, -1, -1, -1];
const ROW_OFFSETS: [i32; 6] = [-1, 0, 1, 1, 0, -1];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoarseMapGrid {
    cells: [[i8; COARSE_MAP_WIDTH]; COARSE_MAP_HEIGHT],
}

impl CoarseMapGrid {
    pub(crate) fn flattened(&self) -> impl Iterator<Item = i8> + '_ {
        self.cells.iter().flatten().copied()
    }

    #[cfg(any(test, feature = "differential-trace"))]
    pub fn fnv1a_hash(&self) -> u32 {
        self.cells
            .iter()
            .flatten()
            .copied()
            .fold(0x811c_9dc5, |hash, value| {
                (hash ^ u32::from(value as u8)).wrapping_mul(0x0100_0193)
            })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ExpandedMapSeedTile {
    pub(crate) terrain_kind: i8,
    pub(crate) owner_nation: i8,
    pub(crate) province_index: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ExpandedProvinceSeed {
    pub(crate) owner_nation: i8,
    pub(crate) region_class: i8,
}

/// The accepted coarse map and the region class assigned to each nation class.
///
/// Rejected attempts, generator group bookkeeping, and expanded tile seeds are
/// not game state. They are available only through `differential_trace` while
/// the native oracle still requires them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoarseMap {
    pub grid: CoarseMapGrid,
    pub region_classes: [i8; RANDOM_MAP_CLASS_COUNT],
}

impl CoarseMap {
    pub(crate) fn expanded_seed_data(
        &self,
    ) -> (Vec<ExpandedMapSeedTile>, Vec<ExpandedProvinceSeed>) {
        let mut tiles = vec![
            ExpandedMapSeedTile {
                terrain_kind: WATER,
                owner_nation: -1,
                province_index: -1,
            };
            EXPANDED_MAP_WIDTH * EXPANDED_MAP_HEIGHT
        ];
        let mut provinces = Vec::new();
        for coarse_index in 0..COARSE_MAP_CELL_COUNT {
            let class =
                self.grid.cells[coarse_index / COARSE_MAP_WIDTH][coarse_index % COARSE_MAP_WIDTH];
            let (terrain_kind, owner_nation, province_index) =
                if class == UNASSIGNED || class == DISCONNECTED_OCEAN {
                    (WATER, -1, -1)
                } else {
                    let province_index = provinces.len() as i16;
                    provinces.push(ExpandedProvinceSeed {
                        owner_nation: class,
                        region_class: self.region_classes[class as usize],
                    });
                    (PLAINS, class, province_index)
                };
            let coarse_row = coarse_index / COARSE_MAP_WIDTH;
            let coarse_column = coarse_index % COARSE_MAP_WIDTH;
            for block_row in 0..4 {
                let row = coarse_row * 4 + block_row;
                for block_column in 0..4 {
                    let column = if coarse_row & 1 == 0 {
                        coarse_column * 4 + block_column
                    } else {
                        (coarse_column * 4 + block_column + EXPANDED_MAP_WIDTH - 2)
                            % EXPANDED_MAP_WIDTH
                    };
                    tiles[row * EXPANDED_MAP_WIDTH + column] = ExpandedMapSeedTile {
                        terrain_kind,
                        owner_nation,
                        province_index,
                    };
                }
            }
        }
        (tiles, provinces)
    }
}

#[cfg(feature = "differential-trace")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoarseMapAttempt {
    pub draw_count: u32,
    pub map_lcg_after_seeding: u32,
    pub pre_validation_grid: CoarseMapGrid,
    pub city_region_next_id: i32,
    pub city_region_ids: [i32; RANDOM_MAP_CLASS_COUNT],
    pub group_members: [[i32; 3]; 7],
    pub post_validation_grid: CoarseMapGrid,
    pub error_check_failed: bool,
    pub has_continuous_ocean_column: Option<bool>,
    pub frontier_mask_complete: Option<bool>,
    pub accepted: bool,
    pub map_lcg_after_validation: u32,
}

/// Test-only record of the rejected coarse-generation attempts emitted by the
/// native differential harness. Normal generation returns [`CoarseMap`].
#[cfg(feature = "differential-trace")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CoarseMapTrace {
    pub initial_map_lcg: u32,
    pub attempts: Vec<CoarseMapAttempt>,
    pub accepted_map_lcg: u32,
    pub accepted_grid: CoarseMapGrid,
    pub city_region_next_id: i32,
    pub city_region_ids: [i32; RANDOM_MAP_CLASS_COUNT],
    pub group_members: [[i32; 3]; 7],
    expanded_tiles: Vec<ExpandedMapSeedTile>,
    expanded_provinces: Vec<ExpandedProvinceSeed>,
}

#[cfg(feature = "differential-trace")]
impl CoarseMapTrace {
    fn from_generation_result(
        initial_map_lcg: u32,
        accepted_map_lcg: u32,
        attempts: Vec<CoarseMapAttempt>,
        result: &CoarseMapBuild,
    ) -> Self {
        let (expanded_tiles, expanded_provinces) = result.map.expanded_seed_data();
        Self {
            initial_map_lcg,
            attempts,
            accepted_map_lcg,
            accepted_grid: result.map.grid.clone(),
            city_region_next_id: result.city_region_next_id,
            city_region_ids: result.map.region_classes.map(i32::from),
            group_members: result.group_members,
            expanded_tiles,
            expanded_provinces,
        }
    }

    pub fn final_map(&self) -> CoarseMap {
        CoarseMap {
            grid: self.accepted_grid.clone(),
            region_classes: self.city_region_ids.map(|id| id as i8),
        }
    }

    pub fn expanded_tile_count(&self) -> usize {
        self.expanded_tiles.len()
    }

    pub fn expanded_province_count(&self) -> usize {
        self.expanded_provinces.len()
    }
}

struct CoarseMapBuild {
    map: CoarseMap,
    #[cfg(feature = "differential-trace")]
    city_region_next_id: i32,
    #[cfg(feature = "differential-trace")]
    group_members: [[i32; 3]; 7],
}

#[derive(Clone)]
struct GeneratorScratch {
    grid: CoarseMapGrid,
    group_members: [[i32; 3]; 7],
    city_region_next_id: i32,
    city_region_ids: [i32; RANDOM_MAP_CLASS_COUNT],
    last_minor_seed_candidate: i32,
    draw_count: u32,
}

impl GeneratorScratch {
    fn reset(&mut self) {
        self.grid.cells = [[UNASSIGNED; COARSE_MAP_WIDTH]; COARSE_MAP_HEIGHT];
        self.group_members = [[-1; 3]; 7];
        self.city_region_next_id = -1;
        self.city_region_ids = [-1; RANDOM_MAP_CLASS_COUNT];
        self.last_minor_seed_candidate = -1;
        self.draw_count = 0;
    }

    fn draw(&mut self, rng: &mut RetailLcg) -> u32 {
        self.draw_count += 1;
        rng.next_sample_15()
    }

    fn run_attempt(&mut self, rng: &mut RetailLcg) {
        self.reset();
        for class_index in 0..7 {
            loop {
                self.cleanup_class(class_index);
                let cell_index = loop {
                    let candidate = (self.draw(rng) % COARSE_MAP_CELL_COUNT as u32) as i32;
                    if self.cell(candidate) == UNASSIGNED {
                        break candidate;
                    }
                };
                if self.assign(cell_index, 8, class_index, 5, rng) == 8 {
                    break;
                }
            }
        }

        for class_index in 7..RANDOM_MAP_CLASS_COUNT {
            let parity = (class_index - 7) >> 2;
            loop {
                self.cleanup_class(class_index);
                let mut cell_index = 0;
                let mut has_assigned_neighbor = false;
                for _ in 0..4 {
                    if has_assigned_neighbor {
                        break;
                    }
                    let roll1 = (self.draw(rng) % COARSE_MAP_WIDTH as u32) as i32;
                    let roll2 = (self.draw(rng) % COARSE_MAP_HEIGHT as u32) as i32;
                    cell_index = roll1 / 2
                        + if parity & 1 != 0 { 13 } else { 0 }
                        + (roll2 / 2 + if parity < 2 { 0 } else { 7 }) * COARSE_MAP_WIDTH as i32;
                    for direction in 0..6 {
                        let neighbor = adjacent_cell(cell_index, direction);
                        if neighbor != -1 && self.cell(neighbor) != UNASSIGNED {
                            has_assigned_neighbor = true;
                        }
                    }
                }
                if self.assign(cell_index, 4, class_index, 5, rng) == 4 {
                    break;
                }
            }
        }
    }

    fn cleanup_class(&mut self, class_index: usize) {
        self.city_region_ids[class_index] = -1;
        for cell in self.grid.cells.iter_mut().flatten() {
            if *cell == class_index as i8 {
                *cell = UNASSIGNED;
            }
        }
        for member in self.group_members.iter_mut().flatten() {
            if *member == class_index as i32 {
                *member = -1;
            }
        }
    }

    fn assign(
        &mut self,
        cell_index: i32,
        mode: i32,
        class_index: usize,
        retry_budget: i32,
        rng: &mut RetailLcg,
    ) -> i32 {
        let row = cell_index / COARSE_MAP_WIDTH as i32;
        if mode == 0 || row <= 0 || row >= 14 || self.cell(cell_index) != UNASSIGNED {
            return 0;
        }
        let merged = if class_index < 7 {
            self.merge_major_neighbors(cell_index, class_index)
        } else {
            self.merge_neighbors(cell_index, class_index)
        };
        if !merged {
            return 0;
        }

        self.set_cell(cell_index, class_index as i8);
        let mut remaining = mode - 1;
        let mut excluded = [false; 6];
        let mut available_count = 6;
        for (direction, is_excluded) in excluded.iter_mut().enumerate() {
            if adjacent_cell(cell_index, direction) == -1 || direction as i32 == retry_budget {
                *is_excluded = true;
                available_count -= 1;
            }
        }

        let mut last_cell = cell_index;
        while remaining != 0 && available_count != 0 {
            let mut weights = [0; 6];
            let mut total_weight = 0;
            for direction in 0..6 {
                if !excluded[direction] {
                    let neighbor = adjacent_cell(last_cell, direction);
                    let mut weight = if direction as i32 != retry_budget {
                        10
                    } else {
                        2
                    };
                    for neighbor_direction in 0..6 {
                        let neighbor_of_neighbor = adjacent_cell(neighbor, neighbor_direction);
                        if neighbor_of_neighbor != -1
                            && self.cell(neighbor_of_neighbor) == class_index as i8
                        {
                            weight += 10;
                        }
                    }
                    weights[direction] = weight;
                }
                total_weight += weights[direction];
            }

            let roll = (self.draw(rng) % total_weight as u32) as i32;
            let mut selected_direction = 0;
            if weights[0] < roll {
                let mut cumulative = weights[0];
                loop {
                    let next_weight = weights[selected_direction + 1];
                    weights[selected_direction + 1] = next_weight + cumulative;
                    cumulative += next_weight;
                    selected_direction += 1;
                    if cumulative >= roll {
                        break;
                    }
                }
            }

            let neighbor = adjacent_cell(last_cell, selected_direction);
            let assigned = self.assign(
                neighbor,
                remaining,
                class_index,
                selected_direction as i32,
                rng,
            );
            remaining -= assigned;
            excluded[selected_direction] = true;
            available_count -= 1;
            last_cell = neighbor;
        }
        mode - remaining
    }

    fn merge_major_neighbors(&mut self, cell_index: i32, class_index: usize) -> bool {
        for direction in 0..6 {
            let neighbor = adjacent_cell(cell_index, direction);
            let neighbor_class = if neighbor == -1 {
                UNASSIGNED
            } else {
                self.cell(neighbor)
            };
            if neighbor_class == UNASSIGNED || neighbor_class == class_index as i8 {
                continue;
            }
            let neighbor_class = neighbor_class as usize;
            let my_group = self.city_region_ids[class_index];
            let neighbor_group = self.city_region_ids[neighbor_class];
            if my_group == -1 {
                if neighbor_group == -1 {
                    self.city_region_next_id += 1;
                    let new_group = self.city_region_next_id as usize;
                    self.group_members[new_group][0] = class_index as i32;
                    self.group_members[new_group][1] = neighbor_class as i32;
                    self.city_region_ids[class_index] = self.city_region_next_id;
                    self.city_region_ids[neighbor_class] = self.city_region_next_id;
                } else {
                    let group = neighbor_group as usize;
                    let Some(slot) = self.group_members[group]
                        .iter()
                        .position(|member| *member == -1)
                    else {
                        return false;
                    };
                    self.group_members[group][slot] = class_index as i32;
                    self.city_region_ids[class_index] = neighbor_group;
                }
            } else if neighbor_group == -1 {
                let group = my_group as usize;
                let Some(slot) = self.group_members[group]
                    .iter()
                    .position(|member| *member == -1)
                else {
                    return false;
                };
                self.group_members[group][slot] = neighbor_class as i32;
                self.city_region_ids[neighbor_class] = my_group;
            } else if my_group != neighbor_group {
                return false;
            }
        }
        true
    }

    fn merge_neighbors(&mut self, cell_index: i32, class_index: usize) -> bool {
        for direction in 0..6 {
            let neighbor = adjacent_cell(cell_index, direction);
            let neighbor_class = if neighbor == -1 {
                UNASSIGNED
            } else {
                self.cell(neighbor)
            };
            if neighbor_class == UNASSIGNED || neighbor_class == class_index as i8 {
                continue;
            }
            let neighbor_class = neighbor_class as usize;
            let my_group = self.city_region_ids[class_index];
            let neighbor_group = self.city_region_ids[neighbor_class];
            if my_group == -1 {
                if neighbor_group == -1 {
                    self.city_region_next_id += 1;
                    self.city_region_ids[class_index] = self.city_region_next_id;
                    self.city_region_ids[neighbor_class] = self.city_region_next_id;
                } else {
                    self.city_region_ids[class_index] = neighbor_group;
                }
            } else if my_group != neighbor_group {
                return false;
            }
        }
        true
    }

    fn error_check(&mut self) -> bool {
        self.erase_ocean(0);
        let mut failed = false;
        for cell in self.grid.cells.iter_mut().flatten() {
            if *cell == UNASSIGNED {
                *cell = DISCONNECTED_OCEAN;
                failed = true;
            } else if *cell == -9 {
                *cell = UNASSIGNED;
            }
        }
        failed
    }

    fn erase_ocean(&mut self, cell_index: i32) {
        self.set_cell(cell_index, -9);
        for direction in 0..6 {
            let neighbor = adjacent_cell(cell_index, direction);
            if neighbor != -1 && self.cell(neighbor) == UNASSIGNED {
                self.erase_ocean(neighbor);
            }
        }
    }

    fn has_continuous_ocean_column(&self) -> bool {
        (0..COARSE_MAP_WIDTH).any(|column| {
            (0..COARSE_MAP_HEIGHT).all(|row| self.grid.cells[row][column] == UNASSIGNED)
        })
    }

    fn frontier_mask_complete(&self) -> bool {
        let mut mask = 0_u32;
        for cell_index in COARSE_MAP_WIDTH as i32..(14 * COARSE_MAP_WIDTH) as i32 {
            let class = self.cell(cell_index);
            if class != UNASSIGNED {
                for direction in 0..6 {
                    if self.cell(adjacent_cell(cell_index, direction)) == UNASSIGNED {
                        mask |= 1 << class;
                        break;
                    }
                }
            }
        }
        mask == 0x7f_ffff
    }

    fn backfill_city_region_ids(&mut self) {
        for class_index in 0..RANDOM_MAP_CLASS_COUNT {
            if self.city_region_ids[class_index] == -1 {
                self.city_region_next_id += 1;
                self.city_region_ids[class_index] = self.city_region_next_id;
            }
        }
    }

    fn cell(&self, cell_index: i32) -> i8 {
        let row = cell_index / COARSE_MAP_WIDTH as i32;
        let column = cell_index % COARSE_MAP_WIDTH as i32;
        self.grid.cells[row as usize][column as usize]
    }

    fn set_cell(&mut self, cell_index: i32, value: i8) {
        let row = cell_index / COARSE_MAP_WIDTH as i32;
        let column = cell_index % COARSE_MAP_WIDTH as i32;
        self.grid.cells[row as usize][column as usize] = value;
    }
}

/// Runs the recovered 27x15 seeding/rejection pass and its immediate 4x expansion.
///
/// Retail's coarse neighbor routine always wraps its 27 columns and does not read
/// the map topology byte. The bounded/wrapping topology choice first affects later
/// full-resolution passes, so it is intentionally not an input to this function.
pub fn generate_coarse_random_map(rng: &mut RetailLcg) -> CoarseMap {
    generate_coarse_random_map_impl(
        rng,
        #[cfg(feature = "differential-trace")]
        None,
    )
    .map
}

#[cfg(feature = "differential-trace")]
pub fn trace_coarse_random_map(rng: &mut RetailLcg) -> CoarseMapTrace {
    let initial_map_lcg = rng.state();
    let mut attempts = Vec::new();
    let result = generate_coarse_random_map_impl(rng, Some(&mut attempts));
    CoarseMapTrace::from_generation_result(initial_map_lcg, rng.state(), attempts, &result)
}

fn generate_coarse_random_map_impl(
    rng: &mut RetailLcg,
    #[cfg(feature = "differential-trace")] mut attempts: Option<&mut Vec<CoarseMapAttempt>>,
) -> CoarseMapBuild {
    let mut scratch = GeneratorScratch {
        grid: CoarseMapGrid {
            cells: [[UNASSIGNED; COARSE_MAP_WIDTH]; COARSE_MAP_HEIGHT],
        },
        group_members: [[-1; 3]; 7],
        city_region_next_id: -1,
        city_region_ids: [-1; RANDOM_MAP_CLASS_COUNT],
        last_minor_seed_candidate: -1,
        draw_count: 0,
    };
    loop {
        scratch.run_attempt(rng);
        #[cfg(feature = "differential-trace")]
        let trace_before_validation = attempts.as_ref().map(|_| {
            (
                scratch.draw_count,
                rng.state(),
                scratch.grid.clone(),
                scratch.city_region_next_id,
                scratch.city_region_ids,
                scratch.group_members,
            )
        });
        let error_check_failed = scratch.error_check();
        let has_continuous_ocean_column =
            (!error_check_failed).then(|| scratch.has_continuous_ocean_column());
        let frontier_mask_complete = has_continuous_ocean_column
            .filter(|value| *value)
            .map(|_| scratch.frontier_mask_complete());
        let accepted = !error_check_failed
            && has_continuous_ocean_column == Some(true)
            && frontier_mask_complete == Some(true);
        #[cfg(feature = "differential-trace")]
        if let (Some(attempts), Some(trace_before_validation)) =
            (&mut attempts, trace_before_validation)
        {
            let (
                draw_count,
                map_lcg_after_seeding,
                pre_validation_grid,
                city_region_next_id,
                city_region_ids,
                group_members,
            ) = trace_before_validation;
            attempts.push(CoarseMapAttempt {
                draw_count,
                map_lcg_after_seeding,
                pre_validation_grid,
                city_region_next_id,
                city_region_ids,
                group_members,
                post_validation_grid: scratch.grid.clone(),
                error_check_failed,
                has_continuous_ocean_column,
                frontier_mask_complete,
                accepted,
                map_lcg_after_validation: rng.state(),
            });
        }
        if accepted {
            break;
        }
    }

    scratch.backfill_city_region_ids();
    CoarseMapBuild {
        map: CoarseMap {
            grid: scratch.grid,
            region_classes: scratch.city_region_ids.map(|id| id as i8),
        },
        #[cfg(feature = "differential-trace")]
        city_region_next_id: scratch.city_region_next_id,
        #[cfg(feature = "differential-trace")]
        group_members: scratch.group_members,
    }
}

fn adjacent_cell(cell: i32, direction: usize) -> i32 {
    let mut column = cell % COARSE_MAP_WIDTH as i32;
    let mut row = cell / COARSE_MAP_WIDTH as i32;
    column += if row & 1 == 0 {
        COLUMN_OFFSETS_EVEN[direction]
    } else {
        COLUMN_OFFSETS_ODD[direction]
    };
    row += ROW_OFFSETS[direction];
    if column < 0 {
        column += COARSE_MAP_WIDTH as i32;
    } else if column >= COARSE_MAP_WIDTH as i32 {
        column -= COARSE_MAP_WIDTH as i32;
    }
    let neighbor = column + row * COARSE_MAP_WIDTH as i32;
    if !(0..COARSE_MAP_CELL_COUNT as i32).contains(&neighbor) {
        -1
    } else {
        neighbor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic_and_preserves_retail_class_sizes() {
        let mut first_rng = RetailLcg::from_state(0x1234_5678);
        let first = generate_coarse_random_map(&mut first_rng);
        let mut second_rng = RetailLcg::from_state(0x1234_5678);
        let second = generate_coarse_random_map(&mut second_rng);
        assert_eq!(first, second);
        assert_eq!(first_rng, second_rng);

        let mut counts = [0; RANDOM_MAP_CLASS_COUNT];
        for class in first.grid.flattened().filter(|class| *class >= 0) {
            counts[class as usize] += 1;
        }
        assert_eq!(&counts[..7], &[8; 7]);
        assert_eq!(&counts[7..], &[4; 16]);
        let (expanded_tiles, expanded_provinces) = first.expanded_seed_data();
        assert_eq!(expanded_provinces.len(), 120);
        assert_eq!(expanded_tiles.len(), 108 * 60);
    }

    #[test]
    fn seed_one_returns_the_retail_final_map_and_rng_state() {
        let mut rng = RetailLcg::from_state(0x15a6_cd28);
        let map = generate_coarse_random_map(&mut rng);

        assert_eq!(rng.state(), 259_883_818);
        assert_eq!(map.grid.fnv1a_hash(), 0x5c1e_ab12);
        assert_eq!(
            map.region_classes,
            [
                4, 0, 0, 0, 5, 3, 1, 1, 1, 1, 1, 0, 2, 1, 1, 4, 4, 0, 4, 0, 0, 0, 5
            ]
        );
    }

    #[cfg(feature = "differential-trace")]
    #[test]
    fn trace_matches_retail_oracle_seed_one_attempt_stream() {
        let mut rng = RetailLcg::from_state(0x15a6_cd28);
        let trace = trace_coarse_random_map(&mut rng);
        let attempts = trace
            .attempts
            .iter()
            .map(|attempt| {
                (
                    attempt.pre_validation_grid.fnv1a_hash(),
                    attempt.draw_count,
                    attempt.map_lcg_after_seeding,
                    attempt.error_check_failed,
                    attempt.has_continuous_ocean_column,
                    attempt.frontier_mask_complete,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            attempts,
            vec![
                (0xf7c1_cf72, 403, 3_390_400_103, true, None, None),
                (0x5c1e_ab12, 451, 259_883_818, false, Some(true), Some(true)),
            ]
        );
        assert_eq!(trace.accepted_map_lcg, 259_883_818);
        assert_eq!(trace.accepted_grid.fnv1a_hash(), 0x5c1e_ab12);
        assert_eq!(trace.city_region_next_id, 5);
        assert_eq!(trace.expanded_province_count(), 120);
    }

    #[cfg(feature = "differential-trace")]
    #[test]
    fn trace_matches_retail_oracle_seed_two_rejection_stream() {
        let mut rng = RetailLcg::from_state(0x51b2_c045);
        let trace = trace_coarse_random_map(&mut rng);
        let attempts = trace
            .attempts
            .iter()
            .map(|attempt| {
                (
                    attempt.pre_validation_grid.fnv1a_hash(),
                    attempt.draw_count,
                    attempt.map_lcg_after_seeding,
                    attempt.error_check_failed,
                    attempt.has_continuous_ocean_column,
                    attempt.frontier_mask_complete,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            attempts,
            vec![
                (0x699b_52ca, 464, 3_888_987_573, true, None, None),
                (0x1f0c_d646, 438, 748_813_343, true, None, None),
                (0x0471_457c, 446, 3_585_573_809, false, Some(false), None),
                (
                    0xd2a6_ff22,
                    460,
                    3_712_210_293,
                    false,
                    Some(true),
                    Some(true)
                ),
            ]
        );
        assert_eq!(trace.accepted_map_lcg, 3_712_210_293);
        assert_eq!(trace.accepted_grid.fnv1a_hash(), 0xd2a6_ff22);
        assert_eq!(trace.city_region_next_id, 5);
        assert_eq!(trace.expanded_province_count(), 120);
    }

    #[test]
    fn coarse_adjacency_always_wraps_without_a_topology_input() {
        // TMapMaker::GetAdjacentRegionGridCell (retail 0x00528ce0) wraps the
        // 27-column coarse grid unconditionally in both row parities.
        assert_eq!(adjacent_cell(27, 4), 53);
        assert_eq!(adjacent_cell(80, 1), 54);
    }
}
