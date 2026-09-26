# Army tactical projection attributes

`TArmyTacUnit` stores a five-element float array at `+0x44..+0x54`.
`0x005a5fe0` writes the components in increasing order, and the army-player
accumulator (`0x0059b5b0`) and deployment pruner (`0x0059b990`) traverse all five
components with four-byte strides. These are attributes 0 through 4 from
`TMilitaryUnit::GetAttribute`, weighted by current tactical strength and source
experience. They are not five independent fields or five tactical unit classes.
The array ends at the existing `TArmyTacUnit` size of `0x58` and is derived state,
absent from the tactical battle save stream.

The Mac symbol oracle names the corresponding class method
`TArmyTacUnit::CalculateAttributes()`
(`vendor/macos_codewarrior/evidence/symbols.csv`). The Windows source retains its
existing function name, `ComputeTacticalProjectionScoreVector`.

## Arithmetic and call order

The Windows instructions establish these dependencies:

1. Read source experience, divide by 100 with signed truncation, and narrow the
   quotient to a signed word. Store the resulting quality factor as a float.
2. Call `GetAttribute(5)` and discard its result. This call remains in the source:
   the getter at `0x005c3530` performs table reads and signed integer division.
3. Multiply current tactical strength by the float constant `0.002f`. Preserve
   that float for component 0, and multiply strength by quality for the shared
   scale, which is stored as a float before the following attribute calls.
4. Read attributes 0 through 4 in order. Every output receives attribute times
   scale; component 0 also receives a second strength factor.

Retail additionally stores `1.0f` and multiplies components 0, 1, and 4 by it.
These neutral multiplications need no source-level factor. The related strategic
routine at `0x0053cc10` uses attribute 5 to calculate a terrain factor, but the
tactical routine has no such adjustment. It would be a behavior change to copy
the strategic formula into tactical projection.

The quality, strength, and scale float intermediates remain explicit. The
arithmetic expression order remains intact, including the strength-squared first
component. The distribution-similarity helper (`0x005362c0`) accumulates in x87
precision without intermediate float stores; its arithmetic is unchanged.

## Player metrics and deployment

`TArmyPlayer::projectionMetrics2C` occupies five floats at `+0x2c..+0x3c`.
Accumulation first stores component sums for active units (`state1c == 0`). It
then evaluates both reference profiles before replacing components 0 and 1 with
their fitness scores. Components 2 through 4 remain untransformed sums; the AI
compares component 3 for artillery strength. A separate byte at `+0x51` records
whether an active artillery or sapper unit exists. Neither field requires an
overlay union or another object.

The two profile selectors differ in retail and remain distinct:

| Caller | No fort | Fort present |
| --- | --- | --- |
| Army-player terrain metric, `0x0059b5b0` | row 2 | row 1 |
| Attacker deployment pruning, `0x0059b990` | row 1 | row 2 |

Row 0 supplies the baseline metric and the defender's deployment profile. Rows
are five consecutive signed words beginning at `0x00697870`.

The deployment pruner tentatively adds each candidate's components to the kept
sum, scores that sum, and subtracts the same candidate afterward. This in-place
add/subtract sequence retains its float rounding; making an independent trial
copy would change later candidate inputs. Retail also reserves the first
category-9 unit without adding it to the kept sum, and scans candidate ordinals
strictly below `GetCount()`. Those edge behaviors remain intact.
