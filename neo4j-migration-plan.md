# Neo4j Migration Plan for Imperialism Knowledge Base

Date: 2026-02-15

## 1. Goal
Migrate the current Markdown research notes into a queryable graph that captures:
- game domain facts (buildings, technologies, units, resources, scenarios)
- reverse-engineering evidence (functions, addresses, offsets, formulas, files)
- provenance and confidence (where each claim came from and how certain it is)

This keeps facts, hypotheses, and proof paths connected instead of buried in prose.

## 2. Scope of Source Material
Initial ingestion sources in this repository:
- `imperialism-decomp.md`
- `technology-unlocks.md`
- `tech-experiment-university-unlocks.md`
- `tabsenu-gob-findings.md`
- `bitmap-ids.md`
- `manual_text.txt`
- planning notes (`city-university-research-plan.md`, `map-orders-research-plan.md`)

Out of scope in phase 1:
- full OCR/NLP over the entire manual
- automatic decompilation parsing from Ghidra exports

## 3. Graph Modeling Principles
1. Separate facts from evidence.
- A fact node/relationship can exist only if linked to at least one evidence node.

2. Every technical assertion should be traceable.
- Example: "Forester requires tech X" must link to source lines, function address, or scenario record.

3. Keep confidence explicit.
- Distinguish `confirmed`, `strong_hypothesis`, `speculative`.

4. Stable IDs over display names.
- Use deterministic IDs (`func_00474ac5`, `bitmap_9926`, `tech_feed_grasses`).

## 4. Proposed Neo4j Schema

### Core domain nodes
- `:Technology {id, name, era_year_start, era_year_end, cost}`
- `:Unit {id, name, category}`
- `:Building {id, name, slot_id}`
- `:Resource {id, name, class}`  // class: resource/material/good
- `:Scenario {id, name, source_file}`
- `:Nation {id, name, index}`

### Reverse-engineering nodes
- `:Function {id, name, address, module}`
- `:Offset {id, base_struct, hex_offset, width_bytes, meaning}`
- `:Formula {id, expression, context}`
- `:Bitmap {id, bitmap_id, usage}`
- `:StringEntry {id, string_id, text}`
- `:ControlTag {id, tag}`

### Provenance + quality nodes
- `:SourceDocument {id, path, type}`
- `:Evidence {id, excerpt, source_path, line_start, line_end, captured_at}`
- `:Claim {id, statement, status, confidence, last_reviewed_at}`
- `:ResearchTask {id, title, status, owner, created_at}`

### Key relationships
- `(:Unit)-[:UNLOCKED_BY]->(:Technology)`
- `(:Technology)-[:ENABLES]->(:Building|:Unit|:Resource)`
- `(:Building)-[:PRODUCES]->(:Resource)`
- `(:Nation)-[:STARTS_WITH_TECH_IN]->(:Technology)` with scenario context
- `(:Scenario)-[:INCLUDES_NATION]->(:Nation)`

- `(:Function)-[:READS_OFFSET|WRITES_OFFSET]->(:Offset)`
- `(:Function)-[:USES_BITMAP]->(:Bitmap)`
- `(:Function)-[:USES_STRING]->(:StringEntry)`
- `(:Function)-[:IMPLEMENTS]->(:Claim)`
- `(:Formula)-[:OBSERVED_IN]->(:Function)`
- `(:ControlTag)-[:HANDLED_BY]->(:Function)`

- `(:Claim)-[:SUPPORTED_BY]->(:Evidence)`
- `(:Evidence)-[:FROM_SOURCE]->(:SourceDocument)`
- `(:ResearchTask)-[:TRACKS]->(:Claim)`

## 5. Constraints and Indexes
Use these early:
- unique constraints on `id` for all major labels
- index `Function.address`
- index `Technology.name`, `Unit.name`, `Building.slot_id`
- index `Evidence.source_path`
- index `Claim.status`

## 6. Migration Phases

### Phase 0: Bootstrap graph
Create constraints, indexes, and seed static entities:
- 16 city building slots
- known building list from `imperialism-decomp.md`
- baseline tech/unit/resource vocabulary from `technology-unlocks.md` and manual snippets

### Phase 1: Structured facts from high-signal notes
Parse manually structured docs first:
- `imperialism-decomp.md` (functions, addresses, formulas, offsets)
- `tech-experiment-university-unlocks.md` (scenario tech records)
- `technology-unlocks.md` (tech -> civilian unlocks)

Output:
- nodes + relationships + `Claim` + `Evidence` for each imported assertion

### Phase 2: Provenance hardening
For each existing claim, enforce at least one evidence edge.
- mark missing-evidence claims as `status='needs_evidence'`
- attach line-ranged evidence excerpts from source files

### Phase 3: Query layer for RE workflows
Add reusable Cypher query pack:
- "what unlocks this unit?"
- "which functions write city production offsets?"
- "which facts are still hypotheses?"
- "which scenario gives tech X to nation Y?"

### Phase 4: Incremental ingestion pipeline
Each time you update markdown or discover a function in Ghidra:
- append/modify facts in a staging JSONL
- run idempotent upsert job
- update claim statuses and evidence links

## 7. Ingestion Architecture
Use two-step ingestion to stay safe and repeatable.

1. Extract -> JSONL
- Build a small parser script (Python) that reads selected `.md/.txt` files.
- Emit records with explicit type (`Technology`, `Function`, `Claim`, `Evidence`, `RELATION`).

2. Load -> Neo4j
- Use deterministic `MERGE` statements.
- Upsert nodes first, then relationships, then evidence links.
- All loads should be idempotent.

Recommended file layout:
- `etl/parsers/*.py`
- `etl/out/*.jsonl`
- `etl/cypher/*.cql`
- `etl/run_ingest.sh`

## 8. Claim and Confidence Model
Use claim nodes even when relationship seems simple.

Example modeling:
- Claim: "Forester unlock is gated by Feed Grasses"
- status: `strong_hypothesis`
- confidence: `0.75`
- evidence A: wiki/string table text
- evidence B: function branch in university UI

When Ghidra confirms exact tech flag check, upgrade claim:
- status -> `confirmed`
- confidence -> `0.95+`

## 9. Minimal Cypher Starter Set

```cypher
// Example unique constraint
CREATE CONSTRAINT technology_id IF NOT EXISTS
FOR (n:Technology) REQUIRE n.id IS UNIQUE;
```

```cypher
// Example fact + claim + evidence linkage
MERGE (u:Unit {id:'unit_forester'})
  ON CREATE SET u.name='Forester', u.category='civilian'
MERGE (t:Technology {id:'tech_feed_grasses'})
  ON CREATE SET t.name='Feed Grasses'
MERGE (c:Claim {id:'claim_forester_unlock_feed_grasses'})
  ON CREATE SET c.statement='Forester is unlocked by Feed Grasses', c.status='strong_hypothesis', c.confidence=0.75
MERGE (e:Evidence {id:'ev_tech_unlocks_md_1'})
  ON CREATE SET e.source_path='technology-unlocks.md', e.line_start=1, e.line_end=40
MERGE (u)-[:UNLOCKED_BY]->(t)
MERGE (c)-[:ASSERTS]->(u)
MERGE (c)-[:ASSERTS]->(t)
MERGE (c)-[:SUPPORTED_BY]->(e);
```

## 10. Quality Gates
Before each ingest run:
- no duplicate IDs in JSONL
- all relationships reference existing node IDs
- every `Claim` has `status` and `confidence`

After ingest run:
- orphan claims count is zero (`Claim` without `SUPPORTED_BY`)
- high-priority entities (University, civilian unlocks, city production offsets) have coverage

## 11. First Sprint (practical)
1. Create constraints/indexes + seed domain vocabulary.
2. Ingest only 3 files:
   - `imperialism-decomp.md`
   - `technology-unlocks.md`
   - `tech-experiment-university-unlocks.md`
3. Validate with 5 target queries used in daily RE.
4. Expand to manual and remaining notes.

## 12. Suggested Next Deliverables
- `neo4j-schema.cql` (constraints + indexes + starter ontology)
- `etl/parsers/parse_imperialism_notes.py`
- `etl/cypher/load_from_jsonl.cql`
- `queries/re_workbench.cql`

