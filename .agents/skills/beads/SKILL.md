---
name: beads
description: Use Beads for durable Imperialism task state, blockers, dependencies, and handoff.
---

# Beads

Run from the repository workspace.

```sh
bd prime
bd ready
bd show <id>
bd update <id> --claim
```

Create a task when discovered work must survive the current session:

```sh
bd create --title="Summary" --description="Why it exists and what remains" --type=task --priority=2
```

Update or close every issue actually handled before handoff:

```sh
bd update <id> --notes="Current evidence or blocker"
bd close <id> --reason="Completed"
```

Beads owns unfinished work and resumable status. Focused docs own recovered evidence; Git owns history.
Do not create markdown task lists or use interactive `bd edit` as a substitute.
