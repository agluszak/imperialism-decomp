from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pyghidra

from imperialism_re.core.config import get_runtime_config
from imperialism_re.core.runtime import open_project_with_lock_cleanup as _open_project
from imperialism_re.core.runtime import start_pyghidra as _start_pyghidra


@contextmanager
def open_program(project_root: Path | None = None) -> Iterator[object]:
    cfg = get_runtime_config(project_root)
    _start_pyghidra(cfg)
    project = _open_project(cfg)
    with pyghidra.program_context(project, cfg.program_path) as program:
        yield program
