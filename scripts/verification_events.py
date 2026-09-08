"""Pytest evidence plugin. Emits exact node IDs and every test phase, durably."""
from __future__ import annotations
import json
import os
from pathlib import Path

_PATH: Path | None = None


def pytest_addoption(parser):
    parser.addoption('--controller-evidence', default=None)


def emit(event: str, **values) -> None:
    if _PATH is not None:
        with _PATH.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'event': event, **values}, ensure_ascii=True) + '\n')
            stream.flush()
            os.fsync(stream.fileno())


def pytest_configure(config):
    global _PATH
    value = config.getoption('--controller-evidence')
    _PATH = Path(value) if value else None
    if _PATH is not None:
        # A new file is mandatory: old evidence must never be merged into a run.
        with _PATH.open('x', encoding='utf-8'):
            pass
        emit('session_start')


def pytest_collection_finish(session):
    emit('inventory', nodeids=[item.nodeid for item in session.items])


def pytest_collectreport(report):
    if report.failed:
        emit('collection_error', nodeid=report.nodeid, detail=str(report.longrepr)[:4000])


def pytest_runtest_logreport(report):
    emit('phase', nodeid=report.nodeid, when=report.when, outcome=report.outcome,
         seconds=report.duration,
         reason=str(report.longrepr)[:4000] if report.failed or report.skipped else None,
         wasxfail=getattr(report, 'wasxfail', None))


def pytest_sessionfinish(session, exitstatus):
    emit('session_finish', exit_code=int(exitstatus))
