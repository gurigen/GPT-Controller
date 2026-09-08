"""Isolated verification with fresh evidence, exact coverage, and failure accounting.

This does not contact user repositories or install/deploy anything. Each test file
gets its own process, log, JUnit XML and durable exact-node-ID journal. Even when a
file fails or times out, the remaining files are attempted. Inspect all skips.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

SCRIPTS = Path(__file__).resolve().parent


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: dict) -> None:
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temp.open('x', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=True, indent=2)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def fingerprint(root: Path) -> dict[str, str]:
    paths = []
    for name in ('src', 'tests', 'scripts', 'schemas', '.github'):
        if (root / name).exists():
            paths.extend((root / name).rglob('*'))
    paths.extend(root / name for name in ('pyproject.toml', 'SOURCE_MANIFEST.json'))
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths)) if p.is_file() and
            p.suffix in {'.py', '.json', '.toml', '.ps1', '.yml', '.yaml'} and
            '__pycache__' not in p.parts}


def terminate(process: subprocess.Popen) -> None:
    if os.name == 'posix':
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        import psutil
        try:
            children = psutil.Process(process.pid).children(recursive=True)
        except psutil.NoSuchProcess:
            children = []
        for child in reversed(children):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        process.kill()
    process.wait(timeout=10)


def invoke(root: Path, folder: Path, stem: str, targets: list[str],
           env: dict[str, str], timeout: float, *, collect: bool = False) -> dict:
    events = folder / (stem + '.jsonl')
    xml = folder / (stem + '.xml')
    # Keep local Git object paths below Windows MAX_PATH, independently of
    # the evidence directory depth. Preserve every run's temporary evidence.
    temporary = Path(tempfile.mkdtemp(prefix='gpt-v-')) / 't'
    args = [sys.executable, '-m', 'pytest', '-q', '--rootdir=' + str(root),
            '-p', 'no:cacheprovider', '-p', 'verification_events',
            '--controller-evidence=' + str(events),
            '--basetemp=' + str(temporary), *targets]
    args += ['--collect-only'] if collect else ['--junitxml=' + str(xml)]
    result = {'target': stem, 'temporary_directory': str(temporary), 'return_code': None, 'timed_out': False, 'events': [], 'errors': []}
    try:
        with (folder / (stem + '.log')).open('wb') as log:
            process = subprocess.Popen(args, cwd=root, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=os.name == 'posix')
            try:
                result['return_code'] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result['timed_out'] = True
                terminate(process)
                result['return_code'] = process.returncode
        if not events.is_file():
            result['errors'].append('missing event journal')
        else:
            for line in events.read_text(encoding='utf-8').splitlines():
                try:
                    result['events'].append(json.loads(line))
                except ValueError:
                    result['errors'].append('incomplete or malformed journal record')
        finish = [e for e in result['events'] if e['event'] == 'session_finish']
        if len(finish) != 1 or finish[0]['exit_code'] != result['return_code']:
            result['errors'].append('missing or mismatched session completion')
        if not collect:
            if not xml.is_file():
                result['errors'].append('missing JUnit XML')
            else:
                cases = list(ET.parse(xml).iter('testcase'))
                result['junit_cases'] = len(cases)
    except Exception as exc:
        result['errors'].append(type(exc).__name__ + ': ' + str(exc))
    return result


def inventory(events: list[dict]) -> list[str]:
    return [node for event in events if event['event'] == 'inventory' for node in event['nodeids']]


def summarize(expected: list[str], runs: list[dict]) -> dict:
    phases = defaultdict(list)
    observed = []
    issues = []
    for run in runs:
        observed.extend(inventory(run['events']))
        issues.extend(f'{run["target"]}: {x}' for x in run['errors'])
        if run['timed_out'] or run['return_code'] not in (0, 1):
            issues.append(f'{run["target"]}: interrupted or invalid pytest exit {run["return_code"]}')
        for event in run['events']:
            if event['event'] == 'phase':
                phases[event['nodeid']].append(event)
            elif event['event'] == 'collection_error':
                issues.append(f'{run["target"]}: collection error')
    cases = []
    for nodeid in sorted(set(expected) | set(observed) | set(phases)):
        events = phases[nodeid]
        by_when = Counter(e['when'] for e in events)
        finished = by_when['setup'] == 1 and by_when['teardown'] == 1 and by_when['call'] <= 1
        if not finished:
            status = 'incomplete'
        elif any(e['outcome'] == 'failed' for e in events):
            status = 'failed'
        elif any(e['outcome'] == 'skipped' or e.get('wasxfail') for e in events):
            status = 'skipped'
        elif by_when['call'] == 1 and all(e['outcome'] == 'passed' for e in events):
            status = 'passed'
        else:
            status = 'incomplete'
        cases.append({'nodeid': nodeid, 'status': status,
                      'seconds': sum(e['seconds'] for e in events),
                      'reason': next((e.get('reason') for e in events if e.get('reason')), None)})
    duplicate = [n for n, count in Counter(observed).items() if count > 1]
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted((set(observed) | set(phases)) - set(expected))
    if len(set(expected)) != len(expected):
        issues.append('duplicate baseline inventory node IDs')
    if not expected:
        issues.append('no test cases collected')
    if sum(r.get('junit_cases', 0) for r in runs) != len(cases):
        issues.append('JUnit case count differs from exact-node-ID evidence')
    counts = Counter(case['status'] for case in cases)
    complete = not (issues or duplicate or missing or unexpected or counts['incomplete'])
    return {'collected': len(expected), 'cases': cases,
            **{key: counts[key] for key in ('passed', 'failed', 'skipped', 'incomplete')},
            'coverage_complete': complete, 'duplicate': duplicate, 'missing': missing,
            'unexpected': unexpected, 'evidence_errors': issues}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=SCRIPTS.parent)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=float, default=300)
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 3600:
        parser.error('--timeout must be greater than zero and at most 3600 seconds')
    root = args.root.resolve()
    output = (args.output or root / 'verification-local').resolve()
    output.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:12]
    folder = output / run_id; folder.mkdir()
    state = {'run_id': run_id, 'run_directory': run_id, 'status': 'running',
             'started_at': now(), 'platform': platform.platform(), 'python': platform.python_version(),
             'windows_desktop_acceptance': 'NOT_RUN', 'runs': []}
    def save():
        atomic_json(folder / 'status.json', state)
        atomic_json(output / 'status.json', state)
    save()  # invalidate any old green summary BEFORE source reads or test launch
    try:
        before = fingerprint(root)
        atomic_json(folder / 'source-before.json', before)
        env = dict(os.environ)
        env.update(PYTHONPATH=os.pathsep.join((str(root/'src'), str(root/'tests'), str(SCRIPTS))),
                   PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTHONDONTWRITEBYTECODE='1')
        env.pop('PYTEST_ADDOPTS', None)
        env.pop('PYTEST_PLUGINS', None)
        files = sorted((root / 'tests').rglob('test_*.py'))
        collect = invoke(root, folder, 'collection', [str(p) for p in files], env, args.timeout, collect=True) if files else {
            'return_code': 5, 'events': [], 'errors': ['no test files'], 'timed_out': False}
        expected = inventory(collect['events'])
        runs = []
        for index, path in enumerate(files):
            stem = f'{index:03d}-' + path.stem
            result = invoke(root, folder, stem, [str(path)], env, args.timeout)
            runs.append(result)
            state['runs'].append({k: v for k, v in result.items() if k != 'events'})
            save()
            print(path.relative_to(root), result['return_code'], flush=True)
        state.update(summarize(expected, runs))
        state['collection_exit_code'] = collect['return_code']
        if collect['return_code'] != 0 or collect['errors']:
            state['coverage_complete'] = False
            state['evidence_errors'].extend(collect['errors'] or ['baseline collection failed'])
        after = fingerprint(root)
        atomic_json(folder / 'source-after.json', after)
        state['source_unchanged'] = before == after
        state['source_fingerprint_sha256'] = hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()
        if before != after:
            state['coverage_complete'] = False
            state['evidence_errors'].append('source changed during verification')
        state['status'] = 'passed' if state['coverage_complete'] and state['failed'] == 0 else 'failed'
    except BaseException as exc:
        state.update(status='failed', coverage_complete=False, runner_error=type(exc).__name__ + ': ' + str(exc))
    finally:
        state['finished_at'] = now()
        save()
    print(json.dumps({k: v for k, v in state.items() if k not in ('runs', 'cases')}, ensure_ascii=True), flush=True)
    return 0 if state['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
