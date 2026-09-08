"""Rebuild this candidate from the exact upstream Git tree, without remote writes.

Usage: python developer/rebuild.py --checkout /path/to/upstream --output /new/path
The checkout's current branch and worktree are never changed. The pinned tree must
already exist in its object database; a Git clone of upstream provides that tree.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess

BASE_TREE = '158f8361cba27442fa5b7cb1b1d47f04f8940593'
BUNDLE = Path(__file__).resolve().parents[1]


def git(checkout: Path, *args: str) -> bytes:
    return subprocess.run(['git', '-C', str(checkout), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout


def rebuild(checkout: Path, output: Path) -> dict:
    checkout = checkout.resolve(); output = output.resolve()
    if output.exists():
        raise ValueError('Output must be a new directory; existing contents are never overwritten')
    if output.is_relative_to(checkout) or output.is_relative_to(BUNDLE):
        raise ValueError('Output must be outside the upstream checkout and candidate bundle')
    manifest = json.loads((BUNDLE / 'SOURCE_MANIFEST.json').read_text(encoding='utf-8'))
    if manifest['base_tree'] != BASE_TREE:
        raise ValueError('Unexpected upstream tree')
    records = git(checkout, 'ls-tree', '-r', '-z', BASE_TREE).split(b'\0')
    files = []
    for record in records:
        if not record:
            continue
        head, raw_name = record.split(b'\t', 1)
        mode, kind, sha = head.decode('ascii').split()
        name = raw_name.decode('utf-8')
        path = PurePosixPath(name)
        if mode != '100644' or kind != 'blob' or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
            raise ValueError('Unsupported or unsafe pinned source entry')
        files.append((name, sha))
    if len(files) != 61:
        raise ValueError('Unexpected pinned source inventory')
    output.mkdir(parents=True)
    # On failure leave the newly created output for diagnosis, never change source.
    for name, sha in files:
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git(checkout, 'cat-file', 'blob', sha))
    patch = str(BUNDLE / 'changes.patch')
    subprocess.run(['git', 'apply', '--check', patch], cwd=output, check=True, timeout=30)
    subprocess.run(['git', 'apply', patch], cwd=output, check=True, timeout=30)
    for name, expected in manifest['files'].items():
        path = output / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Reconstructed source mismatch: ' + name)
    (output / 'SOURCE_MANIFEST.json').write_bytes((BUNDLE / 'SOURCE_MANIFEST.json').read_bytes())
    (output / 'changes.patch').write_bytes((BUNDLE / 'changes.patch').read_bytes())
    receipt = {'base_tree': BASE_TREE, 'source_files_verified': len(manifest['files']),
               'release': manifest['runtime_extension'], 'tests_run_by_rebuild': False,
               'git_remote_writes': False, 'deployment': False}
    (output / 'REBUILD_RECEIPT.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(rebuild(args.checkout, args.output), indent=2))


if __name__ == '__main__':
    main()
