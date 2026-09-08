from __future__ import annotations
import re
from pathlib import Path
from .common import ControlError, identifier, load_json


def validate(value, action_id: str) -> None:
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError('depends_on must be a bounded list')
    seen = set()
    for dependency in value:
        if not isinstance(dependency, dict) or set(dependency) != {'action_id','action_sha256'}:
            raise ValueError('dependencies require exact Action ID and SHA256')
        ident = identifier(dependency['action_id'])
        if ident.casefold() == action_id.casefold() or ident.casefold() in seen:
            raise ValueError('self/duplicate dependency')
        seen.add(ident.casefold())
        if not isinstance(dependency['action_sha256'],str) or not re.fullmatch('[a-f0-9]{64}',dependency['action_sha256']):
            raise ValueError('invalid dependency SHA256')


def state(config, action: dict) -> tuple[list[str], list[str]]:
    missing, failed = [], []
    for dependency in action.get('depends_on', []):
        ident = dependency['action_id']
        path = config.repo_path / 'results' / f'{ident}.json'
        if not path.exists():
            missing.append(ident)
            continue
        result = load_json(path)
        if (result.get('action_id') != ident or result.get('action_sha256') != dependency['action_sha256']
            or result.get('status') != 'succeeded' or result.get('output_truncated')
            or result.get('goal', {}).get('goal_achieved') is False):
            failed.append(ident)
    return missing, failed


def check(config, action: dict) -> None:
    missing, failed = state(config,action)
    if missing or failed:
        raise ControlError('blocked', f'dependencies not verified: missing={missing}, failed_or_mismatched={failed}')
