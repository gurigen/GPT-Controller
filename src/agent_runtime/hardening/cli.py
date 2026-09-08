from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from .common import digest, load_json, state_root
from .control import Control
from .integration import doctor
from .output import safe_output
from .state import Ledger
from .validation import validate_action_extra


def main() -> None:
    parser = argparse.ArgumentParser(description="Local GPT Controller hardening administration")
    parser.add_argument("--config", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument("--no-ui", action="store_true")
    doctor_parser.add_argument("--require-git", action="store_true")
    doctor_parser.add_argument("--require-ui", action="store_true")
    sub.add_parser("pause")
    sub.add_parser("resume")
    cancel = sub.add_parser("cancel")
    cancel.add_argument("action_id")
    approve = sub.add_parser("approve")
    approve.add_argument("action_file", type=Path)
    approve.add_argument("--expected-sha256", required=True)
    approve.add_argument("--ttl", type=int, default=300)
    sub.add_parser("cleanup-artifacts")
    serve = sub.add_parser("serve-artifacts")
    serve.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    from agent_runtime.config import Config
    config = Config.load(args.config)
    if args.command == "doctor":
        if args.no_ui and args.require_ui:
            parser.error("--no-ui and --require-ui are incompatible")
        output = doctor(config, probe_git=True, probe_host=not args.no_ui)
    elif args.command == "pause":
        output = Control(config).pause(True)
    elif args.command == "resume":
        # Resume cannot discard unacknowledged GUI operations.
        Control(config).pause(False)
        try:
            Control(config).check(input_operation=True)
        except Exception:
            Control(config).pause(True)
            raise
        output = {"paused": False}
    elif args.command == "cancel":
        output = Control(config).cancel(args.action_id)
    elif args.command == "approve":
        action = load_json(args.action_file)
        from agent_runtime.protocol import validate_action
        validate_action(action)
        validate_action_extra(action)
        payload_hash = digest(action)
        if payload_hash != args.expected_sha256:
            parser.error("Action content changed; approval was NOT granted")
        Ledger(state_root(config) / "execution.sqlite3").approve(action["id"], payload_hash, args.ttl)
        output = {"action_id": action["id"], "action_sha256": payload_hash, "approved_locally": True, "expires_in_seconds": args.ttl}
    elif args.command == "cleanup-artifacts":
        from .artifacts import ArtifactStore
        output = {"expired_artifacts_removed": ArtifactStore(config).cleanup()}
    else:
        from .artifacts import serve_http
        token = os.environ.get("GPT_CONTROLLER_ARTIFACT_TOKEN", "")
        serve_http(config, token, args.port)
        return
    print(json.dumps(safe_output(output), ensure_ascii=False, indent=2))
    if args.command == "doctor":
        if args.require_git and output.get("git", {}).get("status") != "reachable":
            raise SystemExit(2)
        if args.require_ui and output.get("gui_ready") is not True:
            raise SystemExit(3)


if __name__ == "__main__":
    main()
