# Candidate contract — q-agent-v4 + hardening 4.1.0rc2

This document overrides conflicting historical upstream notes in this candidate only. It does not assert an upstream release or actual deployment. Names below are executable only in the patched candidate.

## Identity and execution

Actions retain protocol `q-agent-v4` and exact targets use `target: {mode: agent, agent: "my-pc"}`. The other audit's `target.agent_id`/q-agent-v5 example is not accepted. Pending filename must equal Action ID. Claims and results contain the SHA256 of canonical UTF-8 JSON (sorted keys, compact separators, no non-finite numbers). IDs are case-insensitively unique in the local ledger. No claimed/ambiguous work is reassigned merely because a lease expires.

SQLite records action and step start, effect class, content hash and result with synchronous FULL. Process crash before a durable result is not proof of zero side effects. Read-only operations may retry; unsafe operations are not automatically replayed. `continue_on_error` never bypasses an ambiguous/blocked/cancelled/needs_user halt. A caller can retrieve the exact cached completed result, but the PC work is not rerun.

## Goals and dependencies

`goal` has only `description` and 1..100 `conditions`. Supported conditions are `file.exists`, `file.sha256`, `file.text_contains`, `csv.columns`, and `output.matches`. File conditions explicitly name workspace and relative path. Comparisons use a source index or `last`/`outputs`, a dot path and one of equals/not_equals/contains/truthy/exists, optionally bounded all/any/not composition. Missing or truncated evidence cannot be used to infer success. Full arbitrary natural-language task planning is not inside Runtime.

`depends_on` is an array of `{action_id, action_sha256}`. A missing result waits; a failed/ambiguous result, mismatched hash, or explicitly unachieved goal blocks the dependent action. This is not an authorization to infer or submit new tasks.

`not_before`, `created_at` and `expires_at` require timezone-qualified timestamps. Local `max_action_age_seconds`, when configured, requires created_at and limits stale work even without expires_at. TTL does not justify retry.

## Permission checks

Permissions are derived from operation content, not simply from `requires: [general]`. `security.mode` is `trusted` (compatibility default) or `restricted`. Local `security.rules` map permission names to allow/ask/deny. Explicit local rules take precedence over mode defaults; this is a policy configuration choice, not an OS sandbox. Major permissions: shell.exec, workspace.sync, filesystem.read/write/delete, browser.control/launch/evaluate/close_user_tab, ui.observe/input, clipboard.read/write, artifact.export, secrets.read, control.resume.

Approval is local, one-use and bound to the whole Action hash and expiry. `approval.request` returns a request description; it cannot grant approval. Approval must precede queue submission. Do not approve a modified Action using the old hash. Raw shell can read/write local configuration in trusted mode under its actual Windows rights; do not describe policy flags as an unbreakable boundary.

## Desktop

`desktop.observe` requests input desktop, foreground window and screen capture, returning an observation ID, PNG artifact, timestamp, physical-pixel origin/size, monitor/DPI metadata and foreground identity. `desktop.act` references observation_id and exactly one supported UI operation. Coordinates are image pixels converted using the captured origin. Default verification blocks input if the image/foreground/layout changed or the observation is older than 10 seconds (maximum 30). A dynamic clock/animation may require re-observation; turning off pixel verification is an explicit weaker guarantee.

`desktop.verify`/`goal.verify` evaluates a declared goal. There is no magical UI-success inference. Native UIA call completion is not proof that a save/send occurred. Windows foreground/session checks and Unicode input paths need real desktop acceptance. UAC/login/security surfaces must be handed to the user rather than disabling their protection.

## IPC and cancellation

User-session host and background runtime share a locally protected key. Requests and responses include authenticated content, ID, Action hash and expiry. Local spool locking prevents two hosts processing the same spool. Unclaimed timed-out requests are cancelled before removal. Claimed timed-out requests become ambiguous and quarantine new input until authenticated completion; a timer or unsigned response is not sufficient. A blocked native UIA call cannot be retroactively cancelled. Watchdog supervision detects stuck hosts, but this candidate has no separately isolated native subprocess for every GUI primitive.

`action.cancel` inside an ordinary Action cannot pre-empt a busy serialized queue by itself. Use local CLI cancel, or the out-of-band Git path `control/cancel/<action-id>.json` with matching action_id. `control/pause/<agent-id>.json` can request pause; remote pause=false never silently clears local quarantine. Control polling uses a separate bare mirror to avoid corrupting the runtime worktree.

## Artifacts

Encrypted local store uses AES-GCM, authenticated metadata, SHA256, per-item expiry and total plaintext-size quota. On Windows the key is protected with current-user DPAPI; test Linux uses a separate mode-0600 file. Keys are not stored in the artifact database. This is not a complete protection against that same user account.

`artifact.get` returns bounded base64 chunks, next_offset, eof, per-chunk hash and whole artifact hash, subject to export approval. Exported chunks are plaintext content encoded as base64, not encryption, and remain in private Git history. Sensitive credential-state artifacts cannot use ordinary export. Browser/GUI source PNGs may also remain on the local filesystem; not all local files are encrypted or covered by store cleanup.

Local administration `serve-artifacts` binds 127.0.0.1 with a bearer supplied only through `GPT_CONTROLLER_ARTIFACT_TOKEN`. It exposes no command execution. No public listener/tunnel is auto-created. Cross-PC retrieval requires an separately authorized transport. Real PNG reconstruction and local authenticated HTTP are tested; user-PC-to-ChatGPT image delivery is not verified.

## Discovery and publication

A separate temporary Git index publishes `agents/<agent>/manifest.json` and `status.json`, at a local interval of at least60 seconds (default300). Capability configuration is distinguished from a successful live GUI probe. Status valid_until is an observation expiry, not a reexecution lease. Push conflicts are not force-pushed. A result outbox persists locally before publication and retries only publication; restart cannot reinterpret it as work needing execution.

## Files and diagnostics

Typed writes deny overwrite unless requested; compare hashes when overwriting critical files. Atomic no-clobber creation uses a same-filesystem hard link from a completed temporary file. Overwrite preconditions are not a universal filesystem transaction under hostile concurrent writers. Typed deletes default to a local recovery area and forbid deleting workspace root. No automatic trash purge is performed.

stdout/stderr and results have distinct bounded collection budgets. Redaction is best-effort for recognizable credentials and configured environment secrets. Arbitrary unlabelled data and images are not classified by a general DLP engine. Large third-party browser return values may allocate memory before being reduced; no global RAM sandbox is claimed.

`agent.doctor` makes read-only Git checks and an optional authenticated host probe; it does not execute queued work as a health test. CLI `--require-git` or `--require-ui` fails its exit status when that required check cannot be proved. Dependency-installed and heartbeat-only are not GUI ready.
