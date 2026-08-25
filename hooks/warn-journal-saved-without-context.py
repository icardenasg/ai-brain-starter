#!/usr/bin/env python3
"""Block journal-file saves when Step 0's context preflight never ran.

Enforces Step 0 of daily-journal SKILL.md:
  "Run `journal-preflight.py` FIRST — the literal first tool call of every
   /journal, before the opener. Non-negotiable."

The preflight writes a marker at `<vault>/⚙️ Meta/.journal-context/<date>.json`
(also `Meta/...` for non-emoji vaults) recording that every configured source
was pulled. This guard is the backstop for when the model skips Step 0: if a
journal entry for <date> is about to be saved and that marker is ABSENT, the
save is blocked with instructions to run the preflight first.

Codified 2026-07-07 after a /journal session shipped the opener with ZERO
context (no calendar / messages / RescueTime / activity) — the user had to ask
"why didn't you pull everything?". Turns Step 0 from discipline into
infrastructure. Sibling of block-journal-save-without-panel-shown.py.

Triggered on (mirrors the panel-shown guard):
  - Write -> file_path matches /Journals/<Month YYYY>/<file>.md
  - Bash  -> command writes/appends to that path (cat >, tee, redirect, mv, cp)

Fails OPEN: any ambiguity (no vault root, no parseable date, IO error) -> allow.
It blocks ONLY when it positively determines the marker for the entry's date is
missing. Marker present is sufficient proof the preflight ran that day.

Bypass: JOURNAL_CONTEXT_BYPASS=1 (env or inline prefix) — addendum/out-of-band
edits to an already-contextualized entry.
"""

import json
import os
import re
import sys
import datetime
from pathlib import Path

# Inline-bypass support (mirrors the panel-shown guard): os.environ can't see an
# inline `VAR=1 cmd` prefix on the Bash path. Fail-open to no-op if _lib absent.
sys.path.insert(0, str(Path(__file__).resolve().parent / "_lib"))
try:
    from cmd_env import inline_bypass
except Exception:
    def inline_bypass(command, var):  # type: ignore
        return False

if os.environ.get("JOURNAL_CONTEXT_BYPASS") == "1":
    sys.exit(0)

JOURNAL_PATH_RE = re.compile(r"Journals/[A-Z][a-zA-Z]+\s+\d{4}/[^/\"']+\.md")
CREATION_DATE_RE = re.compile(r"creationDate:\s*(\d{4}-\d{2}-\d{2})")
DAY_BOUNDARY = (3, 45)  # 3:45am — entries before this belong to the prior day


def _target_today():
    now = datetime.datetime.now()
    b = now.replace(hour=DAY_BOUNDARY[0], minute=DAY_BOUNDARY[1], second=0, microsecond=0)
    d = now.date()
    if now < b:
        d -= datetime.timedelta(days=1)
    return d.isoformat()


def _norm(text):
    """Backslashes -> forward slashes before ANY path matching.

    On Windows the journal path arrives as `C:\\vault\\Journals\\May 2026\\x.md`,
    which matches none of the '/'-written patterns here. Without this the gate
    never opens on Windows: no warning, no error, no signal — a silent fail-open
    on the platform rather than a visible break. Matching only; nothing here is
    executed as a path (and Python opens `C:/x/y` fine on Windows)."""
    return text.replace("\\", "/")


# One label token (e.g. an emoji folder prefix) may sit between the vault root and
# `Journals/`, as in `<vault>/📓 Journals/Agosto 2026/`. It must be a SINGLE token:
# no slashes, no whitespace, and no quotes. Excluding quotes is what stops a shell
# prefix from being swallowed here — see _vault_root.
_LABEL = r"(?:[^/\n\"'\s]+\s)?"
_MONTH = r"Journals/[A-Z][a-zA-Z]+\s+\d{4}/"

# `cd "<abs>" && ... Journals/<Month YYYY>/...` — the idiom the skill's own Bash
# examples produce when the journal path is written relative to the vault.
_CD_RE = re.compile(r"(?:^|[;&|]\s*)cd\s+[\"']?((?:(?<![A-Za-z])[A-Za-z]:)?/[^\n\"']+)[\"']?")


def _vault_root(text):
    r"""Absolute dir before the '<optional label >Journals/<Month YYYY>/' segment.
    Anchored on the absolute path (starts at a real '/', or a `C:/` drive root),
    so a leading shell prefix like `cat > '/vault/.../x.md'` is NOT captured into
    the root (that was the 2026-07-07 Bash-path fail-open bug).

    The drive-letter alternative is guarded by `(?<![A-Za-z])` so a URL like
    `http://host/Journals/May 2026/` cannot have its `p:` read as a drive.

    2026-08-24 fix: the label group used to be `[^/\n]*\s`, which allows quotes.
    On `cd "/Users/mac/Brain" && cat > "📓 Journals/Agosto 2026/x.md"` it happily
    matched `Brain" && cat > "📓 ` as the label, leaving the root truncated to
    `/Users/mac` — so the marker lookup pointed outside the vault and every save
    was DENIED with a correct-looking path. A false block, not a fail-open: worse
    than the bug it replaced, because the guard looked like it was working.
    The label is now a single quote-free, space-free token.

    Second half of the fix: when the journal path is RELATIVE (the common form,
    since a `cd` into the vault comes first), there is no absolute path to anchor
    on and this used to fail open — the guard silently did nothing. Fall back to
    the `cd` target, but only if that directory actually contains the Journals
    path from the command."""
    m = re.search(
        r"((?:(?<![A-Za-z])[A-Za-z]:)?/[^\n\"']*?)/" + _LABEL + _MONTH,
        text)
    if m:
        return m.group(1)

    # Relative journal path: anchor on `cd <abs>` when it really is the vault.
    rel = re.search(_LABEL + _MONTH, text)
    if not rel:
        return None
    cds = _CD_RE.findall(text)
    for cand in reversed(cds):          # last cd wins
        cand = cand.rstrip("/") or "/"
        if os.path.isdir(os.path.join(cand, rel.group(0).rstrip("/"))):
            return cand
    return None


def _marker_exists(vault, date_iso):
    for meta in ("⚙️ Meta", "Meta"):
        if os.path.exists(os.path.join(vault, meta, ".journal-context", f"{date_iso}.json")):
            return True
    return False


_SHELL_WRITE = ("cat >", "cat >>", "tee ", "tee -", " > ", " >> ", "mv ", "cp ", "rsync ")

# A journal written from an inline interpreter script (`python3 - <<EOF ... EOF`)
# used to sail straight past this guard: none of the shell redirect markers above
# appear in such a command, so `blob` stayed empty and the hook no-opped. Found
# 2026-08-24, when an entire /journal session's edits were made that way and the
# guard never fired once. Requires BOTH an interpreter and a write-shaped call, so
# a read-only script that merely names a journal path still fails open.
_INTERP_RE = re.compile(r"\b(?:python3?|node|ruby|perl|deno|bun)\b")
_INTERP_WRITE_RE = re.compile(
    r"write_text\(|writelines\(|\.write\(|writeFileSync|appendFileSync|"
    r"File\.write|open\([^)]*['\"][wax]")


def _shell_write(cmd):
    return any(m in cmd for m in _SHELL_WRITE)


def _interpreter_write(cmd):
    return bool(_INTERP_RE.search(cmd)) and bool(_INTERP_WRITE_RE.search(cmd))


try:
    payload = json.load(sys.stdin)
except Exception:
    sys.exit(0)

tool_name = payload.get("tool_name", "")
tool_input = payload.get("tool_input", {}) or {}

blob = ""          # text to scan for path + date + vault root
if tool_name == "Write":
    fp = _norm(tool_input.get("file_path", "") or "")
    if JOURNAL_PATH_RE.search(fp):
        blob = fp + "\n" + (tool_input.get("content", "") or "")
elif tool_name == "Bash":
    cmd = tool_input.get("command", "") or ""
    # inline_bypass (shlex-based) can't parse a `cat << EOF` heredoc — and journals
    # are ALWAYS written as heredocs — so also accept a parse-independent env-prefix
    # form (`JOURNAL_CONTEXT_BYPASS=1 cat > ...`). Either satisfies the escape hatch.
    if inline_bypass(cmd, "JOURNAL_CONTEXT_BYPASS") or \
       re.search(r"(^|\s)JOURNAL_CONTEXT_BYPASS=1(\s|$)", cmd):
        sys.exit(0)
    cmd_norm = _norm(cmd)
    if JOURNAL_PATH_RE.search(cmd_norm) and (_shell_write(cmd) or _interpreter_write(cmd)):
        # Normalized, because _vault_root() below must see forward slashes too.
        blob = cmd_norm

if not blob:
    sys.exit(0)  # not a journal save

vault = _vault_root(blob)
if not vault or not os.path.isdir(vault):
    sys.exit(0)  # can't locate vault -> fail open

dm = CREATION_DATE_RE.search(blob)
date_iso = dm.group(1) if dm else _target_today()

if _marker_exists(vault, date_iso):
    sys.exit(0)  # preflight ran for this date -> allow

err = (
    "BLOCKED by warn-journal-saved-without-context hook.\n\n"
    f"No preflight marker for {date_iso} at\n"
    f"  {vault}/⚙️ Meta/.journal-context/{date_iso}.json\n"
    "-> Step 0's context pull never ran, so this journal would ship with no\n"
    "calendar / messages / RescueTime / activity context. That is the exact\n"
    "2026-07-07 failure this guard exists to stop.\n\n"
    "Fix (do this, then re-issue the save):\n"
    '  1. python3 "⚙️ Meta/scripts/journal-preflight.py"\n'
    "  2. Make the calendar + email + Slack + health MCP pulls it prints.\n"
    "  3. Fold the context into ## Today + a context_sources: frontmatter block.\n\n"
    "Bypass (addendum / pre-contextualized entry): JOURNAL_CONTEXT_BYPASS=1"
)
# JSON-decision output (exit 0) — NOT exit 2. This is the public-installer-compatible
# blocking form (mirrors block-secret-in-note.py): a hooks.json `... || echo '{allow}'`
# crash-fallback then fails OPEN correctly, because a real block exits 0 (fallback never
# fires) while only a crash exits non-zero (fallback allows). Works identically for the
# personal registration (Claude Code honors permissionDecision=deny).
print(json.dumps({"hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": err}}))
sys.exit(0)
