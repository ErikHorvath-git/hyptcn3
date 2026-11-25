"""The seal of the test roles: the ledger, the guards and the one final run (protocol v5, package B7c, agent S).

Binding texts: the lead's skeleton dokazy/B7/kostra/KOSTRA.md section 7 with the B7c row of section 8, the design
dokazy/B7/navrh/NAVRH_B7c.md sections 1.1 and 2, and proposal 10.1, 10.2, 10.5, 10.8 and 11
(docs/NAVRH_PROTOKOL_V5.sk.md). The roles test_benign and test_controls of a campaign are used once, by one final
command (python -m tcn.finalne, package B7c agent E), on the same replays for every model.

    SEALED_ROLES                the sealed roles: test_benign, test_controls
    ZAZNAM                      the ledger of record, a file in git: data/results/kniha_pecati.json (check E of
                                scripts/check_claims.sh: it carries the provenance fields and its values)
    KNIHA                       the ledger of this process, which every guard reads: ZAZNAM unless vlastna_kniha
                                switched it (design B7c 5.1)
    vlastna_kniha(path)         a context manager: KNIHA is a ledger of its own outside data/results (a G1 dry run)
    stage(mode, *, ledger=None) the stage that STAGE_RULE gives plan mode `mode` on a ledger (KNIHA when None): final
                                or generalka on the ledger of record, suchy on any other (a final run, kontrola)
    record_stage(mode, sessions, *, ledger=None)
                                the stage of a record that covers `sessions` (RECORD_STAGE_RULE, finding N2 of B7c,
                                package B9b): {stage, basis}; final or generalka only when the ledger of record holds
                                every sealed session of the record, and final only when the ledger at HEAD holds them
                                too; suchy otherwise, the basis says why (the records of tcn.eval of protocol schema
                                3 and the ending record of a campaign, scripts/campaign.py)
    identita(hashes)            the identity of a seal (IDENTITY_RULE)
    zapis(records, *, protocol, protocol_sha256, mode, command, ledger=None)
                                writes the archives of the sessions of the sealed roles of a plan into the ledger (the
                                campaign calls it, package B9; one session or many, idempotent)
    zapis_korpus(index, *, command, ledger=None)
                                zapis of the sealed sessions of a corpus index (features/dataset.py)
    odtlacok(archive)           the content fingerprint of a feature archive, of its path or of its arrays
                                (CONTENT_RULE, the lead's answer to Q31): (sha256, None) or (None, why)
    kontrola(archive=None, *, sha256=None, purpose, ledger=None, sessions=None, paths=None)
                                the check before every replay or scoring of an archive: the decision, or Zapecatene;
                                an archive given by its path is bound to the ledger by its bytes, the session of its
                                directory and its content, one given by its sha256 by its bytes and by the session
                                (sessions) and the path (paths) its caller gives with it (SEALED_RULE)
    kontrola_okien(windows, purpose, *, ledger=None)
                                kontrola of the archives a window set holds: by their bytes and the sessions the set
                                names (tcn.metody.Okna), and where its index records name their path
                                (safeguard.training.Windows) also by the directory and the content of each
    kontrola_snimok(directory, *, purpose, ledger=None)
                                the check before the raw snapshots of a session enter a detector: the session that the
                                session.json of the directory or of its parent names (SNAPSHOT_RULE), or the marker of
                                a raw/ restored from an archive (RESTORED_RULE, the lead's answer to Q19)
    stav(index, *, ledger=None) the seal of a corpus without consuming it: its identity, what the ledger holds, its runs
    spotrebuj(index, *, out, command, ledger=None) -> Beh
                                consumes the seal of a corpus, once, for the final run of this process (RUN_RULE);
                                the run's stage comes from its ledger (STAGE_RULE): final or generalka on ZAZNAM,
                                suchy on any other; at stage final the ledger at HEAD holds the seal (SEAL_IN_GIT_RULE)
    otvoreny()                  the open final run of this process, or None
    zaloz(*, command, ledger=None)
                                creates an empty ledger (refused when the file exists)
    python -m tcn.pecat zaloz | zapis --corpus I | zapis --audit A --mode M | stav --corpus I | kontrola --archive A
                                [--ledger L]
                                zapis --audit: one accepted session of a campaign from its audit record, the form the
                                campaign's runner calls as the owner (package B9a; scripts/campaign.py SEAL_RULE)

The guarded entry points (GUARD_RULE) call kontrola before anything is read or written: safeguard replay --archive
(safeguard/cli.py), tcn.porovnanie replay, safeguard.runtime.replay_archive, the methods of tcn/metody.py and
tcn/opisne.py given a window set that holds a sealed archive, scripts/controls.py outcomes of a session of role
test_controls, the TCN-gui (TCN-gui/analyza.py resolve_input, before it opens an input: analyze, tcn_gui.py with
its button and --png, TCN-gui/porovnanie.py compare), the legacy activity classifier tcn/klasifikator.py before it
loads each archive of an index, the qualification of the feature columns (features/qualification.py from_index,
package B11) before it opens the archive of a session of a sealed role, which only the index of a rehearsal gives it,
and tcn.eval far and udalosti before they read the rows of a replay, by the archive_sha256 of its configuration.json
(GUARD_RULE names the last two since the ledger was recreated for question Q31). The seal binds the session and the
content of an archive, not only its bytes (SEALED_RULE, the lead's answer to Q31): kontrola given the path of an
archive also finds the session of its directory as kontrola_snimok does and computes its content fingerprint
(odtlacok, CONTENT_RULE), which zapis stores beside every sealed archive. Two callers give neither the path nor the
content of an archive, so the content does not bind them (Q31, for the lead): tcn.eval gives the archive_sha256 of a
replay (its bytes alone), and a window set of tcn.metody.Okna names the sha256 and the session of each archive (its
bytes and its session). The raw snapshots of a session enter a detector through kontrola_snimok (SNAPSHOT_RULE):
safeguard replay --snapshots and watch, safeguard.runtime.run_directory (also under the TCN-gui and safeguard run),
scripts/validate_safeguard.py and the legacy standalone detector scripts/detektor.py. A guard refuses by name with
Zapecatene, a ValueError, so every caller that reports a ValueError reports the refusal. Unguarded, by design or for
the lead: safeguard.runtime.Detector.process on frames, features.archive.load (reading is no replay) and the live
snapshots of safeguard watch and run before the campaign writes the session into the ledger.

The ledger protects against mistakes, not intent (TIMESTAMP_RULE): a person can edit the file. Its time stamp is the
push to the remote repository of the commit that holds it, and every run records whether the seals it consumed were
in the ledger at HEAD before it began (seal_in_git); a run of stage final is refused unless they were
(SEAL_IN_GIT_RULE, design B7c 5.2).
"""
import argparse
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # python -m tcn.pecat from another directory
    sys.path.insert(0, str(ROOT))

from scripts.protocol_v5 import MODES, SCHEMA as PROTOCOL_SCHEMA  # noqa: E402

# Schema 2 (question Q31): every archive of the ledger carries its content fingerprint (content_sha256, content_why),
# which the content binding of kontrola reads; a ledger of schema 1 has none, so it is refused by name, not read without
# that binding.
SCHEMA = "hyptcn3/seal-ledger/2"
RUN_SCHEMA = "hyptcn3/seal-run/1"
DECISION_SCHEMA = "hyptcn3/seal-decision/1"
INDEX_SCHEMA = "hyptcn3/corpus-index/1"
# The test roles of the plan: features/dataset.py ROLES without its FIT_ROLES, the roles training never loads (a test
# pins the equality). Skeleton B7 section 7.
SEALED_ROLES = ("test_benign", "test_controls")
TRACKED = "data/results/kniha_pecati.json"  # The ledger's path in the repository.
RESULTS = ROOT / "data" / "results"
ZAZNAM = ROOT / TRACKED  # The ledger of record (STAGE_RULE; design B7c 5.1, question Q15).
KNIHA = ZAZNAM  # The ledger of this process, which every guard reads (vlastna_kniha switches it for a G1 dry run).
# The stage of a record (proposal 11.1, scripts/controls.py STAGES) that a final run of each plan mode writes on the
# ledger of record; on any other ledger the stage is DRY_STAGE (STAGE_RULE).
STAGE = {"campaign": "final", "rehearsal": "generalka"}
DRY_STAGE = "suchy"
REHEARSAL_MARK = "generálka: nikdy v datasete (návrh 10.4, 10.5); kniha pečatí sa vedie, nevynucuje"
FINAL_MARK = "finálne vyhodnotenie (návrh 10.8): jeden beh, pečať testovacích rolí spotrebovaná týmto behom"
DRY_MARK = ("suchý beh (návrh 10.2): dokazuje logiku reťazca, nie vedu ani senzor; nikdy v texte práce (kap. 11.1); "
            "kniha pečatí mimo data/results")
MARKS = {"final": FINAL_MARK, "generalka": REHEARSAL_MARK, DRY_STAGE: DRY_MARK}  # The mark of each stage.
_SHA = re.compile(r"[0-9a-f]{64}")
# The fields of features/archive.py save (the lead's answer to Q31, CONTENT_RULE): those of the content fingerprint, in
# its order, and those it leaves out; tcn/tests/test_pecat.py pins that together they are every field save writes.
CONTENT_FIELDS = ("mena", "matica", "seq", "casy", "valid", "perbin", "biny", "chain_ids", "snimky", "poznamky",
                  "quality_json", "layout_json")
NOT_CONTENT = ("trvanie_s", "schema", "quality_policy", "max_medzera_s")
# The bindings of an archive to the ledger (SEALED_RULE), in the order a refusal names them.
BINDINGS = ("bytes", "session", "content")
# Why the content does not bind an archive given by its sha256 without its path (the decision's checked content_why).
NO_PATH = "kontrola was given its sha256 without its path (paths), so its content does not bind it"

# ------------------------------------------------------------------ the rules (written into the ledger and the records)

IDENTITY_RULE = (
    "the identity of a seal is the sha256 of the ASCII lines of the sorted sha256 hex digests of the feature archives "
    "(the bytes of the file, features_sha256 of the index) of the sessions of the sealed roles test_benign and "
    "test_controls, each line ending in a newline (what sort | sha256sum gives for them); it is no path and no index, "
    "so a copy of the corpus under another path has the same seal (skeleton B7 section 7)")
SEALED_RULE = (
    "an archive is sealed when the ledger holds it by one of three bindings (the lead's answer to Q31): its bytes (the "
    "ledger holds its sha256), its session (the ledger holds an archive of the session id that the directory of an "
    "archive given by its path names, read as SNAPSHOT_RULE reads a snapshot directory: the session.json in it, its "
    "restore marker, then those of its parent; or the session id its caller names for it, as a window set does for "
    "each archive it holds) or its content (the ledger holds an archive of its content fingerprint, CONTENT_RULE); "
    "kontrola binds an archive given by its path by all three, and one given by its sha256 by its bytes and by what "
    "its caller gives with it, the session id it names (sessions) and the path of the archive (paths), whose directory "
    "and content bind it as well: kontrola_okien gives the sessions a window set names for its archives and the paths "
    "its index records name (safeguard.training.Windows), tcn.eval the sha256 of a replay alone; a session.json or a "
    "restore marker that cannot be read or names no session_id binds no session, and an archive whose arrays cannot be "
    "read has no fingerprint: the other bindings decide and the decision says why; zapis writes the archives of the "
    "sessions of the sealed roles of a plan with the content fingerprint of each (the campaign at acceptance, package "
    "B9; zapis_korpus for a corpus index); an archive bound to none is not sealed: the ledger is the seal, whatever "
    "the path or the role a caller names; the seal binds the session and the content, not only the bytes of its "
    "archive (verification of B7c, F8; verification of G0, S1): a re-extraction of a sealed session given by its path "
    "is sealed by its session in the session's directory and by its content anywhere, and in plan mode campaign zapis "
    "refuses a second archive with other bytes for a plan, mode, role and session the ledger holds (a re-extraction is "
    "the same session), in plan mode rehearsal it keeps the second one beside the first (REHEARSAL_RULE: not enforced)")
GUARD_RULE = (
    "a sealed archive of a campaign (one that SEALED_RULE binds to an archive the ledger holds in plan mode campaign) "
    "is replayed or scored only inside the final run that consumed its seal (spotrebuj in the process of the final "
    "command, python -m tcn.finalne), which lets an archive through when it is an archive of the run or bound to one "
    "and every archive of plan mode campaign it is bound to is one of the run's; outside it every guarded entry point "
    "refuses it by name before anything is read or written: safeguard replay --archive, tcn.porovnanie replay, "
    "safeguard.runtime.replay_archive, the methods of tcn/metody.py and tcn/opisne.py given a window set that holds "
    "it, scripts/controls.py outcomes of its controls, the TCN-gui (TCN-gui/analyza.py resolve_input before it "
    "opens an input, so analyze, tcn_gui.py with its button Skontrolovať všetky and --png, and TCN-gui/porovnanie.py "
    "compare), the legacy activity classifier tcn/klasifikator.py before it loads each archive of an index, the "
    "qualification of the feature columns (features/qualification.py from_index, before it opens the archive of a "
    "session of a sealed role) and tcn.eval far and udalosti before they read the rows of a replay (by the "
    "archive_sha256 its configuration.json names, so by its bytes alone); the raw snapshots of its session likewise "
    "(SNAPSHOT_RULE): safeguard replay --snapshots and watch, safeguard.runtime.run_directory (also as the TCN-gui "
    "uses it), scripts/validate_safeguard.py and the legacy standalone detector scripts/detektor.py over --snapshots; "
    "after the final run it stays refused (the test role is used once)")
CONTENT_RULE = (
    "the content fingerprint of a feature archive (content_sha256; the lead's answer to Q31) is the sha256 over the "
    "fields of features/archive.py save that are a function of the raw snapshots and their sidecars, and the order of "
    "the columns, in this order: mena (the order of the columns, which gives the matrix its meaning), matica (the "
    "feature matrix), seq and casy (the sequence number and the time of each row), valid (the validity of each row), "
    "perbin and biny (the per-bin values and the identity of the bins, from the sidecars), chain_ids (the chain of "
    "each row), snimky (the file name of the snapshot of each row), poznamky (the notes of the traversals of each "
    "row), quality_json (the quality of each row) and layout_json (the memory layout of the sidecars); each field adds "
    "the line of its name, its numpy dtype (dtype.str, little-endian) and its shape (the integers joined by commas), "
    "separated by spaces and ended by a newline, then its bytes in C order; it leaves out trvanie_s (the processing "
    "time of each snapshot, which differs at every extraction: the finding of the G0 verification), schema (the "
    "version of the archive format, a constant of the code that a replay requires, safeguard/features.py "
    "frames_from_archive) and quality_policy and max_medzera_s (parameters of the extraction from the protocol, not "
    "of the raw data; the fields they shape, valid and matica, are in); an archive whose arrays cannot be read, or "
    "that lacks one of these fields, has no fingerprint (content_sha256 null, and the reason in content_why of its "
    "entry in the ledger and of the decision)")
REHEARSAL_RULE = (
    "an archive of a rehearsal (plan mode rehearsal, proposal 10.4 and 10.5) is kept in the ledger and not enforced: "
    "every guard lets through an archive that SEALED_RULE binds to archives of a rehearsal alone (the rehearsal's own, "
    "or a re-extraction of one of its sessions) and its decision carries the rehearsal mark, a rehearsal may run the "
    "final command more than once (each run recorded with its number), and every output of such a run carries the "
    "rehearsal mark (stage generalka on the ledger of record, STAGE_RULE)")
RUN_RULE = (
    "spotrebuj consumes the seal of a corpus once: in plan mode campaign every sealed archive of the corpus must be in "
    "the ledger before (written by the campaign), of that plan, role and session, and none may be in an earlier run; "
    "a second final run is refused, also through a copy of the corpus under another path or an index of part of it "
    "(the identity is the archives', not the path's), and so is a corpus any of whose sessions, by plan and session "
    "id, was in an earlier run of plan mode campaign with another archive (the seal binds the sessions; verification "
    "of B7c, F8); the run is recorded in the ledger before any replay, with its archives and its sessions, so a run "
    "that fails still consumed the seal (closed with its outcome); one run is open in a process at a time")
TIMESTAMP_RULE = (
    "the ledger protects against mistakes, not intent: a person can edit the file; its time stamp is the push of the "
    "commit that holds it to the remote repository (proposal 10.6), not its date field; every run records whether the "
    "ledger at HEAD held the seals it consumed before it began (seal_in_git: null when the ledger lies outside the "
    "repository or git is unavailable), enforced at stage final (SEAL_IN_GIT_RULE)")
STAGE_RULE = (
    "the stage of a final run (proposal 11.1) comes from its ledger, never from an option (design B7c 5.1, question "
    "Q15): a run on the ledger of record (ZAZNAM, data/results/kniha_pecati.json) has stage final in plan mode "
    "campaign and generalka in plan mode rehearsal; a run on any other ledger has stage suchy with the mark of a dry "
    "run (a G1 dry run, proposal 10.2, or a test): it proves the logic of the chain, not the science or the sensor, "
    "and is never in the text of the thesis (chapter 11.1); the decisions of kontrola carry the stage and the mark "
    "of the ledger they consult; vlastna_kniha switches the ledger every guard reads (KNIHA) to a ledger of its own "
    "outside data/results for the G1 command, so that its guards refuse its sealed archives as on the ledger of "
    "record, and it refuses a path under data/results and an open final run")
SEAL_IN_GIT_RULE = (
    "at stage final the ledger at HEAD must hold every sealed archive of the corpus before the run begins (seal_in_git "
    "true: the commit that holds the seal is the one pushed for its time stamp, TIMESTAMP_RULE); a run whose seal "
    "the ledger at HEAD does not hold, or for which that cannot be shown (the ledger outside the repository, git "
    "unavailable), is refused before anything is written; at stages generalka and suchy seal_in_git is recorded, not "
    "enforced (design B7c 5.2)")
UNREADABLE_RULE = (
    "an archive that cannot be read is not decided: its sha256 is unknown, so the ledger cannot be consulted; the "
    "replay reads it and fails as it did before the seal")
SNAPSHOT_RULE = (
    "the raw snapshots of a session enter a detector through kontrola_snimok (verification of B7c, F1): a snapshot "
    "directory belongs to the session whose session_id the session.json in it names, or else its restore marker "
    "restored_from.json names (a raw/ restored from an archive, RESTORED_RULE, the lead's answer to Q19), or else the "
    "session.json and then the restore marker of its parent (the session directory of its raw/); the ledger holds that "
    "session when it holds an archive of that session id, and then the archive's rule applies to the directory: "
    "refused outside the final run that consumed it (plan mode campaign), the rehearsal mark (plan mode rehearsal); a "
    "session.json or a restore marker without a session_id is refused by name, and a directory without a session.json "
    "or a restore marker in it or its parent names no session (NO_SESSION_RULE)")
NO_SESSION_RULE = (
    "a snapshot directory without a session.json or a restore marker in it or in its parent names no session, so the "
    "ledger cannot be consulted (the live capture of safeguard run, a lab test outside a campaign: no tool of the "
    "repository restored it from an archive, RESTORED_RULE): it is let through and the decision says so")
# The lead's answer to question Q19 (2026-11-24; finding N1 of the B7c confirmation, package B10). RESTORED is the name
# scripts/collection_archive.py RESTORED gives the marker (tcn/ imports nothing of scripts/collection_archive.py, which
# imports scripts/collection.py; tcn/tests/test_pecat.py checks that the two names are one). Not in RULES:
# SNAPSHOT_RULE, which the ledger keeps, states the guard's reading of the marker (finding F3 of the B10
# verification), and this text goes into the decision on a restored directory.
RESTORED = "restored_from.json"
RESTORED_RULE = (
    "a raw/ restored from the archive of a session (scripts/collection_archive.py restore_raw, the lead's answer to "
    "question Q19) holds the marker restored_from.json naming the session of the archive's session.json; the guard "
    "reads it as it reads a session.json, in the directory and then in its parent, after the session.json of the "
    "same directory: a marker without a session_id is refused by name, and the snapshots of a sealed session restored "
    "from its archive are refused like those of the session itself")
NO_ARCHIVE_RULE = (
    "a window set whose sessions name no feature archive (built from arrays: synthetic data, the tests) holds no sealed "
    "archive, and kontrola_okien binds none of its sessions (SEALED_RULE binds the session a window set names for an "
    "archive it holds); a window set of tcn.metody.Okna.from_sessions names the archive of every session "
    "(features_sha256 of its index record)")
COMMIT_DIRTY_RULE = (
    "commit_dirty of the ledger's header and of its created block: whether the working tree differs from the commit "
    "(git status --porcelain: a changed, staged or untracked path), the ledger itself and its temporary files aside, "
    "since their change is the one the write records (as the records of data/results of tcn/eval.py and "
    "scripts/validate_safeguard.py record commit_dirty); null when git is unavailable (verification of B7c, F5)")
RULES = {"identity": IDENTITY_RULE, "sealed": SEALED_RULE, "guard": GUARD_RULE, "rehearsal": REHEARSAL_RULE,
         "run": RUN_RULE, "timestamp": TIMESTAMP_RULE, "stage": STAGE_RULE, "seal_in_git": SEAL_IN_GIT_RULE,
         "snapshots": SNAPSHOT_RULE, "commit_dirty": COMMIT_DIRTY_RULE, "content": CONTENT_RULE}
# Package B9b, agent Z (finding N2 of the confirmation of B7c, dokazy/B7/odlozene_B7c.md). Written into the records
# that take their stage by it (record_stage), not into the ledger: RULES is what the ledger keeps.
RECORD_STAGE_RULE = (
    "the stage of a record of the data of a plan (proposal 11.1; finding N2 of the confirmation of B7c, package B9b): "
    "STAGE_RULE tightened by the sessions the record covers (tcn/pecat.py record_stage): final (plan mode campaign) or "
    "generalka (plan mode rehearsal) only when the ledger is the ledger of record, the record covers at least one "
    "session of the sealed roles, the ledger holds the archive (features_sha256) of every such session for that "
    "session, role and plan mode, and, for final, the ledger at HEAD holds every one of those archives as well "
    "(TIMESTAMP_RULE: seal_in_git true); otherwise suchy, and the basis names the first condition that failed; so a "
    "synthetic corpus whose archives the ledger of record does not hold is recorded suchy, never final (the risk of "
    "question Q15); the records of tcn.eval of protocol schema 3 (far, udalosti) take their stage by it over the "
    "sessions of their corpus index, the ending record of a campaign (scripts/campaign.py) over its accepted sessions; "
    "the ending record does not ask the ledger at HEAD (at_head false, question Q21, accepted by the lead 2026-11-24): "
    "the runner writes it before the ledger is committed, so it is final when the ledger of record in the working tree "
    "holds every accepted session of the sealed roles, its basis names that ledger's sha256, and tcn.finalne checks "
    "the ledger at HEAD (seal_in_git) when it reads the record")
HEAD_BY_FINALNE = ("not asked (question Q21): the ledger at HEAD is checked by tcn.finalne (seal_in_git) when it reads "
                   "the record")
NOTE = ("Kniha pečatí testovacích rolí protokolu v5 (balík B7c); nie je to meranie. guest je null: kniha neopisuje "
        "hosťa, iba archívy príznakov a finálne behy.")


class Zapecatene(ValueError):
    """A sealed archive refused outside the final run that consumed its seal (GUARD_RULE), or a final run refused
    (RUN_RULE)."""


# The final run of this process (spotrebuj), or None.
_OPEN = None
# The parsed ledgers by path: (stat signature, document); kontrola reads a ledger at every guarded call.
_CACHE = {}

# ------------------------------------------------------------------ helpers


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _git(*args):
    """The output of a git command in the repository, or None when git is unavailable or the command fails."""
    try:
        done = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _commit():
    out = _git("rev-parse", "HEAD")
    return out.strip() if out else None


def _commit_dirty(path):
    """COMMIT_DIRTY_RULE: whether the tree differs from the commit outside the ledger at `path` (resolved) and its
    temporary files; None when git is unavailable."""
    out = _git("status", "--porcelain")
    if out is None:
        return None
    try:
        own = path.relative_to(ROOT).as_posix()
        temporary = (path.parent.relative_to(ROOT) / f".{path.name}.").as_posix()
    except ValueError:
        own = temporary = None
    for line in out.splitlines():
        for name in line[3:].split(" -> "):
            name = name.strip('"')
            if own is None or (name != own and not name.startswith(temporary)):
                return True
    return False


def _ledger_path(ledger):
    """The ledger of a call: KNIHA when None (the ledger of this process: ZAZNAM, the tracked file, unless vlastna_kniha
    switched it), else the path given (a G1 dry run, the tests)."""
    return Path(KNIHA if ledger is None else ledger).resolve()


def _stage(path, mode):
    """STAGE_RULE: the stage of a run of plan mode `mode` on the resolved ledger `path`."""
    return STAGE[mode] if path == Path(ZAZNAM).resolve() else DRY_STAGE


def stage(mode, *, ledger=None):
    """The stage of a run or a record of plan mode `mode` (STAGE_RULE, proposal 11.1) on the ledger `ledger`, or on the
    ledger of this process (KNIHA) when None: final (campaign) or generalka (rehearsal) on the ledger of record, suchy
    on any other; a plan mode that is none is refused by name. The public form of the rule for the records of
    tcn.eval (verification of B7c, F4)."""
    if mode not in MODES:
        raise ValueError(f"plan mode {mode!r}: a stage is that of a plan mode, {' or '.join(MODES)}")
    return _stage(_ledger_path(ledger), mode)


def _sealed_sessions(sessions):
    """[(session id, role, features_sha256 or None)] of the sessions of the sealed roles among `sessions`
    (record_stage); None where the session names no sha256 of its archive."""
    if type(sessions) not in (list, tuple):
        raise ValueError("the sessions of a record are a list (index records, or the rows of a campaign's record)")
    out = []
    for item in sessions:
        ident = (item["id"] if "id" in item else item.get("session")) if type(item) is dict else None
        role = item.get("role") if type(item) is dict else None
        if type(ident) is not str or not ident or type(role) is not str or not role:
            raise ValueError("a session of a record names its id (id, or session in the row of a campaign's record) "
                             "and its role")
        if role in SEALED_ROLES:
            sha = item.get("features_sha256")
            out.append((ident, role, sha if _is_sha(sha) else None))
    return out


def record_stage(mode, sessions, *, ledger=None, at_head=True):
    """The stage of a record of plan mode `mode` that covers `sessions` (RECORD_STAGE_RULE, proposal 11.1; finding N2
    of the confirmation of B7c): {"stage": final, generalka or suchy, "basis": {...}}.

    sessions: the sessions whose data the record holds, each with its session id (id, as features/dataset.py names
    it in an index, or session, as in a row of a campaign's ending record), its role and, for a session of a sealed
    role, the sha256 of its feature archive (features_sha256); only those of SEALED_ROLES are checked. ledger: the
    ledger to consult, KNIHA (the ledger of this process) when None. final (campaign) or generalka (rehearsal) only
    when that ledger is the ledger of record (ZAZNAM), at least one session is of a sealed role, the ledger holds the
    archive of each of them for its session, role and plan mode, and for final when the ledger at HEAD holds every
    one of those archives (_in_git true); suchy otherwise, also when a session of a sealed role names no sha256 of its
    archive (its seal cannot be shown).

    basis: {rule, ledger, of_record, mode, sealed (the count of the sessions of the sealed roles), missing (the ids
    whose archive the ledger does not hold for that session, role and mode, or that name no sha256; null when not
    asked), seal_in_git (true, false, or null: not asked, or not shown because the ledger lies outside the repository
    or git is unavailable), why (null at final or generalka)}. A plan mode that is none and a session without its id or
    role are refused by name (ValueError).

    at_head False (the ending record of a campaign, scripts/campaign.py ENDING_RULE; question Q21, accepted by the
    lead 2026-11-24): the ledger at HEAD is not asked, since the runner writes the record before the
    ledger is committed; a record of plan mode campaign is then final when the ledger of record in the working tree
    holds every session of the sealed roles, and the basis adds at_head false, ledger_sha256 (the bytes of that ledger)
    and head (tcn.finalne checks the ledger at HEAD, seal_in_git, when it reads the record). The records of tcn.eval
    keep at_head True, the whole rule of N2."""
    if mode not in MODES:
        raise ValueError(f"plan mode {mode!r}: a stage is that of a plan mode, {' or '.join(MODES)}")
    sealed = _sealed_sessions(sessions)
    path, record = _ledger_path(ledger), Path(ZAZNAM).resolve()
    basis = {"rule": RECORD_STAGE_RULE, "ledger": str(path), "of_record": path == record, "mode": mode,
             "sealed": len(sealed), "missing": None, "seal_in_git": None, "why": None}

    def dry(why, **found):
        return {"stage": DRY_STAGE, "basis": dict(basis, **found, why=why)}
    if path != record:
        return dry(f"the ledger {path} is not the ledger of record {record} (a G1 dry run or a test)")
    if not sealed:
        return dry(f"the record covers no session of the sealed roles {', '.join(SEALED_ROLES)}: the ledger of "
                   "record cannot tie it to the seal of a plan")
    unnamed = [ident for ident, _, sha in sealed if sha is None]
    if unnamed:
        return dry(f"{len(unnamed)} of the {len(sealed)} sessions of the sealed roles name no sha256 of their feature "
                   f"archive (first {unnamed[0]}): their seal cannot be shown", missing=unnamed)
    doc = _read(path, missing_ok=True)
    archives = doc["values"]["archives"] if doc is not None else {}
    missing = [ident for ident, role, sha in sealed
               if not (type(archives.get(sha)) is dict and (archives[sha].get("session"), archives[sha].get("role"),
                                                              archives[sha].get("mode")) == (ident, role, mode))]
    if missing:
        return dry(f"the ledger of record holds no archive of {len(missing)} of the {len(sealed)} sessions of the "
                   f"sealed roles for their session, role and plan mode {mode} (first {missing[0]}): their seal is "
                   "not the campaign's", missing=missing)
    basis["missing"] = []
    if not at_head:  # Q21: the ending record of a campaign; the ledger at HEAD is tcn.finalne's to check.
        basis.update(at_head=False, ledger_sha256=_digest(path) if path.is_file() else None, head=HEAD_BY_FINALNE)
        return {"stage": STAGE[mode], "basis": basis}
    if mode == "campaign":
        seal_in_git = _in_git(path, [sha for _, _, sha in sealed])
        basis["seal_in_git"] = seal_in_git
        if seal_in_git is not True:
            return dry(f"the ledger {path} as committed at HEAD does not hold every archive of the sessions of the "
                       "sealed roles" if seal_in_git is False else
                       f"whether the ledger at HEAD holds them cannot be shown (the ledger {path} lies outside the "
                       f"repository {ROOT}, or git is unavailable)")
    return {"stage": STAGE[mode], "basis": basis}


def _run_mark(stage, mode):
    """The mark {stage, rehearsal, mark} of a run of `stage` and plan mode `mode`, and of a decision of kontrola on its
    ledger (STAGE_RULE)."""
    return {"stage": stage, "rehearsal": mode == "rehearsal", "mark": MARKS[stage]}


@contextmanager
def vlastna_kniha(path):
    """The ledger of a G1 dry run (STAGE_RULE, design B7c 5.1): inside the block KNIHA, the ledger every guard reads
    and every call without ledger= uses, is `path`, so that a sealed archive of that ledger is refused outside the run
    that consumed it, as on the ledger of record, and a final run on it has stage suchy. The ledger must exist for the
    guards (zaloz or zapis creates it). Refused by name before anything changes: a path under data/results, where the
    ledger of record is kept (a dry run never writes the results), and an open final run (its guards read the ledger
    it consumed). KNIHA is restored on exit."""
    global KNIHA
    target, results = Path(path).resolve(), RESULTS.resolve()
    if target == results or results in target.parents or target == Path(ZAZNAM).resolve():
        raise ValueError(f"{target}: a ledger of its own lies outside {results}, where the ledger of record is kept "
                         "(tcn/pecat.py STAGE_RULE)")
    if _OPEN is not None:
        raise ValueError(f"a final run is open in this process (seal {_OPEN.identity}, run {_OPEN.number}): the ledger "
                         "its guards read is not switched under it (tcn/pecat.py STAGE_RULE)")
    before = KNIHA
    KNIHA = target
    try:
        yield target
    finally:
        KNIHA = before


def plan_name(protocol, mode):
    """The name of the plan of `protocol` in `mode` (scripts/protocol_v5.py: the rehearsal's own name in rehearsal
    mode, name + rehearsal.name_suffix); refuses another schema or mode by name."""
    if type(protocol) is not dict or protocol.get("schema") != PROTOCOL_SCHEMA:
        found = protocol.get("schema") if type(protocol) is dict else None
        raise ValueError(f"the seal is that of protocol v5 (protocol schema {PROTOCOL_SCHEMA}), not of {found!r}: a "
                         "corpus of schema 1 or 2 keeps tcn.eval --final")
    if mode not in MODES:
        raise ValueError(f"plan mode {mode!r}: a seal names the plan mode of its corpus, {' or '.join(MODES)}")
    name = protocol.get("name")
    if mode == "rehearsal":
        suffix = (protocol.get("rehearsal") or {}).get("name_suffix")
        if type(name) is not str or type(suffix) is not str:
            raise ValueError("the protocol names no plan of mode rehearsal (name and rehearsal.name_suffix)")
        return name + suffix
    if type(name) is not str or not name:
        raise ValueError("the protocol names no plan (name)")
    return name


def identita(hashes):
    """The identity of the seal of these archives (IDENTITY_RULE): sha256 of the sorted lines of their sha256."""
    hashes = list(hashes)
    if not hashes or not all(map(_is_sha, hashes)) or len(set(hashes)) != len(hashes):
        raise ValueError("a seal is the identity of distinct sha256 hex digests of feature archives, at least one")
    return hashlib.sha256("".join(h + "\n" for h in sorted(hashes)).encode("ascii")).hexdigest()


# ------------------------------------------------------------------ the ledger


def _empty(command, path):
    return {"schema": SCHEMA, "commit": None, "commit_dirty": None, "date": None, "host": None, "guest": None,
            "command": command, "n": 0,
            "values": {"rules": RULES, "roles": list(SEALED_ROLES),
                       "created": {"date": _now(), "commit": _commit(), "commit_dirty": _commit_dirty(path),
                                   "command": command},
                       "archives": {}, "runs": []},
            "note": NOTE}


def _check(doc, path):
    """The ledger's shape (schema 2: every archive with its content fingerprint, a sha256 or null; question Q31)."""
    values = doc.get("values") if type(doc) is dict else None
    if (type(doc) is not dict or doc.get("schema") != SCHEMA or type(values) is not dict
            or type(values.get("archives")) is not dict or type(values.get("runs")) is not list
            or not all(_is_sha(h) and type(e) is dict and "content_sha256" in e
                       and (e["content_sha256"] is None or _is_sha(e["content_sha256"]))
                       for h, e in values["archives"].items())
            or not all(type(run) is dict and type(run.get("archives")) is list for run in values["runs"])):
        raise ValueError(f"the ledger {path} is no seal ledger of schema {SCHEMA}")
    return doc


def _read(path, *, missing_ok=False):
    """The ledger at `path` (checked; the cached document, never to be changed: a writer takes _for_write); None when
    it does not exist and missing_ok, else ValueError by name."""
    try:
        status = path.stat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise ValueError(f"the ledger {path} is missing: it is a tracked file of the repository (git checkout "
                         f"{TRACKED}); without it no archive can be told sealed or not") from None
    signature = (status.st_mtime_ns, status.st_size, status.st_ino)
    cached = _CACHE.get(str(path))
    if cached is not None and cached[0] == signature:
        return cached[1]
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"the ledger {path} cannot be read: {error}") from None
    _check(doc, path)
    _CACHE[str(path)] = (signature, doc)
    return doc


def _for_write(path, command, *, missing_ok):
    """A copy of the ledger to change under the lock (a new ledger when it does not exist and missing_ok)."""
    doc = _read(path, missing_ok=missing_ok)
    return _empty(command, path) if doc is None else copy.deepcopy(doc)


@contextmanager
def _locked(path):
    """An exclusive lock of the ledger's directory for one read-modify-write (two campaign runners, one per VM, may
    write at once); the ledger itself is replaced atomically, so readers need no lock."""
    if not path.parent.is_dir():
        raise ValueError(f"the directory of the ledger {path} does not exist")
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _write(path, doc, command):
    """Write the ledger with the provenance of this write (check E of scripts/check_claims.sh)."""
    doc.update(commit=_commit(), commit_dirty=_commit_dirty(path), date=_now(), host=socket.gethostname(), guest=None,
               command=command, n=len(doc["values"]["archives"]), note=NOTE)
    doc["values"]["rules"] = RULES
    text = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with open(temporary, "x", encoding="utf-8") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    _CACHE.pop(str(path), None)


def _held(archives, plan, mode, record):
    """The archives the ledger holds for the plan, mode, role and session of `record` (SEALED_RULE), sorted."""
    key = (plan, mode, record["role"], record["id"])
    return sorted(sha for sha, entry in archives.items()
                  if (entry.get("plan"), entry.get("mode"), entry.get("role"), entry.get("session")) == key)


def _entry_problem(entry, record, plan, mode):
    """Why the ledger's entry of an archive differs from the session a caller names for it (None when it does not)."""
    if (entry.get("role"), entry.get("session"), entry.get("plan"), entry.get("mode")) != (
            record["role"], record["id"], plan, mode):
        return (f"the ledger seals this archive for session {entry.get('session')} of role {entry.get('role')}, plan "
                f"{entry.get('plan')} ({entry.get('mode')}), not for session {record['id']} of role {record['role']}, "
                f"plan {plan} ({mode})")
    return None


def _sealed_records(records, base=None):
    """The records of the sealed roles, each with the resolved path of its archive; the archive's bytes must give its
    features_sha256 (the ledger keys on the bytes)."""
    if type(records) not in (list, tuple):
        raise ValueError("the records of a seal are a list of index records")
    out, seen = [], set()
    for record in records:
        if type(record) is not dict or record.get("role") not in SEALED_ROLES:
            continue
        ident, features, sha = record.get("id"), record.get("features"), record.get("features_sha256")
        if type(ident) is not str or not ident or type(features) is not str or not _is_sha(sha):
            raise ValueError(f"a record of the sealed role {record['role']} names its session (id), its feature "
                             "archive (features) and the archive's sha256 (features_sha256)")
        path = Path(features)
        if not path.is_absolute() and base is not None:
            path = base / path
        try:
            found = _digest(path)
        except OSError as error:
            raise ValueError(f"the feature archive of session {ident} cannot be read: {error}") from None
        if found != sha:
            raise ValueError(f"the feature archive of session {ident} changed since its record: {path} has sha256 "
                             f"{found}, the record {sha}")
        if sha in seen:
            raise ValueError(f"two sessions of the sealed roles name one feature archive ({sha})")
        seen.add(sha)
        out.append(dict(record, features=str(path.resolve())))
    return out


# ------------------------------------------------------------- the content of an archive (the lead's answer to Q31)

# What reading the arrays of a file that is no feature archive raises (numpy.load and its members, allow_pickle off).
_UNREADABLE = (OSError, ValueError, KeyError, EOFError, zipfile.BadZipFile, zlib.error)


def _fingerprint(arrays):
    """CONTENT_RULE over a mapping of the arrays of a feature archive: (sha256, None) or (None, why)."""
    import numpy as np
    digest = hashlib.sha256()
    for name in CONTENT_FIELDS:
        if name not in arrays:
            return None, f"it lacks the field {name} of features/archive.py save (CONTENT_RULE)"
        value = np.asarray(arrays[name])
        if value.dtype.hasobject:
            return None, f"its field {name} holds Python objects, not the array features/archive.py save writes"
        if value.dtype.byteorder == ">":
            value = value.astype(value.dtype.newbyteorder("<"))
        value = np.ascontiguousarray(value)
        digest.update(f"{name} {value.dtype.str} {','.join(str(n) for n in value.shape)}\n".encode("ascii"))
        digest.update(value.tobytes())
    return digest.hexdigest(), None


def odtlacok(archive):
    """The content fingerprint of a feature archive (CONTENT_RULE): `archive` is the path of the archive or the mapping
    of its arrays (numpy.load of it, features/archive.py load). (sha256 hex digest, None), or (None, why) when its
    arrays cannot be read (a file that is no feature archive) or it lacks a field of CONTENT_FIELDS; never raises for
    an unreadable file, since the other bindings of SEALED_RULE still decide."""
    if not isinstance(archive, (str, os.PathLike)):
        try:
            return _fingerprint(archive)
        except _UNREADABLE as error:
            return None, f"its arrays cannot be read ({type(error).__name__}: {error})"
    import numpy as np
    try:
        data = np.load(archive, allow_pickle=False)
    except _UNREADABLE as error:
        return None, f"its arrays cannot be read ({type(error).__name__}: {error})"
    if not hasattr(data, "files"):  # One array (.npy), not the named arrays of an archive.
        return None, "it holds one array, not the named arrays of a feature archive (features/archive.py save)"
    with data:
        try:
            return _fingerprint(data)
        except _UNREADABLE as error:
            return None, f"its arrays cannot be read ({type(error).__name__}: {error})"


def zaloz(*, command, ledger=None):
    """Create an empty ledger (the tracked one once, a G1 dry run's own); refused when the file exists."""
    path = _ledger_path(ledger)
    with _locked(path):
        if path.exists():
            raise ValueError(f"the ledger {path} exists: a ledger is created once")
        _write(path, _empty(command, path), command)
    return {"ledger": str(path), "created": True}


def zapis(records, *, protocol, protocol_sha256, mode, command, ledger=None):
    """Write the archives of the sessions of the sealed roles among `records` into the ledger (SEALED_RULE).

    records: index records (features/dataset.py build), or for one accepted session of a campaign (package B9) a
    record with at least id, role, group, scenario, features and features_sha256 (vm when the plan has VMs); records
    of other roles are not sealed and are counted apart. protocol, protocol_sha256 and mode: the plan of the
    campaign (protocol schema 3, mode campaign or rehearsal, no default). An archive already in the ledger for the same
    session, role, plan and mode is kept as it is; for another one it is refused by name. In plan mode campaign a
    second archive with other bytes for a plan, mode, role and session the ledger holds is refused (SEALED_RULE: the
    seal binds the session); a rehearsal keeps it beside the first. Every archive it writes carries its content
    fingerprint (content_sha256, CONTENT_RULE; null with the reason in content_why for a file whose arrays cannot be
    read). A ledger that does not exist yet is created. Returns {ledger, plan, mode, written, already, not_sealed}."""
    plan = plan_name(protocol, mode)
    if not _is_sha(protocol_sha256):
        raise ValueError("protocol_sha256 is the sha256 of the protocol file of the plan")
    if type(command) is not str or not command:
        raise ValueError("a write of the ledger names the command that made it")
    sealed = _sealed_records(records)
    not_sealed = {}
    for record in records:
        if type(record) is dict and record.get("role") not in SEALED_ROLES:
            not_sealed[str(record.get("role"))] = not_sealed.get(str(record.get("role")), 0) + 1
    path = _ledger_path(ledger)
    written, already = [], []
    with _locked(path):
        doc = _for_write(path, command, missing_ok=True)
        archives = doc["values"]["archives"]
        for record in sealed:
            sha = record["features_sha256"]
            entry = archives.get(sha)
            if entry is not None:
                problem = _entry_problem(entry, record, plan, mode)
                if problem is not None:
                    raise Zapecatene(f"{record['features']}: {problem}")
                already.append(sha)
                continue
            held = _held(archives, plan, mode, record)
            if held and mode == "campaign":
                raise Zapecatene(
                    f"{record['features']}: the ledger seals session {record['id']} of role {record['role']}, plan "
                    f"{plan} (campaign) by the archive {held[0]}; a second archive with other bytes of a sealed "
                    "session (a re-extraction) is refused: the seal binds the session, not only the bytes of its "
                    "archive (SEALED_RULE)")
            content, why = odtlacok(record["features"])
            archives[sha] = {"role": record["role"], "session": record["id"], "group": record.get("group"),
                             "vm": record.get("vm"), "scenario": record.get("scenario"), "plan": plan, "mode": mode,
                             "protocol_sha256": protocol_sha256, "features": record["features"],
                             "content_sha256": content, "content_why": why,
                             "written": {"date": _now(), "commit": _commit(), "command": command},
                             **({"beside": held} if held else {})}
            written.append(sha)
        if written or not path.exists():
            _write(path, doc, command)
    return {"ledger": str(path), "plan": plan, "mode": mode, "written": sorted(written), "already": sorted(already),
            "not_sealed": not_sealed}


def _corpus(index):
    """(path, document, protocol, mode, plan, sealed records) of a corpus index (features/dataset.py)."""
    path = Path(index).resolve()
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"the corpus index {path} cannot be read: {error}") from None
    if type(doc) is not dict or doc.get("schema") != INDEX_SCHEMA or type(doc.get("sessions")) is not list:
        raise ValueError(f"{path}: no corpus index of schema {INDEX_SCHEMA} (features/dataset.py build)")
    protocol, mode = doc.get("protocol_config"), doc.get("plan_mode")
    plan = plan_name(protocol, mode)
    sealed = _sealed_records(doc["sessions"], path.parent)
    if not sealed:
        raise ValueError(f"{path}: the index holds no session of the sealed roles {', '.join(SEALED_ROLES)}")
    return path, doc, protocol, mode, plan, sealed


def zapis_korpus(index, *, command, ledger=None):
    """zapis of the sessions of the sealed roles of a corpus index, under its protocol and plan mode."""
    path, doc, protocol, mode, _, _ = _corpus(index)
    out = zapis(doc["sessions"], protocol=protocol, protocol_sha256=doc.get("protocol_sha256"), mode=mode,
                command=command, ledger=ledger)
    return dict(out, corpus=str(path))


# ------------------------------------------------------------------ the check before a replay or a scoring


def _decision(purpose, path, archive, sha, allowed, *, ledger, mark=None, identity=None, sealed=None, rule, checked=(),
              bound=()):
    """A decision of the seal; checked holds what kontrola bound each archive by (_item) and bound the ledger's
    archives it found bound (SEALED_RULE): each {archive, session, mode, by}, by the bindings of BINDINGS that hold."""
    return {"schema": DECISION_SCHEMA, "purpose": purpose, "archive": archive, "sha256": sha, "ledger": str(path),
            "sealed": sealed, "allowed": allowed, "stage": None if mark is None else mark["stage"],
            "rehearsal": bool(mark and mark["rehearsal"]), "mark": None if mark is None else mark["mark"],
            "identity": identity, "rule": rule, "checked": list(checked), "bound": list(bound)}


def _consumed(doc, sha):
    """The end of a refusal: the final run that consumed the seal of the ledger's archive `sha`, if one did."""
    runs = [run for run in doc["values"]["runs"] if sha in run["archives"]]
    return (f"; its seal was consumed by the final run opened {runs[0].get('opened', {}).get('date')} (out "
            f"{runs[0].get('out')})" if runs else "")


def _refusal(purpose, what, sha, entry, doc, path):
    consumed = _consumed(doc, sha)
    return Zapecatene(
        f"{purpose}: refused, {what} is sealed (sha256 {sha}; session {entry.get('session')} of role "
        f"{entry.get('role')}, plan {entry.get('plan')}, ledger {path}): a sealed archive of a campaign is replayed or "
        f"scored only by the final command (python -m tcn.finalne) in the run that consumes its seal "
        f"(tcn/pecat.py GUARD_RULE){consumed}")


def _bound_refusal(purpose, what, item, key, how, entry, doc, path):
    """The refusal of an archive that SEALED_RULE binds to the ledger's archive `key` of a campaign by its session or
    its content (`how`), not by its bytes: it names the session, the binding and the archive the ledger holds."""
    session = entry.get("session")
    sealed = f"session {session} of role {entry.get('role')}, plan {entry.get('plan')}, ledger {path}"
    if how == "session":
        named_by = next(s["named_by"] for s in item["sessions"] if s["session"] == session)
        because = (f"is sealed by its session (sha256 {item['sha256']}; {named_by} names session {session}, which the "
                   f"ledger seals by the archive {key}: {sealed}): the seal binds the session, whatever the bytes of "
                   "its archive (tcn/pecat.py SEALED_RULE)")
    else:
        because = (f"is sealed by its content (sha256 {item['sha256']}; its content fingerprint "
                   f"{item['content_sha256']} is that of the archive {key}, which the ledger seals for {sealed}): the "
                   "seal binds the content, whatever the bytes of its archive (tcn/pecat.py SEALED_RULE, CONTENT_RULE)")
    return Zapecatene(f"{purpose}: refused, {what} {because}; a sealed archive of a campaign is replayed or scored "
                      "only by the final command (python -m tcn.finalne) in the run that consumes its seal "
                      f"(tcn/pecat.py GUARD_RULE){_consumed(doc, key)}")


def _item(sha, *, path=None, named=None, content_why=None):
    """What kontrola binds one archive by (SEALED_RULE): {sha256, sessions, session_why, content_sha256, content_why}.
    sessions: [{session, named_by}], the session the directory of its path names (named_by: the session.json or the
    restore marker that names it, read as SNAPSHOT_RULE reads a directory) and the one a window set names for it
    (named_by: the window set); session_why: why the directory names none. content_sha256: its fingerprint from its
    path (CONTENT_RULE), else None and content_why says why. Neither a directory that names no session nor a file
    whose arrays cannot be read is refused here: the other bindings decide."""
    item = {"sha256": sha, "sessions": [], "session_why": None, "content_sha256": None, "content_why": content_why}
    if path is not None:
        directory = Path(path).resolve().parent
        meta, ident, problem = _session_meta(directory)
        if ident is not None:
            item["sessions"].append({"session": ident, "named_by": str(meta)})
        else:
            item["session_why"] = problem or (f"neither {directory} nor its parent holds a session.json or a restore "
                                              "marker")
        item["content_sha256"], item["content_why"] = odtlacok(path)
    if type(named) is str and named:
        item["sessions"].append({"session": named, "named_by": "the window set"})
    return item


def _bound(archives, item):
    """{key: bindings} of the ledger's archives that SEALED_RULE binds `item` (_item) to, the bindings in the order of
    BINDINGS: bytes (the key is its sha256), session (the archive's session is one named for it), content (the
    archive's content fingerprint is its own)."""
    names = {s["session"] for s in item["sessions"]}
    content = item["content_sha256"]
    out = {}
    for key, entry in archives.items():
        how = [name for name, holds in (("bytes", key == item["sha256"]), ("session", entry.get("session") in names),
                                        ("content", content is not None and entry.get("content_sha256") == content))
               if holds]
        if how:
            out[key] = how
    return out


def _decide(items, *, purpose, path, what, archive, single):
    """The decision of kontrola over the archives `items` (_item) on the resolved ledger `path` (GUARD_RULE): an archive
    bound to an archive of plan mode campaign that is not one of the open final run's is refused (by the first binding
    of BINDINGS that holds); one that is an archive of the open run or bound to one is final_run; one bound only to
    archives of a rehearsal is rehearsal; one bound to none is not_sealed."""
    doc = _read(path)
    archives = doc["values"]["archives"]
    run, allowed, marks, sealed, found = _OPEN, [], [], False, {}
    for item in items:
        bound = _bound(archives, item)
        for key, how in bound.items():
            found.setdefault(key, set()).update(how)
        outside = [key for key in sorted(bound) if archives[key].get("mode") == "campaign"
                   and (run is None or key not in run.archives)]
        if outside:
            how = next(name for name in BINDINGS if any(name in bound[key] for key in outside))
            key = next(key for key in outside if how in bound[key])
            if how == "bytes":
                raise _refusal(purpose, what, key, archives[key], doc, path)
            raise _bound_refusal(purpose, what, item, key, how, archives[key], doc, path)
        if run is not None and (item["sha256"] in run.archives or any(key in run.archives for key in bound)):
            allowed.append("final_run")
            marks.append(run.mark)
            sealed = True
        elif bound:  # Bound to archives of a rehearsal only (REHEARSAL_RULE: let through with its mark).
            allowed.append("rehearsal")
            marks.append(_run_mark(_stage(path, "rehearsal"), "rehearsal"))
            sealed = True
        else:
            allowed.append("not_sealed")
    reasons = sorted(set(allowed))
    mark = next((m for m in marks if m["rehearsal"]), marks[0] if marks else None)
    rules = {"not_sealed": SEALED_RULE, "rehearsal": REHEARSAL_RULE, "final_run": GUARD_RULE}
    return _decision(purpose, path, archive, items[0]["sha256"] if single else sorted({i["sha256"] for i in items}),
                     reasons[0] if len(reasons) == 1 else reasons, ledger=path, mark=mark,
                     identity=None if run is None or "final_run" not in reasons else run.identity, sealed=sealed,
                     rule=" | ".join(rules[r] for r in reasons), checked=items,
                     bound=[{"archive": key, "session": archives[key].get("session"),
                             "mode": archives[key].get("mode"), "by": [name for name in BINDINGS if name in how]}
                            for key, how in sorted(found.items())])


def kontrola(archive=None, *, sha256=None, purpose, ledger=None, what=None, sessions=None, paths=None):
    """The check before a replay or a scoring (GUARD_RULE): give the path of one feature archive (archive) or the
    sha256 of the archives (sha256: one or a list) a caller is about to replay or score; purpose names the entry point
    in a refusal, and what what is read when only sha256 is given (default: an archive of the window set). With
    sha256 a caller gives what else it holds of each archive (the lead's answer to Q31), in lists as long as the list
    of sha256 (one item for one sha256), None where it holds nothing: sessions, the session id it names for the
    archive (a window set), and paths, the path of the archive, whose directory and content then bind it too. So an
    archive is bound to the ledger by its bytes, its session and its content (SEALED_RULE): one given by its path by
    all three, one given by its sha256 alone by its bytes. Returns the decision {schema, purpose, archive, sha256,
    ledger, sealed, allowed, stage, rehearsal, mark, identity, rule, checked, bound}: allowed is not_sealed
    (SEALED_RULE), rehearsal (REHEARSAL_RULE: the mark of the stage of this ledger, STAGE_RULE), final_run (an archive
    of the final run of this process or bound to one: the run's stage and mark) or unreadable (UNREADABLE_RULE); for a
    list the distinct values, sorted. Raises Zapecatene for a sealed archive of a campaign outside the final run that
    consumed it, naming its session and the binding, ValueError when the ledger is missing or malformed."""
    if type(purpose) is not str or not purpose:
        raise ValueError("kontrola names the entry point that asks (purpose)")
    if (archive is None) == (sha256 is None):
        raise ValueError("kontrola takes the path of one archive or the sha256 of the archives, exactly one")
    path = _ledger_path(ledger)
    if archive is not None:
        if sessions is not None or paths is not None:
            raise ValueError("kontrola takes sessions and paths with the sha256 of the archives, not with a path")
        try:
            sha = _digest(archive)
        except OSError:
            return _decision(purpose, path, str(archive), None, "unreadable", ledger=path, rule=UNREADABLE_RULE)
        return _decide([_item(sha, path=archive)], purpose=purpose, path=path, what=f"the archive {archive}",
                       archive=str(archive), single=True)
    hashes = [sha256] if type(sha256) is str else list(sha256)
    if not hashes or not all(map(_is_sha, hashes)):
        raise ValueError("sha256 is the sha256 hex digest of a feature archive, or a non-empty list of them")
    sessions = [None] * len(hashes) if sessions is None else list(sessions)
    paths = [None] * len(hashes) if paths is None else [None if p is None else str(p) for p in paths]
    if (len(sessions) != len(hashes) or len(paths) != len(hashes)
            or not all(s is None or type(s) is str and s for s in sessions) or not all(p is None or p for p in paths)):
        raise ValueError("sessions and paths are lists as long as the list of sha256, each item a session id or a path "
                         "of the archive, or None")
    given = sorted(set(zip(hashes, sessions, paths)), key=lambda one: (one[0], one[1] or "", one[2] or ""))
    return _decide([_item(h, named=s, path=p, content_why=NO_PATH) for h, s, p in given], purpose=purpose, path=path,
                   what="an archive of the window set" if what is None else what, archive=None,
                   single=type(sha256) is str)


def _window_archives(windows):
    """[(sha256, session id or None, path or None)] of the archives the sessions of a window set name ([] when it names
    none, NO_ARCHIVE_RULE): a window set of tcn.metody.Okna names the sha256 of each (Okna.archives) and its session
    (Okna.session_ids), not its path or its content; the index records of safeguard.training.Windows (its sessions
    (record, frames, ...)) name the sha256 (features_sha256), the session (id) and the path (features) of each."""
    archives = getattr(windows, "archives", None)
    if archives is not None:
        names = list(getattr(windows, "session_ids", None) or ())
        return [(sha, names[s] if s < len(names) and type(names[s]) is str and names[s] else None, None)
                for s, sha in enumerate(archives) if sha is not None]
    sessions = getattr(windows, "sessions", None)
    if type(sessions) is not list:
        return []
    records = [s[0] for s in sessions
               if type(s) is tuple and s and type(s[0]) is dict and _is_sha(s[0].get("features_sha256"))]
    return [(r["features_sha256"], r["id"] if type(r.get("id")) is str and r["id"] else None,
             r["features"] if type(r.get("features")) is str and r["features"] else None) for r in records]


def kontrola_okien(windows, purpose, *, ledger=None):
    """kontrola of the archives that the sessions of a window set name, before a method scores it (the hook of
    tcn/metody.py and tcn/opisne.py): each by its bytes, by the session the set names for it and, where the set's
    index records name its path (safeguard.training.Windows), by the session of its directory and its content
    (SEALED_RULE); None when the set names no archive (NO_ARCHIVE_RULE)."""
    found = _window_archives(windows)
    if not found:
        return None
    hashes, sessions, paths = (list(column) for column in zip(*found))
    return kontrola(sha256=hashes, sessions=sessions, paths=paths, purpose=purpose, ledger=ledger)


def _session_meta(directory):
    """(meta, session id, problem) of a directory (SNAPSHOT_RULE, RESTORED_RULE): meta is the first that exists of the
    session.json in it, its restore marker, the session.json and the restore marker of its parent; (None, None, None)
    when none exists; problem names a meta that cannot be read or names no session_id (whose session id is None)."""
    for meta in (directory / "session.json", directory / RESTORED, directory.parent / "session.json",
                 directory.parent / RESTORED):
        if meta.is_file():
            try:
                doc = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                return meta, None, f"{meta} cannot be read ({error})"
            ident = doc.get("session_id") if type(doc) is dict else None
            if type(ident) is not str or not ident:
                return meta, None, f"{meta} names no session_id"
            return meta, ident, None
    return None, None, None


def _session_of(directory):
    """(the session.json or the restore marker, the session id) of a snapshot directory (SNAPSHOT_RULE, RESTORED_RULE):
    the session.json in it, else its restore marker, else the same in its parent; (None, None) when none exists;
    ValueError by name for one that cannot be read or names no session_id."""
    meta, ident, problem = _session_meta(directory)
    if problem is not None:
        raise ValueError(f"{problem}: the session of the snapshot directory {directory} cannot be told (tcn/pecat.py "
                         "SNAPSHOT_RULE)")
    return meta, ident


def kontrola_snimok(directory, *, purpose, ledger=None):
    """The check before the raw snapshots of a session enter a detector (SNAPSHOT_RULE, GUARD_RULE): `directory` is the
    snapshot directory (its raw/ or the session directory), purpose names the entry point in a refusal. The decision
    of kontrola for the archives the ledger holds of the session its session.json names (or the restore marker of a
    raw/ restored from an archive, RESTORED_RULE), with the directory, the session.json, the marker and the session:
    allowed not_sealed when the ledger holds none, no_session when neither names one (NO_SESSION_RULE). Raises
    Zapecatene for the snapshots of a session the ledger seals for a campaign outside the final run that consumed its
    archive."""
    if type(purpose) is not str or not purpose:
        raise ValueError("kontrola_snimok names the entry point that asks (purpose)")
    directory, path = Path(directory).resolve(), _ledger_path(ledger)
    meta, ident = _session_of(directory)
    restored = meta is not None and meta.name == RESTORED
    where = {"directory": str(directory), "session_json": None if meta is None or restored else str(meta),
             "restored_from": str(meta) if restored else None, "session": ident}
    snapshot_rule = SNAPSHOT_RULE + (" | " + RESTORED_RULE if restored else "")
    if ident is None:
        return dict(_decision(purpose, path, None, None, "no_session", ledger=path, rule=NO_SESSION_RULE), **where)
    held = sorted(sha for sha, entry in _read(path)["values"]["archives"].items() if entry.get("session") == ident)
    if not held:
        return dict(_decision(purpose, path, None, [], "not_sealed", ledger=path, sealed=False,
                              rule=snapshot_rule + " | " + SEALED_RULE), **where)
    what = f"the snapshot directory {directory} of session {ident}" + (
        f", restored from an archive ({meta})" if restored else "")
    decision = kontrola(sha256=held, purpose=purpose, ledger=ledger, what=what)
    return dict(decision, rule=snapshot_rule + " | " + decision["rule"], **where)


# ------------------------------------------------------------------ the final run


def _in_git(path, hashes):
    """Whether the ledger at HEAD holds every archive of `hashes` (TIMESTAMP_RULE); None when the ledger lies outside
    the repository or git is unavailable."""
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return None
    if _commit() is None:
        return None
    shown = _git("show", f"HEAD:{relative.as_posix()}")
    if shown is None:
        return False
    try:
        archives = json.loads(shown)["values"]["archives"]
    except (ValueError, KeyError, TypeError):
        return False
    return all(h in archives for h in hashes)


class Beh:
    """The final run of this process (spotrebuj): its seal and its record.

    identity, mode, plan, stage (final or generalka on the ledger of record, suchy on another: STAGE_RULE),
    rehearsal, mark {stage, rehearsal, mark}, archives (the sha256
    of the sealed archives of the corpus), number (the ordinal of the runs of this seal; a campaign has run 1 only),
    ledger, corpus. record() is what the final command writes into its record; close(outcome, error) writes the end of
    the run into the ledger and closes it in this process. As a context manager the run closes on exit, completed or
    failed with the exception's text."""

    def __init__(self, ledger, entry):
        self.ledger, self.entry = ledger, entry
        self.identity, self.mode, self.plan = entry["identity"], entry["mode"], entry["plan"]
        self.stage, self.number, self.corpus = entry["stage"], entry["number"], entry["corpus"]
        self.rehearsal = self.mode == "rehearsal"
        self.mark = _run_mark(self.stage, self.mode)
        self.archives = frozenset(entry["archives"])
        self.closed = None

    def record(self):
        """The seal in the record of the final command: the run as the ledger holds it, the mark and the rules."""
        return {"schema": RUN_SCHEMA, "ledger": str(self.ledger), "mark": dict(self.mark), "rules": dict(RULES),
                **json.loads(json.dumps(self.entry)), "closed": self.closed}

    def close(self, outcome="completed", error=None):
        """Write the end of the run (outcome completed or failed, the error) into the ledger; the run is closed in this
        process whatever the write does."""
        global _OPEN
        if outcome not in ("completed", "failed"):
            raise ValueError("a final run closes completed or failed")
        if self.closed is not None:
            return self.closed
        self.closed = {"date": _now(), "outcome": outcome, "error": None if error is None else str(error)}
        try:
            with _locked(self.ledger):
                doc = _for_write(self.ledger, self.entry["command"], missing_ok=False)
                for run in doc["values"]["runs"]:
                    if (run.get("identity"), run.get("number"), run.get("opened")) == (
                            self.identity, self.number, self.entry["opened"]):
                        run["closed"] = self.closed
                        break
                else:
                    raise ValueError(f"the ledger {self.ledger} holds no open run {self.number} of seal "
                                     f"{self.identity}")
                _write(self.ledger, doc, self.entry["command"])
        finally:
            if _OPEN is self:
                _OPEN = None
        return self.closed

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if kind is None:
            self.close("completed")
        else:
            try:
                self.close("failed", f"{kind.__name__}: {value}")
            except (OSError, ValueError):
                pass  # The exception of the run is the one to report; the run is closed in this process anyway.
        return False


def otvoreny():
    """The open final run of this process (Beh), or None."""
    return _OPEN


def _runs_of(doc, hashes):
    return [run for run in doc["values"]["runs"] if set(run["archives"]) & set(hashes)]


def _run_sessions(run, archives):
    """The sessions (plan, session id) of a run: those it recorded and those of the ledger's entries of its archives."""
    found = {(item.get("plan"), item.get("session")) for item in run.get("sessions") or [] if type(item) is dict}
    return found | {(archives[sha].get("plan"), archives[sha].get("session")) for sha in run["archives"]
                    if sha in archives}


def _session_runs(doc, plan, sealed):
    """[(run, [(plan, session id) ...])] of the earlier runs of plan mode campaign that held a session of `sealed` under
    `plan` (RUN_RULE: the seal binds the sessions, verification of B7c, F8)."""
    mine, archives = {(plan, r["id"]) for r in sealed}, doc["values"]["archives"]
    found = [(run, sorted(_run_sessions(run, archives) & mine)) for run in doc["values"]["runs"]
             if run.get("mode") == "campaign"]
    return [(run, sessions) for run, sessions in found if sessions]


def stav(index, *, ledger=None):
    """The seal of a corpus index without consuming it: {corpus, ledger, identity, mode, plan, stage (of a run on this
    ledger, STAGE_RULE), sessions (of the sealed roles), roles, in_ledger, missing (sessions whose archive the ledger
    does not hold), mismatched (held for another session, plan or mode), runs (that held one of its archives or, in
    plan mode campaign, one of its sessions), consumed, seal_in_git (TIMESTAMP_RULE), ready (spotrebuj would consume it:
    RUN_RULE, and SEAL_IN_GIT_RULE at stage final), rules}."""
    path, doc, protocol, mode, plan, sealed = _corpus(index)
    ledger_path = _ledger_path(ledger)
    book = _read(ledger_path, missing_ok=mode == "rehearsal") or _empty("stav", ledger_path)
    hashes = [r["features_sha256"] for r in sealed]
    archives = book["values"]["archives"]
    missing = [r["id"] for r in sealed if r["features_sha256"] not in archives]
    mismatched = [r["id"] for r in sealed if r["features_sha256"] in archives
                  and _entry_problem(archives[r["features_sha256"]], r, plan, mode) is not None]
    runs = _runs_of(book, hashes)
    consumed = any(run.get("mode") == "campaign" for run in runs)
    again = [run for run, _ in _session_runs(book, plan, sealed)] if mode == "campaign" else []
    consumed = consumed or bool(again)
    runs += [run for run in again if run not in runs]
    roles = {role: sum(r["role"] == role for r in sealed) for role in SEALED_ROLES}
    stage, seal_in_git = _stage(ledger_path, mode), _in_git(ledger_path, hashes)
    ready = (not mismatched and (mode == "rehearsal" or (not missing and not consumed))
             and (stage != "final" or seal_in_git is True))
    return {"corpus": str(path), "ledger": str(ledger_path), "identity": identita(hashes), "mode": mode, "plan": plan,
            "stage": stage, "sessions": len(sealed), "roles": roles, "in_ledger": len(sealed) - len(missing),
            "missing": missing, "mismatched": mismatched,
            "runs": [{key: run.get(key) for key in ("identity", "number", "mode", "opened", "closed", "out")}
                     for run in runs], "consumed": consumed, "seal_in_git": seal_in_git, "ready": ready,
            "rules": dict(RULES)}


def spotrebuj(index, *, out, command, ledger=None):
    """Consume the seal of the corpus index `index` for the final run of this process (RUN_RULE) and open the run.

    out: the path of the final command's record; command: its command line. The checks come before the ledger is
    written: the index (a corpus index of protocol schema 3 with its plan mode and sessions of the sealed roles whose
    archives give their features_sha256), no final run open in this process, and in plan mode campaign every sealed
    archive in the ledger for its session, role and plan and none in an earlier run, nor any of its sessions with
    another archive in an earlier run of plan mode campaign (RUN_RULE: the seal binds the sessions). A rehearsal (plan
    mode rehearsal) writes the archives the ledger does not hold yet, each with its content fingerprint (CONTENT_RULE),
    and may run again (REHEARSAL_RULE). The stage of
    the run comes from the ledger (STAGE_RULE), and at stage final the ledger at HEAD must hold every sealed archive
    of the corpus (SEAL_IN_GIT_RULE). The run is written into the ledger before it opens. Returns the Beh; refusals
    are Zapecatene."""
    global _OPEN
    if _OPEN is not None:
        raise Zapecatene(f"a final run is open in this process (seal {_OPEN.identity}, run {_OPEN.number}): one run "
                         "at a time")
    if type(command) is not str or not command or out is None:
        raise ValueError("the final run names its command and the path of its record (out)")
    path, doc, protocol, mode, plan, sealed = _corpus(index)
    hashes = sorted(r["features_sha256"] for r in sealed)
    identity = identita(hashes)
    ledger_path = _ledger_path(ledger)
    stage, seal_in_git = _stage(ledger_path, mode), _in_git(ledger_path, hashes)
    dirty = _git("status", "--porcelain")
    with _locked(ledger_path):
        book = _for_write(ledger_path, command, missing_ok=mode == "rehearsal")
        archives = book["values"]["archives"]
        for record in sealed:
            entry = archives.get(record["features_sha256"])
            if entry is None:
                if mode == "campaign":
                    raise Zapecatene(
                        f"{path}: the archive of session {record['id']} (role {record['role']}, sha256 "
                        f"{record['features_sha256']}) is not in the ledger {ledger_path}: the campaign writes every "
                        "sealed session into it before the final run (tcn/pecat.py zapis), so this corpus has no seal "
                        "to consume (RUN_RULE)")
                content, why = odtlacok(record["features"])  # CONTENT_RULE, as zapis stores it.
                archives[record["features_sha256"]] = {
                    "role": record["role"], "session": record["id"], "group": record.get("group"),
                    "vm": record.get("vm"), "scenario": record.get("scenario"), "plan": plan, "mode": mode,
                    "protocol_sha256": doc.get("protocol_sha256"), "features": record["features"],
                    "content_sha256": content, "content_why": why,
                    "written": {"date": _now(), "commit": _commit(), "command": command,
                                "by": "the final run of a rehearsal (REHEARSAL_RULE: kept, not enforced)"}}
                continue
            problem = _entry_problem(entry, record, plan, mode)
            if problem is not None:
                raise Zapecatene(f"{path}: {record['features']}: {problem}")
        earlier = _runs_of(book, hashes)
        if mode == "campaign" and earlier:
            first = earlier[0]
            raise Zapecatene(
                f"{path}: a second final run is refused: the seal of its sealed archives was consumed by the final run "
                f"of seal {first.get('identity')} opened {first.get('opened', {}).get('date')} (corpus "
                f"{first.get('corpus')}, out {first.get('out')}); the identity is that of the archives, so a copy of "
                "the corpus under another path has the same seal (RUN_RULE)")
        again = _session_runs(book, plan, sealed) if mode == "campaign" else []
        if again:
            run, sessions = again[0]
            raise Zapecatene(
                f"{path}: a second final run is refused: session {sessions[0][1]} of plan {sessions[0][0]} was in the "
                f"final run of seal {run.get('identity')} opened {run.get('opened', {}).get('date')} (corpus "
                f"{run.get('corpus')}, out {run.get('out')}) with another archive; the seal binds the sessions, not "
                "only the bytes of their archives (RUN_RULE)")
        if stage == "final" and seal_in_git is not True:
            raise Zapecatene(
                f"{path}: a final run of stage final is refused: "
                + (f"the ledger {ledger_path} as committed at HEAD does not hold every sealed archive of the corpus"
                   if seal_in_git is False else
                   f"whether the ledger at HEAD holds the seal cannot be shown (the ledger {ledger_path} lies outside "
                   f"the repository {ROOT}, or git is unavailable)")
                + "; commit the ledger with the campaign's seal before the final run (SEAL_IN_GIT_RULE)")
        number = 1 + sum(run.get("identity") == identity for run in book["values"]["runs"])
        entry = {"identity": identity, "number": number, "mode": mode, "stage": stage, "plan": plan,
                 "archives": hashes, "roles": {role: sum(r["role"] == role for r in sealed) for role in SEALED_ROLES},
                 "sessions": [{"plan": plan, "role": r["role"], "session": r["id"]}
                              for r in sorted(sealed, key=lambda r: r["id"])],
                 "corpus": str(path), "corpus_sha256": _digest(path), "out": str(Path(out).resolve()),
                 "command": command, "seal_in_git": seal_in_git,
                 "opened": {"date": _now(), "commit": _commit(), "host": socket.gethostname(),
                            "dirty": None if dirty is None else [line[3:] for line in dirty.splitlines()]},
                 "closed": None}
        book["values"]["runs"].append(entry)
        _write(ledger_path, book, command)
    _OPEN = Beh(ledger_path, json.loads(json.dumps(entry)))
    return _OPEN


# ------------------------------------------------------------------ command line

AUDIT_SCHEMA = "hyptcn3/collection-audit/1"  # scripts/collection.py audit_session


def _zapis_auditu(audit, mode, *, command, ledger=None):
    """zapis --audit: the per-session form the campaign's runner calls as the campaign's owner right after the audit
    accepts a session of a sealed role (package B9a, design B9a 1.3 item 7; scripts/campaign.py SEAL_RULE).

    The record of zapis is read from the audit record and its session: id, role, group, vm and scenario from the
    session.json the audit names (its sha256 must be the audit's session_sha256), features and features_sha256 from
    the audit; the plan from the session's copy of the protocol (its sha256 must be the audit's protocol_sha256) in
    plan mode `mode`, which the session's plan_mode (scripts/collection.py run, package B9a) must equal where it
    records one. Only an accepted audit is written; every refusal names its reason. A session of a role that is not
    sealed is counted apart, as zapis counts it."""
    path = Path(audit).resolve()
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"the audit {path} cannot be read: {error}") from None
    values = doc.get("values") if type(doc) is dict else None
    if type(doc) is not dict or doc.get("schema") != AUDIT_SCHEMA or type(values) is not dict:
        raise ValueError(f"{path}: no session audit of schema {AUDIT_SCHEMA}")
    if values.get("accepted") is not True or values.get("reasons") != []:
        raise ValueError(f"{path}: the audit does not accept its session; only an accepted session is sealed")
    if type(values.get("session_dir")) is not str:
        raise ValueError(f"{path}: the audit names no session directory (session_dir)")
    directory = Path(values["session_dir"])
    try:
        session_sha, protocol_sha = _digest(directory / "session.json"), _digest(directory / "protocol.json")
        meta = json.loads((directory / "session.json").read_text(encoding="utf-8"))
        protocol = json.loads((directory / "protocol.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"{path}: the session's records cannot be read: {error}") from None
    if session_sha != values.get("session_sha256"):
        raise ValueError(f"{path}: session.json of {directory} changed since its audit")
    if protocol_sha != values.get("protocol_sha256"):
        raise ValueError(f"{path}: the session's protocol.json is not the protocol of its audit")
    if type(meta) is not dict or meta.get("role") != values.get("role"):
        raise ValueError(f"{path}: the audit's role is not the role of its session.json")
    if "plan_mode" in meta and meta["plan_mode"] != mode:
        raise ValueError(f"{path}: the session belongs to the plan of mode {meta['plan_mode']}, not {mode}")
    record = {"id": meta.get("session_id"), "role": meta.get("role"), "group": meta.get("group"), "vm": meta.get("vm"),
              "scenario": meta.get("scenario"), "features": values.get("features"),
              "features_sha256": values.get("features_sha256")}
    out = zapis([record], protocol=protocol, protocol_sha256=protocol_sha, mode=mode, command=command, ledger=ledger)
    return dict(out, audit=str(path), session=record["id"])


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m tcn.pecat", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="action", required=True)
    for name, text in (("zaloz", "create an empty ledger (refused when the file exists)"),
                       ("zapis", "write the sealed sessions of a corpus index, or one accepted session of a campaign "
                                 "(--audit), into the ledger"),
                       ("stav", "the seal of a corpus index: its identity, the ledger, its runs (consumes nothing)"),
                       ("kontrola", "the decision of the seal for one feature archive (exit 3 when refused)")):
        command = sub.add_parser(name, help=text)
        if name == "kontrola":
            command.add_argument("--archive", required=True, type=Path)
        elif name == "zapis":
            source = command.add_mutually_exclusive_group(required=True)
            source.add_argument("--corpus", type=Path)
            source.add_argument("--audit", type=Path,
                                help="the audit record of one accepted session (the campaign's runner, package B9a)")
            command.add_argument("--mode", choices=MODES,
                                 help="with --audit (required there, no default): the plan mode of the campaign; a "
                                      "corpus names its own")
        elif name != "zaloz":
            command.add_argument("--corpus", required=True, type=Path)
        command.add_argument("--ledger", type=Path, default=None,
                             help="another ledger than the ledger of record (a G1 dry run: stage suchy); default "
                                  "data/results/kniha_pecati.json")
    a = parser.parse_args(argv)
    if a.action == "zapis" and (a.audit is None) != (a.mode is None):
        parser.error("--mode belongs to --audit, and --audit needs it (no default): a corpus index names its plan mode")
    line = shlex.join(["python", "-m", "tcn.pecat", *argv])
    try:
        if a.action == "zaloz":
            result = zaloz(command=line, ledger=a.ledger)
        elif a.action == "zapis" and a.audit is not None:
            result = _zapis_auditu(a.audit, a.mode, command=line, ledger=a.ledger)
        elif a.action == "zapis":
            result = zapis_korpus(a.corpus, command=line, ledger=a.ledger)
        elif a.action == "stav":
            result = stav(a.corpus, ledger=a.ledger)
        else:
            result = kontrola(a.archive, purpose="python -m tcn.pecat kontrola", ledger=a.ledger)
    except Zapecatene as error:
        print(f"tcn.pecat: {error}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as error:
        print(f"tcn.pecat: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
