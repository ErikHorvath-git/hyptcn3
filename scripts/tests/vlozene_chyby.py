"""The nine injected errors of the G1 dry run (protocol v5, package B10, agent G; the lead's skeleton
dokazy/B10/kostra/KOSTRA.md section 4, the design dokazy/B10/navrh/NAVRH_B10.md decision 7 and its section G).

Proposal 10.2 (docs/NAVRH_PROTOKOL_V5.sk.md, the table of stage G1) names nine errors the dry run injects, each to be
refused with its expected reason: a boot in two roles, a missing events.json, one invalid row more, a missed slot, a
foreign VM identity, a second final evaluation, the replay of a sealed role, an event that did not run and a stale
guest hash. This module holds one function per error, with its expected reason as a constant beside it, and vsetky()
gives the nine in that order, so that the command of G1 only calls them. The command belongs to G1; none is here.

Each function takes a synthetic target that a harness built, injects its error and returns the exact reasons (a
sorted list) that the real step of the chain then gives. The step is named beside each error (Chyba.krok) and is a
thin call of the real code. There are three kinds of target:

  Session  a sealed session directory as a capture leaves it, before its audit. krok_audit: the real
           scripts/collection.py audit_session, with only collection.retazec (the feature extraction from guest RAM)
           returning the session's synthetic extraction result (scripts/tests/boundary_sessions.py audit), as in the
           audit self-test. Harness: the self-test's clean session (scripts/tests/audit_cases.py clean_session).
  Korpus   the accepted audits of the plan of a campaign, before its corpus. krok_korpus: features/dataset.py build, as
           scripts/campaign.py finish_corpus calls it. Harness: features/tests/test_dataset_plan.py make_corpus, and,
           for a session that keeps its logs, the self-test's clean session with its real audit.
  Pecat    a corpus index of plan mode campaign whose sealed sessions a ledger of its own holds, before or after the
           dry run's own final run. krok_finalne: the final command (tcn/finalne.py evaluate on that ledger, stage
           suchy); krok_prehratie: a replay (tcn.porovnanie replay). Harness: tcn/tests/test_finalne.py _corpus in mode
           campaign, with tcn.pecat zaloz and zapis_korpus as the campaign writes the seal.

The step of each error is the first one of the chain of proposal 10.2 that meets it (synthetic sessions, audit,
corpus, ..., the sealed final evaluation). The audit sees one session at a time, so a boot shared by two roles first
meets the corpus. A missing events.json also meets the corpus: removed before the audit, it takes with it every
admission of the event's window, and the log audit then names each of those problems as well. On the lab a start of a
group or a capture refuses some errors earlier (a boot that another session has, another QEMU process, guest files
that differ from lab/ in this commit). A dry run without VMs has neither, so the corpus or the audit refuses them.

Test tooling: scripts/tests is outside the measurement hash (scripts/collection.py is_measurement), and this file is
not a case file of the audit self-test (scripts/audit_selftest.py CASE_FILES), so neither the stage hash nor
cases_sha256 changes with it. Its numbers are choices of the tooling (which row, which frame, which process id), never
a measurement, and each says so where it is defined. scripts/tests/test_vlozene_chyby.py shows that the real code
refuses each injection with exactly its reason and admits the target without it. Only mechanics (HONESTY P4).
"""
from collections import namedtuple
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

# The sealed roles: those training never loads (proposal 10.8; tcn/pecat.py SEALED_ROLES).
SEALED = ("test_benign", "test_controls")
MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  (/\S+)")  # A sha256sum line of the guest's stack manifest.


@dataclass
class Session:
    """A sealed session directory as a capture leaves it, before its audit: directory, protocol_path (the protocol file
    the audit reads), protocol (that file, loaded) and result (the extraction result that stands in for
    collection.retazec; the injection of invalid rows changes it in place)."""
    directory: Path
    protocol_path: Path
    protocol: dict
    result: dict


@dataclass
class Korpus:
    """The accepted audits of the plan of a campaign, before its corpus: audits (the paths of the audit records, in the
    campaign's order), protocol (loaded), protocol_sha256 (of its file) and mode (the plan mode)."""
    audits: list
    protocol: dict
    protocol_sha256: str
    mode: str


@dataclass
class Pecat:
    """A corpus index of plan mode campaign whose sealed sessions a ledger of its own holds (tcn.pecat zapis_korpus):
    index, ledger (outside data/results: tcn.pecat vlastna_kniha refuses it there) and work (an existing directory for
    what a run would write: a refused run writes nothing there). The ledger may hold the dry run's own final run of the
    corpus already (druhe_finalne_vyhodnotenie)."""
    index: Path
    ledger: Path
    work: Path


# id: the function's name; chyba: the words of proposal 10.2; ciel: the target class it takes; vloz: the function
# (it injects the error and returns the exact expected reasons); krok: the real step that refuses it (it returns the
# reasons it gives, [] when it admits the target); dovody: the constants the expected reasons are taken from.
Chyba = namedtuple("Chyba", "id chyba ciel vloz krok dovody")


def _read(path):
    return json.loads(Path(path).read_text())


def _rewrite(path, doc):
    """Rewrite a JSON file of the target in the form of scripts/collection.py write_json (which never overwrites)."""
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _middle(protocol):
    """The snapshot in the middle of the first chain, a delta snapshot far from the full snapshots and the ends of the
    session (judgment of the tooling, as scripts/tests/audit_cases.py _middle)."""
    return protocol["full_every"] // 2


def _sidecar(directory, seq):
    """(path, document) of the collector sidecar of snapshot `seq` in raw/ of a session directory."""
    found = []
    for path in sorted((Path(directory) / "raw").glob("*.json")):
        doc = _read(path)
        if doc.get("schema") == "vmicollect/1" and doc.get("seq") == seq:
            found.append((path, doc))
    if len(found) != 1:
        raise ValueError(f"{directory}: {len(found)} collector sidecars of snapshot {seq} in raw/, not one")
    return found[0]


def _campaign(doc, ciel, name):
    """The index of a Pecat target is of plan mode campaign; else `name` refuses it by name."""
    if doc.get("plan_mode") != "campaign":
        raise ValueError(f"{name}: the corpus index {ciel.index} is of plan mode {doc.get('plan_mode')!r}; the seal of "
                         "a campaign is enforced, that of a rehearsal is kept (tcn/pecat.py REHEARSAL_RULE)")


def _first_sealed(doc):
    """The record of the first session of a sealed role in a corpus index, in the order of the index."""
    record = next((r for r in doc["sessions"] if r.get("role") in SEALED), None)
    if record is None:
        raise ValueError("the corpus index holds no session of the sealed roles " + ", ".join(SEALED))
    return record


# ------------------------------------------------------------------ 1. a boot in two roles

BOOT_V_DVOCH_ROLACH = "boot/group shared between dataset roles"  # features/dataset.py build


def boot_v_dvoch_rolach(ciel):
    """Korpus: a boot in two roles. The first audited session whose role differs from that of the first session
    records the first session's guest boot, as if its group had started without a new boot after a group of another
    role (proposal 5.4 asks a new boot for every group). Its session.json names that boot (guest_before.boot_id, what
    the corpus build compares). Its audit record names the changed file by its sha256 (values.session_sha256 and the
    log audit's metadata section), as an audit of that session.json records it. Otherwise the build would refuse the
    changed file first ("session metadata changed since audit"). The other records of a full session (end.json, the
    guest state in its logs) stay as they are: the build refuses the session before it reads them. A corpus of one
    role is refused by name."""
    audits = [Path(path) for path in ciel.audits]
    records = [_read(path) for path in audits]
    first = records[0]["values"]
    boot = _read(Path(first["session_dir"]) / "session.json")["guest_before"]["boot_id"]
    other = next((i for i, doc in enumerate(records) if doc["values"]["role"] != first["role"]), None)
    if other is None:
        raise ValueError(f"boot_v_dvoch_rolach: every audit of the corpus is of role {first['role']}; a boot in two "
                         "roles needs a session of another role")
    values = records[other]["values"]
    meta_path = Path(values["session_dir"]) / "session.json"
    meta = _read(meta_path)
    meta["guest_before"]["boot_id"] = boot
    _rewrite(meta_path, meta)
    digest = _sha256(meta_path)
    values["session_sha256"] = digest
    metadata = ((values.get("logs") or {}).get("sections") or {}).get("metadata")
    if type(metadata) is dict:
        metadata["session_sha256"] = digest
    _rewrite(audits[other], records[other])
    return [BOOT_V_DVOCH_ROLACH]


# ------------------------------------------------------------------ 2. a missing events.json

CHYBAJUCI_EVENTS_JSON = "protocol with events but session has no events.json: {session_dir}"  # features/dataset.py
# A session that keeps its logs: the build audits its logs again before it asks for events.json (features/quality.py
# require_log_audit), and that audit no longer equals the record.
CHYBAJUCI_EVENTS_JSON_LOGY = "log audit differs from the record"


def chybajuci_events_json(ciel):
    """Korpus: a missing events.json. The record of the events of the first audited session is gone after its audit.
    The corpus indexes that record with its sha256 for the evaluation of the events, and features/dataset.py build asks
    for it under a protocol that plans events or whose session.json lists them (an empty list too). Which refusal comes
    first depends on whether the build repeats the session's log audit (features/quality.py require_log_audit):
    - it repeats it when the session keeps its logs: session.json of schema /2, logs_manifest.json, and raw/ a
      directory (or a link to an archive that is attached). That audit no longer equals the record
      (CHYBAJUCI_EVENTS_JSON_LOGY);
    - else the build asks for events.json and names the session directory as its audit record gives it
      (CHYBAJUCI_EVENTS_JSON). The sessions of features/tests/test_dataset_plan.py keep no logs."""
    values = _read(ciel.audits[0])["values"]
    directory = Path(values["session_dir"])
    repeated = (_read(directory / "session.json").get("schema") == "hyptcn3/collection-session/2"
                and (directory / "logs_manifest.json").is_file() and (directory / "raw").is_dir())
    (directory / "events.json").unlink()
    return [CHYBAJUCI_EVENTS_JSON_LOGY if repeated else CHYBAJUCI_EVENTS_JSON.format(session_dir=directory)]


# ------------------------------------------------------------------ 3. one invalid row more

NEPLATNY_RIADOK_NAVYSE = "incomplete model inputs under {policy}"  # features/acceptance.py, the invalid_rows rule


def neplatne_riadky(ciel, pocet):
    """Session: `pocet` consecutive rows of the extraction result, from the middle of the first chain (_middle), are
    invalid only because the walk of the processes did not close. The invalid_rows rule of the protocol tolerates that
    cause up to its max (proposal 6.2). The rows are as the extraction leaves them (features/snapshot.py retazec): the
    row's quality says so and the row is not valid; the row after an invalid one has no predecessor (ma_predchodcu 0,
    and proc_new, proc_gone and mod_delta 0). A session that has an invalid row already is refused by name (the count
    is this function's), and so are rows that do not fit in the first chain. Returns the seq of the invalid rows."""
    result, protocol = ciel.result, ciel.protocol
    if not all(result["valid"]):
        raise ValueError("neplatne_riadky takes a session without an invalid row: the count of invalid rows is its own")
    start = _middle(protocol)
    if type(pocet) is not int or not 0 < pocet < protocol["full_every"] - start:
        raise ValueError(f"neplatne_riadky: {pocet!r} rows from {start} do not fit in the first chain")
    columns = [result["mena"].index(name) for name in ("ma_predchodcu", "proc_new", "proc_gone", "mod_delta")]
    rows = [result["seq"].index(seq) for seq in range(start, start + pocet)]
    for i in rows:
        result["quality"][i] = dict(result["quality"][i], model_valid=False, behavior_valid=False,
                                    traversals_complete=False, truncated_traversals=["processes"])
        result["valid"][i] = False
        if i + 1 < len(result["seq"]) and result["seq"][i + 1] == result["seq"][i] + 1:
            for column in columns:
                result["matica"][i + 1][column] = 0.
    return [result["seq"][i] for i in rows]


def neplatny_riadok_navyse(ciel):
    """Session: one invalid row more than the invalid_rows rule of the protocol tolerates, max + 1 rows of
    neplatne_riadky. Their cause is one the rule tolerates, so only their count is wrong. Consecutive rows are one
    burst (no periodicity), and they cost fewer windows than the isolated rows of the worst case the gate is set by
    (features/acceptance.py worst_invalid_rows), so the audit's verdict names the count alone. A protocol without the
    rule is refused by name."""
    rule = ciel.protocol.get("invalid_rows")
    if type(rule) is not dict or type(rule.get("max")) is not int:
        raise ValueError("neplatny_riadok_navyse: the protocol has no invalid_rows rule with a max")
    neplatne_riadky(ciel, rule["max"] + 1)
    return [NEPLATNY_RIADOK_NAVYSE.format(policy=ciel.protocol["quality_policy"])]


# ------------------------------------------------------------------ 4. a missed slot

ZMESKANY_SLOT = "read errors/fill/missed slots: {image}"  # scripts/collection.py audit_session


def zmeskany_slot(ciel):
    """Session: a missed slot. The collector missed the slot before the snapshot in the middle of the first chain
    (_middle) and records it in that snapshot's sidecar: sched.skipped_before 1, the count of the slots missed before
    it (vmicollect/src/sched.c). Only that record changes. A real missed slot also leaves a longer gap between the
    times and a count in the collector's log; their own checks refuse those (timestamp gap,
    logs: collector_errors_or_missed_slots), so this injection has one reason. The sidecars are not in the logs
    manifest."""
    path, side = _sidecar(ciel.directory, _middle(ciel.protocol))
    side["sched"]["skipped_before"] = 1
    _rewrite(path, side)
    return [ZMESKANY_SLOT.format(image=path.with_suffix(".vmicd").name)]


# ------------------------------------------------------------------ 5. a foreign VM identity

CUDZIA_IDENTITA_VM = "sidecar VM identity differs from session"  # scripts/collection.py audit_session


def cudzia_identita_vm(ciel):
    """Session: a foreign VM identity. The snapshot in the middle of the first chain (_middle) comes from the other VM
    of the protocol. Its sidecar names that VM's domain and another QEMU process (vm.vmid, the pid the eBPF backend
    writes) than session.json names (domain, host_context.qemu.pid). The pid is the session's plus 1: any other process
    is foreign (judgment of the tooling). A protocol without another VM is refused by name. The sidecars are not in the
    logs manifest."""
    meta = _read(Path(ciel.directory) / "session.json")
    others = [vm["domain"] for vm in ciel.protocol.get("vms") or [] if vm.get("domain") != meta.get("domain")]
    if not others:
        raise ValueError(f"cudzia_identita_vm: the protocol names no VM but {meta.get('domain')!r}")
    path, side = _sidecar(ciel.directory, _middle(ciel.protocol))
    side["vm"] = dict(side["vm"], domain=others[0], vmid=meta["host_context"]["qemu"]["pid"] + 1)
    _rewrite(path, side)
    return [CUDZIA_IDENTITA_VM]


# ------------------------------------------------------------------ 6. a second final evaluation

DRUHE_FINALNE_VYHODNOTENIE = (  # tcn/finalne.py seal_state, step 0 of the final command
    "{corpus}: the seal of the corpus cannot be consumed on the ledger {ledger} (its seal was consumed by the final "
    "run {number} of seal {identity} opened {opened} (out {out}): a second final run is refused); refused before "
    "anything is computed (tcn.pecat stav, RUN_RULE)")


def druhe_finalne_vyhodnotenie(ciel):
    """Pecat: a second final evaluation. The seal of the corpus on the target's ledger is consumed by a first final run,
    and the final command then runs again (krok_finalne); its step 0 refuses that run by name before anything is
    computed. The first run is the ledger's first run of this seal when it holds one: the dry run's own sealed final
    evaluation. Otherwise this function opens and closes it (tcn.pecat spotrebuj, closed completed: what the final
    command does around its sealed part). Its record is not written here, because a second run meets only the seal.
    The index must be of plan mode campaign (a rehearsal may run again, tcn/pecat.py REHEARSAL_RULE); else the target
    is refused by name. The expected reason names that first run: the seal's identity (IDENTITY_RULE: the sha256 of the
    sorted lines of the sealed archives' sha256, computed here from the index), and its number, date and out (1, the
    date and the out of this function's run, or those the ledger records for the dry run's)."""
    from tcn import pecat
    doc = _read(ciel.index)
    _campaign(doc, ciel, "druhe_finalne_vyhodnotenie")
    hashes = sorted(r["features_sha256"] for r in doc["sessions"] if r.get("role") in SEALED)
    identity = hashlib.sha256("".join(h + "\n" for h in hashes).encode()).hexdigest()
    earlier = [run for run in _read(ciel.ledger)["values"]["runs"] if run.get("identity") == identity]
    if earlier:
        number, opened, out = earlier[0]["number"], earlier[0]["opened"]["date"], earlier[0]["out"]
    else:
        out = (Path(ciel.work) / "prvy_beh.json").resolve()
        with pecat.spotrebuj(ciel.index, out=out, command="vlozene_chyby: the first final run of the dry run",
                             ledger=ciel.ledger) as run:
            number, opened = 1, run.entry["opened"]["date"]
    return [DRUHE_FINALNE_VYHODNOTENIE.format(corpus=Path(ciel.index).resolve(), ledger=Path(ciel.ledger).resolve(),
                                              number=number, identity=identity, opened=opened, out=out)]


# ------------------------------------------------------------------ 7. the replay of a sealed role

PREHRATIE_ZAPECATENEJ_ROLY = (  # tcn/pecat.py kontrola (GUARD_RULE), the first step of tcn.porovnanie replay
    "tcn.porovnanie replay: refused, the archive {archive} is sealed (sha256 {sha256}; session {session} of role "
    "{role}, plan {plan}, ledger {ledger}): a sealed archive of a campaign is replayed or scored only by the final "
    "command (python -m tcn.finalne) in the run that consumes its seal (tcn/pecat.py GUARD_RULE){consumed}")
# The end of that reason once a final run consumed the seal: the first run of the ledger that holds the archive.
PREHRATIE_PO_BEHU = "; its seal was consumed by the final run opened {opened} (out {out})"


def prehratie_zapecatenej_roly(ciel):
    """Pecat: the replay of a sealed role outside the final run. tcn.porovnanie replay (krok_prehratie) replays the
    archive of the first session of a sealed role in the index (_first_sealed). It asks the seal first, before it
    loads a model or writes anything. The index must be of plan mode campaign (the archives of a rehearsal are kept,
    not enforced: tcn/pecat.py REHEARSAL_RULE), and its ledger must hold that archive for its session; else the target
    is refused by name. Nothing changes: the error is the replay itself, and this function names it and its reason,
    with the end PREHRATIE_PO_BEHU when a final run on the ledger consumed the seal. The plan of a campaign is the
    name of its protocol (tcn/pecat.py plan_name)."""
    doc = _read(ciel.index)
    _campaign(doc, ciel, "prehratie_zapecatenej_roly")
    record = _first_sealed(doc)
    digest = _sha256(record["features"])  # What the seal hashes: the bytes of the archive.
    book = _read(ciel.ledger)["values"]
    if (book["archives"].get(digest) or {}).get("session") != record["id"]:
        raise ValueError(f"prehratie_zapecatenej_roly: the ledger {ciel.ledger} does not hold the archive of session "
                         f"{record['id']} (the campaign writes it, tcn/pecat.py zapis)")
    runs = [run for run in book["runs"] if digest in run["archives"]]
    consumed = "" if not runs else PREHRATIE_PO_BEHU.format(opened=(runs[0].get("opened") or {}).get("date"),
                                                            out=runs[0].get("out"))
    return [PREHRATIE_ZAPECATENEJ_ROLY.format(archive=record["features"], sha256=digest, session=record["id"],
                                              role=record["role"], plan=doc["protocol_config"]["name"],
                                              ledger=Path(ciel.ledger).resolve(), consumed=consumed)]


# ------------------------------------------------------------------ 8. an event that did not run

NEPREBEHNUTA_UDALOST = "logs: event_not_executed:{type}"  # scripts/collection_logs.py, the events of a session


def neprebehnuta_udalost(ciel):
    """Session: an event that did not run. The record of the first event that ran in events.json says executed false.
    The capture leaves that record for an event whose start failed or whose state was not restored
    (scripts/collection.py Events); the record's other fields stay. events.json is in the logs manifest, which is
    sealed again as the capture seals it at its end (scripts/tests/test_collection_logs.py seal), when the session has
    one. A session without an event that ran is refused by name."""
    path = Path(ciel.directory) / "events.json"
    doc = _read(path)
    event = next((e for e in doc.get("events") or [] if e.get("executed") is True), None)
    if event is None:
        raise ValueError(f"neprebehnuta_udalost: {path} holds no event that ran")
    event["executed"] = False
    _rewrite(path, doc)
    if (Path(ciel.directory) / "logs_manifest.json").is_file():
        from scripts.tests import test_collection_logs as evidence
        evidence.seal(Path(ciel.directory))
    return [NEPREBEHNUTA_UDALOST.format(type=event["type"])]


# ------------------------------------------------------------------ 9. a stale guest hash

ZASTARANY_HASH_HOSTA = "deployed guest files differ from lab/"  # scripts/collection.py audit_session, guest_mismatch


def zastarany_hash_hosta(ciel):
    """Session: a stale guest hash. The guest runs an older deployment of the first file its manifest hashes. That line
    of guest_before.stack_manifest (session.json) and of guest_after.stack_manifest (end.json, since the guest is the
    same before and after the capture) carries another sha256 than lab/ of this commit (session.json lab_sha256). The
    digest is that of a text naming an older deployment, any other digest (judgment of the tooling). session.json and
    end.json are not in the logs manifest. A manifest without a sha256sum line is refused by name."""
    directory = Path(ciel.directory)
    for name, key in (("session.json", "guest_before"), ("end.json", "guest_after")):
        doc = _read(directory / name)
        manifest = doc[key]["stack_manifest"]
        index = next((i for i, line in enumerate(manifest) if MANIFEST_LINE.fullmatch(line)), None)
        if index is None:
            raise ValueError(f"zastarany_hash_hosta: {name} {key}.stack_manifest hashes no deployed file")
        guest_path = MANIFEST_LINE.fullmatch(manifest[index])[2]
        stale = hashlib.sha256(f"an older deployment of {guest_path}".encode()).hexdigest()
        manifest[index] = stale + "  " + guest_path
        _rewrite(directory / name, doc)
    return [ZASTARANY_HASH_HOSTA]


# ------------------------------------------------------------------ the steps of the chain that refuse them

def krok_audit(ciel, output=None):
    """The audit of a Session: the real scripts/collection.py audit_session, with collection.retazec returning
    ciel.result during the call only (scripts/tests/boundary_sessions.py audit). The record goes to `output`, by
    default <session>/audit.json, and an existing one is never overwritten. Returns the audit's reasons (sorted; []
    when it accepted the session)."""
    from scripts.tests import boundary_sessions as bs
    audit = bs.audit(bs.Session(Path(ciel.directory), Path(ciel.protocol_path), ciel.result), ciel.protocol,
                     output=output, result=ciel.result)
    reasons = list(audit.values["reasons"])
    if (audit.code, bool(reasons)) not in ((0, False), (2, True)):
        raise AssertionError(f"the audit of {ciel.directory} exited {audit.code} with the reasons {reasons}")
    return reasons


def krok_korpus(ciel):
    """The corpus of a Korpus: features/dataset.py build of its audits under its protocol and plan mode, as
    scripts/campaign.py finish_corpus calls it. The completeness and the production check that finish_corpus adds after
    the build are not this step. Returns the build's refusal (the message of its ValueError; [] when it indexed every
    session)."""
    from features import dataset
    try:
        dataset.build([Path(path) for path in ciel.audits], ciel.protocol, ciel.protocol_sha256, mode=ciel.mode)
    except ValueError as error:
        return [str(error)]
    return []


def krok_finalne(ciel):
    """The final command on a Pecat: tcn/finalne.py evaluate of its index on its ledger (stage suchy: tcn.pecat
    vlastna_kniha). The bundles, the record of the campaign, the replays and the record are names under ciel.work that a
    run refused at step 0 never reads or writes. Returns the command's refusal ([its message], as python -m tcn.finalne
    prints it after "tcn.finalne: "; [] when the run wrote its record)."""
    from tcn import finalne
    work = Path(ciel.work)
    try:
        finalne.evaluate(ciel.index, [work / "bez-modelu"], campaign=work / "bez-zaznamu-kampane.json",
                         replays=work / "prehratia", out=work / "druhy_beh.json", ledger=ciel.ledger)
    except (OSError, ValueError, KeyError) as error:  # What the command refuses with (tcn/finalne.py _hlavny).
        return [str(error)]
    return []


def krok_prehratie(ciel):
    """A replay on a Pecat: tcn.porovnanie replay of the archive of prehratie_zapecatenej_roly (the first session of a
    sealed role in the index). The target's ledger is the ledger of this process for the call (tcn.pecat vlastna_kniha,
    as the dry run reads it), and the model and the output are names under ciel.work that a refused replay never reads
    or writes. Returns the refusal of the seal ([its message]; [] when the replay ran)."""
    from tcn import pecat, porovnanie
    record = _first_sealed(_read(ciel.index))
    work = Path(ciel.work)
    with pecat.vlastna_kniha(ciel.ledger):
        try:
            porovnanie.replay(work / "bez-modelu", record["features"], work / "prehratie")
        except pecat.Zapecatene as error:
            return [str(error)]
    return []


def vsetky():
    """The nine errors of proposal 10.2 in its order, each a Chyba (id, chyba, ciel, vloz, krok, dovody)."""
    return (
        Chyba("boot_v_dvoch_rolach", "boot v dvoch rolách", Korpus, boot_v_dvoch_rolach, krok_korpus,
              (BOOT_V_DVOCH_ROLACH,)),
        Chyba("chybajuci_events_json", "chýbajúci events.json", Korpus, chybajuci_events_json, krok_korpus,
              (CHYBAJUCI_EVENTS_JSON, CHYBAJUCI_EVENTS_JSON_LOGY)),
        Chyba("neplatny_riadok_navyse", "o jeden neplatný riadok viac", Session, neplatny_riadok_navyse, krok_audit,
              (NEPLATNY_RIADOK_NAVYSE,)),
        Chyba("zmeskany_slot", "zmeškaný slot", Session, zmeskany_slot, krok_audit, (ZMESKANY_SLOT,)),
        Chyba("cudzia_identita_vm", "cudzia identita VM", Session, cudzia_identita_vm, krok_audit,
              (CUDZIA_IDENTITA_VM,)),
        Chyba("druhe_finalne_vyhodnotenie", "druhé finálne vyhodnotenie", Pecat, druhe_finalne_vyhodnotenie,
              krok_finalne, (DRUHE_FINALNE_VYHODNOTENIE,)),
        Chyba("prehratie_zapecatenej_roly", "prehratie zapečatenej roly", Pecat, prehratie_zapecatenej_roly,
              krok_prehratie, (PREHRATIE_ZAPECATENEJ_ROLY, PREHRATIE_PO_BEHU)),
        Chyba("neprebehnuta_udalost", "neprebehnutá udalosť", Session, neprebehnuta_udalost, krok_audit,
              (NEPREBEHNUTA_UDALOST,)),
        Chyba("zastarany_hash_hosta", "zastaraný hash hosťa", Session, zastarany_hash_hosta, krok_audit,
              (ZASTARANY_HASH_HOSTA,)),
    )
