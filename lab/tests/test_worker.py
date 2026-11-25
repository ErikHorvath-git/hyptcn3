"""The queue worker survives a statement timeout instead of exiting into a systemd restart loop."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import signal
import sys
import threading
import types

import pytest

from scripts import collection_logs

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def services(monkeypatch):
    try:
        import psycopg2  # noqa: F401  The guest has it; the collection host does not.
    except ImportError:
        stub, errors, pool = (types.ModuleType(n) for n in ("psycopg2", "psycopg2.errors", "psycopg2.pool"))
        stub.Error = type("Error", (Exception,), {})
        stub.OperationalError = type("OperationalError", (stub.Error,), {})
        errors.QueryCanceled = type("QueryCanceled", (stub.OperationalError,), {})
        pool.ThreadedConnectionPool = object
        pool.PoolError = type("PoolError", (stub.Error,), {})  # psycopg2.pool: getconn of a full pool.
        stub.errors, stub.pool = errors, pool
        for module in (stub, errors, pool):
            monkeypatch.setitem(sys.modules, module.__name__, module)
    spec = importlib.util.spec_from_file_location("lab_services_under_test", ROOT / "lab/services.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}

    class Event(threading.Event):
        def wait(self, timeout=None):  # no pause between rounds in the test
            return self.is_set()
    monkeypatch.setattr(module.threading, "Event", Event)
    yield module
    for number, handler in handlers.items():
        signal.signal(number, handler)


def rounds(services, monkeypatch, outcomes):
    """Run worker() over scripted rounds: an exception to raise or the row count of a good round."""
    seen = []

    class Cursor:
        rowcount = 0

        def __init__(self, outcome):
            self.outcome, self.statements = outcome, 0

        def execute(self, sql):
            self.statements += 1
            if isinstance(self.outcome, Exception) and sql.startswith("UPDATE orders"):
                raise self.outcome
            if sql.startswith("UPDATE orders"):
                self.rowcount = self.outcome

    @contextmanager
    def database():
        cursor = Cursor(outcomes[len(seen)])
        seen.append(cursor)
        try:
            yield cursor
        finally:
            if len(seen) == len(outcomes):
                signal.raise_signal(signal.SIGTERM)  # the operator stops the unit after the last round
    monkeypatch.setattr(services, "database", database)
    services.worker()
    return seen


def test_statement_timeout_is_reported_and_the_next_round_runs(services, monkeypatch, capsys):
    import psycopg2
    timeout = psycopg2.errors.QueryCanceled("canceling statement due to statement timeout\n")
    seen = rounds(services, monkeypatch, [timeout, timeout, 2])
    lines = capsys.readouterr().out.splitlines()
    assert lines == [services.WORKER_ERROR + "canceling statement due to statement timeout"] * 2 + [
        json.dumps({"service": "worker", "completed": 2})]
    assert [c.statements for c in seen] == [1, 1, 3]  # a failed round stops at the locked table


def test_any_other_database_error_still_ends_the_worker(services, monkeypatch):
    import psycopg2
    with pytest.raises(psycopg2.OperationalError):
        rounds(services, monkeypatch, [psycopg2.OperationalError("server closed the connection"), 1])


def test_log_audit_knows_the_worker_error_line(services):
    assert services.WORKER_ERROR == collection_logs.WORKER_ERROR
    # The lock no longer restarts any unit, so the audit excuses none for it.
    assert "zamok_tabulky" not in collection_logs.EVENT_UNITS
