"""One case of the audit self-test (protocol v5, package B3): a bad session and the exact reasons the audit gives.

    id        unique name of the case
    check     the audit check it exercises: a row of proposal 6.2, or the existing reason or log-audit problem key
    expected  sorted list of the exact reasons collection.audit_session returns for the bad session (exit code 2),
              or a callable taking the protocol dict and returning that list
    mutate    mutate(d, p, result) changes the sealed clean session directory d and returns a changed copy of the
              extraction result, or None to keep it; a case that edits evidence listed in the logs manifest reseals
              it (test_collection_logs.seal) unless the manifest itself is what the case breaks
"""
from collections import namedtuple

Case = namedtuple("Case", "id check expected mutate")
