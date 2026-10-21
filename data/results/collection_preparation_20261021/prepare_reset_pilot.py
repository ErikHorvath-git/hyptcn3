#!/usr/bin/env python3
"""Archive and remove only the explicitly authorized preflight working copies."""
from pathlib import Path
import json
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path('/home/eh/projects/hyptcn3')
sys.path.insert(0, str(ROOT))
from scripts.collection import collection_lock
from scripts.collection_archive import (archive_session, digest, guard_mount,
    mount_identity, now, read_json, reclaim_raw, verify_archive, write_new)

ARCHIVE = Path('/home/eh/hyptcn3-archive')
OUTPUT = ROOT / 'data/results/collection_preflight_cleanup_20261021.json'
SOURCES = (
    ('data/collections/pilot_pool_20261020_bursty', 'pilot', 'pilots'),
    ('data/diagnostics/20261020_stop_validation', 'diagnostic', 'diagnostics'),
)


def space():
    return {name: shutil.disk_usage(path)._asdict() for name, path in (
        ('working', ROOT / 'data/collections'), ('archive', ARCHIVE))}


def main():
    if OUTPUT.exists():
        raise ValueError('immutable report already exists')
    mount = mount_identity(ARCHIVE, allow_system=True)
    guard = lambda: guard_mount(ARCHIVE, mount)
    before, rows = space(), []
    with collection_lock(ROOT / 'data/collections'):
        for relative, role, kind in SOURCES:
            source = ROOT / relative
            meta = read_json(source / 'session.json')
            if meta['role'] != role or (source / 'raw').is_symlink():
                raise ValueError('unexpected source role or already reclaimed source')
            if role == 'pilot' and read_json(source / 'superseded.json')['values']['usable_for_current_corpus'] is not False:
                raise ValueError('pilot has not been superseded')
            destination = ARCHIVE / kind / source.name
            audits = list(source.glob('audit_*.json'))
            audit = audits[0] if len(audits) == 1 else None
            print(json.dumps({'stage': 'archive', 'source': str(source)}), flush=True)
            start = time.monotonic()
            doc = archive_session(source, destination, guard, compress='zstd',
                                  audit=audit, reserve_bytes=30 * 2**30)
            verify_archive(destination, source)
            raw = {name: value for name, value in doc['files'].items() if name.startswith('raw/')}
            row = {'source': str(source), 'role': role, 'destination': str(destination),
                   'archive_manifest_sha256': digest(destination / 'archive-manifest.json'),
                   'verified': True, 'audit_bound': str(audit) if audit else None,
                   'raw_working_bytes_removed': sum(value['size'] for value in raw.values()),
                   'stored_archive_bytes': doc['stored_bytes'],
                   'elapsed_s_before_reclaim': time.monotonic() - start}
            # Direct maintenance is explicitly authorized by the user. The
            # campaign ownership guard and original session metadata stay intact.
            row['receipt'] = reclaim_raw(source, destination, doc, guard)
            rows.append(row)
            print(json.dumps({'stage': 'reclaimed', **row}), flush=True)
    result = {'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'date': now(), 'host': platform.platform(), 'guest': None,
              'command': 'python3 data/lab/prepare_reset_pilot_20261021.py', 'n': len(rows),
              'values': {'sessions': rows, 'space_before': before, 'space_after': space(),
                         'raw_working_bytes_removed': sum(row['raw_working_bytes_removed'] for row in rows),
                         'archive_mount': mount,
                         'note': 'Superseded pilot and controlled-stop trial only. Exact compressed evidence, reports and features retained; original admission verdicts unchanged. No corpus sessions removed.'}}
    write_new(OUTPUT, result)
    print(str(OUTPUT), flush=True)


if __name__ == '__main__':
    main()
