#!/usr/bin/env python3
"""Explicitly authorized maintenance of this project's old diagnostics only.

Uses the existing verified archive/reclamation primitives; does not change
capture provenance, source code, or admission verdicts. No live measurement.
"""
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path('/home/eh/projects/hyptcn3')
sys.path.insert(0, str(ROOT))
from scripts.collection import collection_lock, protocol
from scripts.collection_archive import (archive_session, digest, guard_mount,
    mount_identity, now, read_json, reclaim_raw, restore_raw, verify_archive, write_new)

ARCHIVE = Path('/home/eh/hyptcn3-archive')
OUT = ROOT / 'data/results/collection_storage_20261020.json'
VALIDATION = ROOT / 'data/lab/archive_roundtrip_20261020'
NAMES = [
    '20261020T170034679155Z_diagnostic_bursty',
    '20261020T142021156420Z_diagnostic_write_heavy',
    '20261020T145629855838Z_diagnostic_bursty',
    '20261020T161708770565Z_diagnostic_bursty',
    '20261020T173655582088Z_diagnostic_steady',
]


def emit(**fields):
    print(json.dumps({'date': now(), **fields}), flush=True)


def space():
    return {name: shutil.disk_usage(path)._asdict() for name, path in
            [('working', ROOT / 'data/collections'), ('archive', ARCHIVE)]}


def roundtrip(source, destination):
    """Restore all bytes; re-extract the original first 40 contiguous rows."""
    import numpy as np
    from features.archive import load, save
    from features.snapshot import retazec
    if VALIDATION.exists():
        raise ValueError('roundtrip target already exists')
    VALIDATION.mkdir()
    restored = VALIDATION / 'restored'
    restored.mkdir()
    result = restore_raw(destination, restored / 'raw', reserve_bytes=30 * 2**30)
    shutil.copyfile(source / 'session.json', restored / 'session.json')
    # Immutable metadata next to raw/ supplies the original guest boot context.
    subset = VALIDATION / 'subset'
    (subset / 'raw').mkdir(parents=True)
    shutil.copyfile(source / 'session.json', subset / 'session.json')
    # A later full snapshot still stores predecessor-dependent diagnostic
    # columns. Taking it out of the original timeline would change that
    # context, even though live scoring excludes the full row. Preserve the
    # exact original context by testing the first contiguous range instead.
    selected = list(range(40))
    for path in sorted((restored / 'raw').glob('*.json')):
        side = read_json(path)
        if side.get('schema') == 'vmicollect/1' and side['seq'] in selected:
            for member in (path, path.with_suffix('.vmicd')):
                os.link(member, subset / 'raw' / member.name)
    original = load(source / 'audit_20261020T181902833877Z.npz')
    computed = retazec(str(subset / 'raw'), str(destination / 'profile'),
                      quality_policy='behavioral-inputs-v1')
    feature = save(VALIDATION / 'reextracted.npz', computed)
    actual = load(feature)
    indices = np.array([list(original['seq']).index(seq) for seq in selected])
    checked = []
    row_keys = ('matica', 'seq', 'casy', 'valid', 'perbin', 'chain_ids', 'snimky', 'poznamky')
    fixed_keys = ('schema', 'mena', 'biny', 'quality_policy', 'layout_json', 'max_medzera_s')
    for key in row_keys + fixed_keys:
        wanted = original[key][indices] if key in row_keys else original[key]
        if not np.array_equal(actual[key], wanted, equal_nan=False):
            raise ValueError('restored feature mismatch: ' + key)
        checked.append(key)
    old_quality = json.loads(str(original['quality_json']))
    if json.loads(str(actual['quality_json'])) != [old_quality[int(i)] for i in indices]:
        raise ValueError('restored quality mismatch')
    checked.append('quality_json')
    doc = {**result, 'verified': True, 'reextracted_rows': len(selected),
           'reextracted_seq': selected, 'compared_fields': checked,
           'feature_archive': str(feature), 'feature_sha256': digest(feature),
           'original_feature_sha256': digest(source / 'audit_20261020T181902833877Z.npz'),
           'note': 'All raw members restored and hashed. First 40/400 real rows re-extracted with their complete original context; timings intentionally excluded from equality. No new capture or admission.'}
    write_new(VALIDATION / 'result.json', doc)
    # Only the newly created, verified roundtrip working copies are disposable.
    shutil.rmtree(subset)
    shutil.rmtree(restored)
    return doc


def main():
    if OUT.exists():
        raise ValueError('immutable output already exists')
    ARCHIVE.mkdir(exist_ok=True)
    mount = mount_identity(ARCHIVE, allow_system=True)
    guard = lambda: guard_mount(ARCHIVE, mount)
    p = protocol(ROOT / 'config/collection-v2.json')
    before = space()
    rows = []
    validation = None
    with collection_lock(ROOT / 'data/collections'):
        for index, name in enumerate(NAMES):
            source = ROOT / 'data/diagnostics' / name
            meta = read_json(source / 'session.json')
            if source.parent != ROOT / 'data/diagnostics' or meta['role'] != 'diagnostic':
                raise ValueError('out-of-scope source')
            if (source / 'raw').is_symlink():
                raise ValueError('already reclaimed source requires explicit inspection')
            destination = ARCHIVE / 'diagnostics' / name
            emit(stage='archive_start', source=str(source))
            started = time.monotonic()
            audits = list(source.glob('audit*.json'))
            bound = audits[0] if len(audits) == 1 else None
            doc = archive_session(source, destination, guard, compress='zstd',
                                  audit=bound, reserve_bytes=p['min_free_gib'] * 2**30)
            verify_archive(destination, source)
            if index == 0:
                emit(stage='restore_and_reextract', source=str(source))
                validation = roundtrip(source, destination)
            raw_members = {n: v for n, v in doc['files'].items() if n.startswith('raw/')}
            images = {n: v for n, v in raw_members.items() if n.endswith('.vmicd')}
            raw_bytes = sum(v['size'] for v in images.values())
            raw_stored = sum(v.get('stored_size', v['size']) for v in images.values())
            row = {'session': name, 'scenario': meta['scenario'], 'assigned_cycles': meta['cycles'],
                   'observed_frames': len(images), 'source': str(source), 'destination': str(destination),
                   'archive_manifest_sha256': digest(destination / 'archive-manifest.json'),
                   'source_bytes': doc['bytes'], 'stored_bytes': doc['stored_bytes'],
                   'raw_bytes': raw_bytes, 'raw_stored_bytes': raw_stored,
                   'reclaimed_bytes': sum(v['size'] for v in raw_members.values()),
                   'verified': True, 'audit_bound': str(bound) if bound else None,
                   'elapsed_s_before_reclaim': time.monotonic() - started}
            # User explicitly authorized reclaiming unnecessary working copies.
            # The automated campaign guard is unchanged; historical metadata is
            # never relabelled to impersonate a campaign-owned session.
            receipt = reclaim_raw(source, destination, doc, guard)
            row['receipt'] = receipt
            rows.append(row)
            write_new(VALIDATION / (name + '.json'), row)
            emit(stage='archived_and_reclaimed', **{k: row[k] for k in
                 ('session', 'raw_bytes', 'raw_stored_bytes', 'reclaimed_bytes', 'stored_bytes')})
        complete = [r for r in rows if r['observed_frames'] == r['assigned_cycles']]
        worst = max(complete, key=lambda r: r['stored_bytes'] / r['observed_frames'])
        hourly = worst['stored_bytes'] * p['cycles'] / worst['observed_frames']
        max_raw = max(r['raw_bytes'] * p['cycles'] / r['observed_frames'] for r in complete)
        sessions = sum(p['roles'].values()) * len(p['scenarios'])
        estimates = {'basis_session': worst['session'], 'sessions': sessions,
                     'raw_bytes_per_hour_max_observed': max_raw,
                     'raw_bytes_all_sessions': max_raw * sessions,
                     'archive_bytes_per_hour_max_observed': hourly,
                     'archive_bytes_all_sessions': hourly * sessions,
                     'planning_margin': 1.5, 'emergency_reserve_bytes': p['min_free_gib'] * 2**30,
                     'planned_archive_bytes_with_margin_and_reserve': hourly * sessions * 1.5 + p['min_free_gib'] * 2**30,
                     'working_bytes_per_session_with_margin_and_reserve': max_raw * 1.5 + p['min_free_gib'] * 2**30,
                     'note': 'Planning extrapolation from old diagnostic workload and measured zstd files, not accepted pilot, guarantee or completed corpus. New pool and other scenarios may differ; campaign init re-estimates from accepted pilot.'}
        doc = {'schema': 'hyptcn3/collection-storage-preparation/1', 'date': now(),
               'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
               'commit_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
               'host': platform.platform(), 'guest': {'domain': 'hyptcn-lab', 'new_capture': False},
               'command': '.venv/bin/python data/lab/prepare_storage_20261020.py', 'n': len(rows),
               'values': {'archive_root': str(ARCHIVE), 'archive_mount': mount, 'space_before': before,
                          'space_after': space(), 'sessions': rows, 'roundtrip': validation,
                          'estimates': estimates, 'reclaimed_bytes': sum(r['reclaimed_bytes'] for r in rows),
                          'stored_bytes': sum(r['stored_bytes'] for r in rows),
                          'source_sha256': {str(f.relative_to(ROOT)): digest(f) for f in
                              (Path(__file__), ROOT / 'scripts/collection_archive.py')}}}
        write_new(OUT, doc)
        emit(stage='done', result=str(OUT), estimates=estimates, space_after=space())


if __name__ == '__main__':
    main()
