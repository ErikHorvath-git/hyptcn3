#!/usr/bin/env python3
"""Local pilot/stop-test driver using the campaign's tested child lifecycle.

This runner never starts a corpus campaign. The full capture metadata and
independent audit remain the collection tool's responsibility.
"""
import argparse
from pathlib import Path
import json
import os
import sys

ROOT = Path('/home/eh/projects/hyptcn3')
sys.path.insert(0, str(ROOT))
from scripts import collection, campaign
from scripts.collection_archive import write_new, now, read_json, digest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('plan', type=Path)
    a = ap.parse_args()
    plan = read_json(a.plan)
    if os.geteuid() != 0 or os.environ.get('SUDO_USER') != 'eh':
        raise ValueError('run as sudo from eh')
    if plan['measurement_sha256'] != collection.measurement_sources():
        raise ValueError('measurement code differs from the prepared pilot')
    if digest(ROOT / plan['protocol']) != plan['protocol_sha256']:
        raise ValueError('protocol differs from prepared pilot')
    if digest(__file__) != plan['runner_sha256']:
        raise ValueError('pilot runner differs from prepared plan')
    p = collection.protocol(ROOT / plan['protocol'])
    if collection.guest_identity(p) != plan['guest']:
        raise ValueError('guest differs from prepared pilot')
    role = plan['role']
    if role not in ('pilot', 'diagnostic'):
        raise ValueError('preflight runner cannot collect corpus sessions')
    session = ROOT / plan['session']
    work = a.plan.parent
    if session.exists() or (work / 'status.json').exists():
        raise ValueError('a new exclusive plan/session is required')
    interrupts = collection.Interrupts()
    inhibitor = None
    state = {'schema': 'hyptcn3/preflight-status/1', 'created': now(),
             'plan': str(a.plan), 'plan_sha256': digest(a.plan), 'session': str(session),
             'accepted': False, 'pid': os.getpid()}

    def update(stage, **fields):
        state.update(stage=stage, updated=now(), **fields)
        write_new(work / 'status.json', state, replace=True)
        print(json.dumps({'stage': stage, **fields}), flush=True)

    try:
        with collection.collection_lock(ROOT / 'data/collections') as fd:
            inhibitor = campaign.hold_sleep_inhibitor()
            update('capture')
            command = [sys.executable, ROOT / 'scripts/collection.py', '--protocol', ROOT / plan['protocol'],
                       'run', '--role', role, '--scenario', plan['scenario'], '--group', plan['group'],
                       '--seed', str(plan['seed']), '--session-id', session.name,
                       '--expected-boot-id', plan['guest']['boot_id']]
            if role == 'diagnostic':
                command += ['--collections-dir', session.parent, '--cycles', str(plan['cycles'])]
            rc = campaign.run_child(command, work / 'capture.log', lock_fd=fd,
                                    timeout=plan['cycles'] * p['interval_s'] + p['warmup_s'] + 600)
            if rc:
                update('capture_failed', capture_rc=rc)
                return rc
            update('audit', capture_rc=rc)
            rc = campaign.run_child(collection.user_command([sys.executable, ROOT / 'scripts/collection.py',
                '--protocol', ROOT / plan['protocol'], 'audit', session]), work / 'audit.log', timeout=14400)
            reports = sorted(session.glob('audit*.json'))
            report = reports[-1] if reports else None
            values = read_json(report)['values'] if report else {}
            update('accepted' if rc == 0 and values.get('accepted') else 'rejected', audit_rc=rc,
                   accepted=rc == 0 and values.get('accepted') is True,
                   audit=str(report) if report else None, score_coverage=values.get('score_coverage'),
                   reasons=values.get('reasons', ['audit produced no report']))
            return rc
    except InterruptedError:
        update('interrupted', signals=interrupts.received)
        return 130
    except Exception as error:
        update('failed', error=str(error))
        raise
    finally:
        interrupts.disarm()
        campaign.release_sleep_inhibitor(inhibitor)
        interrupts.restore()


if __name__ == '__main__':
    sys.exit(main())
