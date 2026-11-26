"""The faults of stage G2: their forms and the names each must be refused with (protocol v5, package H1b3).

Binding texts: the lead's G2 skeleton dokazy/G2/kostra/KOSTRA.md (rows H1 and H4, the criterion
live_fault_injections, section 3), the map dokazy/G2/mapa.md (row 9, its questions 11 and 12) and the lead's answers
Q56 (the forms and the expected names are committed before the first run; the memory pressure with the QEMU swap ban
of that VM lifted, expecting `logs: qemu_swap`), Q57 (600 cycles), Q60 (an error-free run has no induced fault, also
on the other VM) and Q26 (both VMs' QEMU share one unit). skuska/ is no directory of scripts/collection.py
MEASUREMENT_DIRS, so nothing here changes the measurement code (map point E).

FAULTS is written and committed before any fault runs (Q56) and never changed afterwards: a fault's form, its
parameters, what proves it happened, the scenario of its sessions and the exact reasons it must be refused with,
each with its origin in the code at commit f5f43d8 (17546fe and package H1b2). An expected name is one exact string of
the refusal: the error end.json records for a capture that did not complete, as scripts/campaign.py
incomplete_reasons gives it, or a reason of the audit's verdict (values.reasons of scripts/collection.py audit). A
fault is refused by its names when every one of them is among those the session received.
"""

# The scenario of every fault session and of the clean session of each VM: one shape for all of them (Q57: a clean
# session per VM of the same shape). The stopped generator runs at rate high (map row 9: the variation its stop leaves
# grows with the rate); corp_high rather than eshop_high, since the burst of the arrivals the stop held back is then
# at most about 16.6/s x 120 s = 2000 user sessions against the cap of 3984, not about 3650 against 7307, and the docs
# service that the killed service fault kills serves corp's documents and reports.
SCENARIO = "corp_high"

FAULTS = {
    "zabity_zberac": {
        "fault": "killed collector",
        "form": ("SIGKILL of the exact PID of the session's collector, vmicollect (scripts/collection.py collectors of "
                 "the VM's domain that descend from the session's own collection.py run), never of "
                 "scripts/lab_capture.sh, whose EXIT trap would end before raw/capture.json; after the first sidecar, "
                 "at an idle moment of the collector: lead_s before the deadline of a cycle whose previous sidecar "
                 "is published, the first such deadline at least at_s after the first sidecar that is neither a full "
                 "snapshot nor the cycle after one"),
        "parameters": {"at_s": 60, "lead_s": 0.5, "longest_s": 60},
        "proof": "the PID is gone or a zombie within 10 s of the signal",
        "scenario": SCENARIO,
        "expected": ["ValueError: collector failed; see capture.log", "logs: collector_exit_code"],
        "origin": ("map row 9 and question 11 (Q56): scripts/collection.py capture_session raises 'collector failed; "
                   "see capture.log' when scripts/lab_capture.sh exits non-zero (line 1532) and records it in "
                   "end.json as '<type>: <message>' (line 1560), which scripts/campaign.py incomplete_reasons gives as "
                   "it stands (line 1830); lab_capture.sh writes raw/capture.json with the collector's exit code "
                   "(137 after SIGKILL) after its wait and exits 1, and the log audit refuses an exit code other than "
                   "0 (scripts/collection_logs.py collector, line 660), which scripts/collection.py audit_session "
                   "names 'logs: collector_exit_code'")},
    "zdrzany_procesor": {
        "fault": "delayed processor",
        "form": ("SIGSTOP of the exact PID of the session's vmicollect (as for the killed collector) lead_s before "
                 "the deadline of a cycle chosen as for the killed collector, SIGCONT stop_s later: that cycle starts "
                 "about stop_s - lead_s = 1.5 s late, less than the interval, so no slot is missed"),
        "parameters": {"at_s": 60, "lead_s": 0.5, "stop_s": 2.0, "longest_s": 60},
        "proof": ("the PID's state is T after SIGSTOP; the sidecar of the delayed cycle records a sched.lateness_s "
                  "above audit.lateness_max_s"),
        "scenario": SCENARIO,
        "expected": ["cycle start later than the audit bound"],
        "origin": ("map row 9 and question 11: vmicollect/src/sched.c keeps absolute deadlines on CLOCK_MONOTONIC and "
                   "records the start of a cycle minus its deadline as sched.lateness_s of its sidecar, so the cycle "
                   "after SIGCONT starts about 1.5 s late and the next deadline stays on the grid; scripts/collection.py "
                   "audit_session refuses a lateness above audit.lateness_max_s, 0.5 s, by this reason (line 1923)")},
    "tlak_na_pamat": {
        "fault": "memory pressure",
        "form": ("at_s after the first sidecar, with the other VM idle (no collector and no generator aimed at it: "
                 "both VMs' QEMU share the unit whose ban is lifted, Q26): memory.swap.max of the cgroup of the "
                 "session's QEMU, the user unit hyptcn-libvirtd.service of way 1, from 0 to max; a child of the "
                 "injector with oom_score_adj 1000 takes step_mib of anonymous memory every step_s and touches all "
                 "of it again and again, until VmSwap of the session's QEMU is at least swap_kb, and holds hold_s "
                 "longer, at most max_s in all; then the child is killed (its exact PID) and memory.swap.max is 0 "
                 "again; the VM restarts before its next session (a run refuses a QEMU with swapped memory)"),
        "parameters": {"at_s": 60, "step_mib": 256, "step_s": 0.5, "swap_kb": 1024, "hold_s": 10, "max_s": 600,
                       "longest_s": 660},
        "proof": ("VmSwap of the session's QEMU at least swap_kb while the ban is lifted; memory.swap.max max during "
                  "the pressure and 0 after it"),
        "scenario": SCENARIO,
        "expected": ["logs: qemu_swap"],
        "origin": ("the lead's answer to Q56 (map question 11): the log audit refuses a session in which a sample of "
                   "the host monitor (one a second) shows swapped memory of the session VM's QEMU "
                   "(scripts/collection_logs.py monitor and qemu_unswapped, line 645), named 'logs: qemu_swap'; with "
                   "the ban in place no page of that QEMU can be swapped (the start refuses a QEMU without it, "
                   "scripts/collection.py run_session lines 1175-1181), so the fault lifts the ban of the unit")},
    "restart_vm": {
        "fault": "VM restart during the session",
        "form": ("at_s after the first sidecar, scripts/labctl.py reboot of the session's VM as its owner (virsh "
                 "reboot --mode agent: the same QEMU, a new boot of the guest); the next session in a new group"),
        "parameters": {"at_s": 60, "timeout_s": 300, "longest_s": 300},
        "proof": "labctl reboot exits 0 and prints the session's boot as previous_boot and another boot_id",
        "scenario": SCENARIO,
        "expected": ["ValueError: guest rebooted or changed during capture"],
        "origin": ("map row 9 and question 11: scripts/collection.py capture_session compares the guest's identity "
                   "after the capture with the one before it and raises 'guest rebooted or changed during capture' "
                   "(line 1541), recorded in end.json as '<type>: <message>' and given by campaign.incomplete_reasons "
                   "as it stands")},
    "zastaveny_generator": {
        "fault": "stopped generator",
        "form": ("at_s after the first sidecar, SIGSTOP of the exact PID of the session's scripts/host_traffic.py "
                 "(scripts/collection.py generators aimed at the VM's target that descend from the session's run), "
                 "SIGCONT stop_s later, at rate high"),
        "parameters": {"at_s": 60, "stop_s": 120, "longest_s": 150},
        "proof": "the PID's state is T after SIGSTOP and no longer T after SIGCONT, stop_s apart",
        "scenario": SCENARIO,
        "expected": ["logs: traffic_realism:arrival_cv"],
        "origin": ("map row 9 and question 11: the scheduler of scripts/host_traffic.py offers every arrival at its "
                   "time and records it when it offers it (OpenLoop._due, the recorder's clock at that moment), so "
                   "after SIGCONT the arrivals the stop held back come in one burst; scripts/traffic_log.py realism "
                   "measures the coefficient of variation of the spacings of the measure phase's arrivals rescaled by "
                   "the planned envelope against audit.traffic.arrival_cv [0.8, 1.2] (lines 822-825), and the log "
                   "audit names a requirement missed 'traffic_realism:<name>' (scripts/collection_logs.py realism)")},
    "zabita_sluzba": {
        "fault": "killed guest service outside an event",
        "form": ("at_s after the first sidecar, in a session without events, scripts/labctl.py exec --guest-command "
                 "'systemctl kill -s KILL hyptcn-lab@docs' as the VM's owner; systemctl show of the unit in the "
                 "guest before the kill and wait_s after it"),
        "parameters": {"at_s": 60, "unit": "hyptcn-lab@docs", "wait_s": 20, "longest_s": 300},
        "proof": "NRestarts of the unit higher wait_s after the kill than before it, and another ExecMainPID",
        "scenario": SCENARIO,
        "expected": ["logs: service_restarted:hyptcn-lab@docs"],
        "origin": ("map row 9 and question 11: hyptcn-lab@docs has Restart=on-failure and RestartSec=3 "
                   "(lab/hyptcn-lab@.service), so systemd restarts it after the SIGKILL and its NRestarts, "
                   "InvocationID, ExecMainPID and ExecMainStartTimestampMonotonic differ between "
                   "guest/state_before.json and guest/state_after.json; in a session without events no event type "
                   "restarts a unit (scripts/collection_logs.py timed_units is empty) and the section guest refuses "
                   "the change by its name (line 371), 'logs: service_restarted:hyptcn-lab@docs'; beside an event of "
                   "restart_databazy it would be service_restarted_outside_event (package B12), so its session has "
                   "no events (map row 9)")},
}
