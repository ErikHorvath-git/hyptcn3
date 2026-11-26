"""The table of the deployed guest against the commit of each G2 session (scripts/campaign_report.py guest, package
H1b6a) on recorded files: sessions recorded by scripts/tests/g2_tabulky.py whose guest_before holds the manifest
collection.guest_identity takes, against the commits of a git repository made in tmp_path (GUEST_REPOSITORY set to
it). Nothing outside tmp_path is written.
"""
import hashlib
import json
import os
import subprocess

import pytest

from scripts import campaign_report, collection
from scripts.tests import g2_tabulky as tab

FILES = {"lab/services.py": "print('the lab services')\n", "lab/nginx.conf": "server { listen 80; }\n",
         "lab/hyptcn-lab@.service": "[Service]\nRestart=on-failure\n", "lab/tests/test_lab.py": "assert True\n",
         "README.md": "not lab\n"}


def git(repo, *args, env=None):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A git repository with lab/ (three top-level files and a tests directory) committed once; (path, commit, the
    sha256 of each file of lab/ at the commit)."""
    path = tmp_path / "repo"
    for name, text in FILES.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text)
    env = {**os.environ, "HOME": str(tmp_path), "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t",
           "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    subprocess.run(["git", "init", "-q", str(path)], check=True, env=env)
    git(path, "add", "-A", env=env)
    git(path, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "lab", env=env)
    commit = git(path, "rev-parse", "HEAD").decode().strip()
    monkeypatch.setattr(campaign_report, "GUEST_REPOSITORY", path)
    lab = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in FILES.items()
           if name.startswith("lab/") and name.count("/") == 1}
    return path, commit, lab


def manifest(lab, *, packages=tab.PACKAGES, timers=tab.TIMERS, change=None):
    """The stack_manifest collection.guest_identity takes of a guest that runs `lab`: a sha256sum line of every
    deployed path, the dpkg lines and the timers; change: {guest path: sha256 or None (no line)}."""
    lines = []
    for path, source in collection.deployed_paths(lab).items():
        sha = (change or {}).get(path, lab[source])
        if sha is not None:
            lines.append(f"{sha}  {path}")
    for path, sha in (change or {}).items():
        if path not in collection.deployed_paths(lab) and sha is not None:
            lines.append(f"{sha}  {path}")
    return [*lines, *packages, timers]


def table(tmp_path, recorder, dirs):
    return tab.run("guest", dirs, recorder, tmp_path / "out" / "host.json")


def sessions(rec, commit, lab, specs):
    """One recorded session per (vm, deck id, options)."""
    return [rec.session(vm, deck_id, commit=commit, lab=options.pop("lab", lab),
                        manifest=options.pop("manifest", manifest(lab)), **options)[0]
            for vm, deck_id, options in specs]


def test_both_vms_run_the_lab_of_the_commit(tmp_path, repo, capsys):
    """Two sessions on each VM whose guests run the files of lab/ of their commit, one dpkg list and one set of timers
    on both VMs: exit 0; the header of check E with the stage G2; per session and path the guest's sha256 and the
    commit's; the commit's files from git, the tests directory and files outside lab/ not among them."""
    path, commit, lab = repo
    rec = tab.Recorder(tmp_path)
    dirs = sessions(rec, commit, lab, [("a", "e01", {}), ("b", "e02", {}), ("a", "e03", {}), ("b", "e04", {})])
    code, doc = table(tmp_path, rec, dirs)
    assert code == 0, doc["values"]["findings"]
    assert {"commit", "date", "host", "guest", "command", "n", "values"} <= set(doc)
    assert (doc["schema"], doc["n"]) == ("hyptcn3/g2-guest-table/1", 4)
    v = doc["values"]
    assert (v["stage"], v["criterion"], v["findings"]) == ("G2", "guest_matches_repository", [])
    assert v["result"] == {"met": True, "vms": ["a", "b"], "sessions_counted": 4, "left_out": 0,
                           "vms_agree": {"packages": True, "timers": True}}
    assert v["commits"] == {commit: {"lab": lab}} and v["repository"]["path"] == str(path)
    row = v["table"][0]
    assert (row["session"], row["vm"], row["commit"], row["matches_commit"], row["lab_sha256_matches_commit"]) == (
        "g2-a-e01-1", "a", commit, True, True)
    assert [(f["path"], f["source"]) for f in row["files"]] == sorted(collection.deployed_paths(lab).items())
    assert all(f["guest_sha256"] == f["commit_sha256"] == lab[f["source"]] and f["equal"] for f in row["files"])
    assert row["packages"] == sorted(tab.PACKAGES) and row["timers"] == ["hyptcn-lab-udrzba.timer"]
    assert v["by_vm"]["a"] == {"sessions": ["g2-a-e01-1", "g2-a-e03-1"], "packages": [sorted(tab.PACKAGES)],
                               "timers": [["hyptcn-lab-udrzba.timer"]]}
    session = v["sessions"][0]
    assert session["status"] == "counted" and {f["name"] for f in session["files"]} == {"session.json",
                                                                                        "protocol.json", "record"}
    assert "guest_matches_repository: met" in capsys.readouterr().out


def test_the_files_of_the_commit_not_of_the_working_tree(tmp_path, repo):
    """A file of lab/ changed in the working tree after the commit changes nothing: the table reads git show of the
    commit, whose bytes are git cat-file's of the blob; a guest that runs the changed file differs from the commit."""
    path, commit, lab = repo
    (path / "lab/services.py").write_text("print('changed after the commit')\n")
    assert campaign_report.guest_commit_files(path, commit) == lab
    assert lab["lab/services.py"] == hashlib.sha256(git(path, "cat-file", "blob", f"{commit}:lab/services.py")
                                                    ).hexdigest()
    changed = hashlib.sha256((path / "lab/services.py").read_bytes()).hexdigest()
    rec = tab.Recorder(tmp_path)
    dirs = sessions(rec, commit, lab, [("a", "e01", {}), ("b", "e02", {
        "manifest": manifest(lab, change={"/opt/hyptcn-lab/services.py": changed}),
        "lab": {**lab, "lab/services.py": changed}, "commit_dirty": True})])
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    v = doc["values"]
    row = v["table"][1]
    assert (row["matches_commit"], row["differ"], row["lab_sha256_differ"]) == (
        False, ["/opt/hyptcn-lab/services.py"], ["lab/services.py"])
    assert v["findings"] == [
        f"g2-b-e02-1 (VM b): the deployed guest differs from lab/ of the commit {commit}: /opt/hyptcn-lab/services.py",
        f"g2-b-e02-1 (VM b): session.json lab_sha256 differs from lab/ of its commit {commit} (commit_dirty True): "
        "lab/services.py"]


def test_a_missing_line_and_a_path_the_commit_lacks_differ(tmp_path, repo):
    """A deployed path without a line in the manifest, and a line of a path that the commit's deployed set lacks: both
    differ from the commit by name, exit 1."""
    _, commit, lab = repo
    rec = tab.Recorder(tmp_path)
    dirs = sessions(rec, commit, lab, [("a", "e01", {"manifest": manifest(lab, change={
        "/etc/nginx/conf.d/hyptcn-lab.conf": None, "/opt/hyptcn-lab/old.py": "1" * 64})}), ("b", "e02", {})])
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    row = doc["values"]["table"][0]
    assert row["differ"] == ["/etc/nginx/conf.d/hyptcn-lab.conf", "/opt/hyptcn-lab/old.py"]
    missing = next(f for f in row["files"] if f["path"] == "/etc/nginx/conf.d/hyptcn-lab.conf")
    extra = next(f for f in row["files"] if f["path"] == "/opt/hyptcn-lab/old.py")
    assert (missing["guest_sha256"], missing["commit_sha256"], extra["source"], extra["commit_sha256"]) == (
        None, lab["lab/nginx.conf"], None, None)


def test_dpkg_and_timers_are_compared_between_the_vms(tmp_path, repo):
    """VM b with another version of nginx than VM a, and VM a whose timers changed between its sessions: findings by
    name, exit 1."""
    _, commit, lab = repo
    other = ["nginx\t1.22.1-9+deb12u4", *tab.PACKAGES[1:]]
    rec = tab.Recorder(tmp_path)
    dirs = sessions(rec, commit, lab, [
        ("a", "e01", {}), ("a", "e03", {"manifest": manifest(lab, timers="timers: apt-daily.timer "
                                                                         "hyptcn-lab-udrzba.timer ")}),
        ("b", "e02", {"manifest": manifest(lab, packages=other)})])
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    v = doc["values"]
    assert v["result"]["vms_agree"] == {"packages": False, "timers": False}
    assert v["by_vm"]["a"]["timers"] == [["apt-daily.timer", "hyptcn-lab-udrzba.timer"], ["hyptcn-lab-udrzba.timer"]]
    assert v["findings"][0].startswith("VM a: 2 different timers over its sessions: ")
    assert v["findings"][1].startswith("the VMs differ in their dpkg lists: VM a ")
    assert "nginx\\t1.22.1-9+deb12u4" in v["findings"][1]
    assert v["findings"][2].startswith("the VMs differ in their timers: ")
    assert len(v["findings"]) == 3


def test_a_vm_without_a_session_and_a_session_the_records_leave_out(tmp_path, repo):
    """Only VM a has a counted session: the finding names VM b; a session of VM b whose record names
    guest_matches_repository in values.excluded is left out by name and its guest is not judged."""
    _, commit, lab = repo
    rec = tab.Recorder(tmp_path)
    dirs = sessions(rec, commit, lab, [("a", "e01", {}), ("b", "e02", {
        "excluded": {"criteria": ["guest_matches_repository"], "rule": "a test"},
        "manifest": manifest(lab, change={"/opt/hyptcn-lab/services.py": "2" * 64})})])
    code, doc = table(tmp_path, rec, dirs)
    assert code == 1
    v = doc["values"]
    assert v["findings"] == ["VM b: no session of it"] and len(v["table"]) == 1
    left = v["sessions"][1]
    assert (left["session_id"], left["status"]) == ("g2-b-e02-1", "left_out")
    assert left["why"] == "its record leaves it out of guest_matches_repository (values.excluded: a test)"


def test_a_commit_the_repository_lacks_or_bytes_that_are_not_the_blob_are_data_errors(tmp_path, repo, monkeypatch,
                                                                                       capsys):
    """A commit that is not in the repository, one that is no object name, and git show bytes that do not give the
    blob's object id: exit 2 by name, nothing written."""
    path, commit, lab = repo
    rec = tab.Recorder(tmp_path)
    d1, = sessions(rec, "d" * 40, lab, [("a", "e01", {})])
    d2, = sessions(rec, "HEAD", lab, [("b", "e02", {})])
    assert table(tmp_path, rec, [d1, d2]) == (2, None)
    err = capsys.readouterr().err
    assert f"the commit {'d' * 40} is not in the repository {path}" in err and 'the commit "HEAD" is no full' in err
    d3, = sessions(rec, commit, lab, [("a", "e03", {})])
    real = campaign_report._git

    def altered(repository, *args):
        done = real(repository, *args)
        if args[0] == "show":
            done.stdout += b"\n"
        return done

    monkeypatch.setattr(campaign_report, "_git", altered)
    assert table(tmp_path, rec, [d3]) == (2, None)
    assert "are not its blob" in capsys.readouterr().err
    assert not (tmp_path / "out" / "host.json").exists()
    assert json.loads((rec.g2_dir / "zaznamy" / f"{d3.name}.json").read_text())["values"]["session_id"] == d3.name
