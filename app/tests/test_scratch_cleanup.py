"""Regression test: leaked Syft/Grype (stereoscope) scratch dirs get reaped.

Background: these ~0.5-1 GB per-scan layer-extraction dirs leak whenever a
scanner process is killed (task timeout, worker restart, max-tasks-per-child
recycle). 81 leaked dirs put 63 GB into one batch worker's writable layer and
took /opt to 98% full. The cleanup task must delete abandoned ones while never
touching dirs young enough to still belong to a running scan.
"""
import os
import time

from app.tasks import cleanup_old_scan_artifacts, TMP_SCRATCH_MAX_AGE


def _mk(path, age_seconds):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "layer.tar"), "w") as f:
        f.write("x")
    when = time.time() - age_seconds
    os.utime(path, (when, when))
    return path


def test_reaps_abandoned_scratch_but_keeps_fresh(mock_redis, tmp_path, monkeypatch):
    # Keep report/SBOM retention pointed at throwaway dirs so the task's other
    # half can't touch anything real.
    monkeypatch.setattr("app.tasks.settings.REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr("app.tasks.settings.SBOMS_DIR", str(tmp_path / "sboms"))

    stale_age = TMP_SCRATCH_MAX_AGE + 600
    stale = _mk(f"/tmp/stereoscope-pytest-stale-{os.getpid()}", stale_age)
    stale_syft = _mk(f"/tmp/syft-cataloger-pytest-stale-{os.getpid()}", stale_age)
    # Young enough that a scan could still own it — must survive.
    fresh = _mk(f"/tmp/stereoscope-pytest-fresh-{os.getpid()}", 60)

    try:
        result = cleanup_old_scan_artifacts()

        assert not os.path.exists(stale), "abandoned stereoscope dir was not reaped"
        assert not os.path.exists(stale_syft), "abandoned syft-cataloger dir was not reaped"
        assert os.path.exists(fresh), "in-use scratch dir must not be deleted"
        assert result["deleted"]["tmp_scanner_dirs"] >= 2
    finally:
        for p in (stale, stale_syft, fresh):
            if os.path.exists(p):
                import shutil
                shutil.rmtree(p, ignore_errors=True)


def test_scratch_threshold_exceeds_hard_scan_limit():
    """The reap clock must never be shorter than the longest a scan can run,
    otherwise cleanup could delete a live scan's working dir."""
    from app.config import settings
    assert TMP_SCRATCH_MAX_AGE > settings.SCAN_TIMEOUT * 3
    assert TMP_SCRATCH_MAX_AGE >= 7500  # batch_scan_images hard limit
