"""Smoke tests for the detections package layout."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


class DetectionsPackageSmokeTests(unittest.TestCase):
    def test_common_helpers_import(self) -> None:
        from detections.common import common_qemu, common_vm

        self.assertTrue(hasattr(common_vm, "TEST_ROUTER_VM_NAME"))
        self.assertTrue(hasattr(common_qemu, "build_client_qemu_argv"))

    def test_run_detections_module_is_present(self) -> None:
        self.assertTrue((_REPO_ROOT / "detections" / "run_detections.py").is_file())
        import detections.run_detections as run_detections

        self.assertTrue(hasattr(run_detections, "__file__"))


if __name__ == "__main__":
    unittest.main()
