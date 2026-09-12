"""Infrastructure tests for lab VM constants, QEMU helpers, and run_VMs defaults."""

from __future__ import annotations

import argparse
import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common import common_qemu
from detections.common.common_qemu import (
    CLIENTA_SERIAL_TCP_PORT,
    LAB_BRIDGE_NAME,
    TAP_CLIENTA,
    TAP_CLIENTK,
    TAP_ROUTER_LAN,
    TAP_TARGET,
    build_client_qemu_argv,
    default_serial_port_for_vm,
    fresh_lab_identity,
    qemu_display_args,
    qemu_serial_tcp_args,
    tap_name_for_vm,
)
from detections.common.common_vm import (
    CLIENTK_SERIAL_TCP_PORT,
    ROUTER_SERIAL_TCP_PORT,
    TARGET_SERIAL_TCP_PORT,
    TEST_CLIENTA_VM_NAME,
    TEST_CLIENTK_VM_NAME,
    TEST_ROUTER_VM_NAME,
    TEST_TARGET_VM_NAME,
)


def _load_run_vms():
    path = Path(__file__).resolve().parents[2] / "run" / "run_VMs.py"
    spec = importlib.util.spec_from_file_location("overdrive_run_vms", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


run_VMs = _load_run_vms()


class LabConstantTests(unittest.TestCase):
    def test_bridge_name(self) -> None:
        self.assertEqual(LAB_BRIDGE_NAME, "test-lan")

    def test_vm_names(self) -> None:
        self.assertEqual(TEST_ROUTER_VM_NAME, "Test_Router")
        self.assertEqual(TEST_CLIENTA_VM_NAME, "Test_Clienta")
        self.assertEqual(TEST_CLIENTK_VM_NAME, "Test_Clientk")
        self.assertEqual(TEST_TARGET_VM_NAME, "target")

    def test_serial_ports_are_unique_and_expected(self) -> None:
        ports = {
            TEST_ROUTER_VM_NAME: ROUTER_SERIAL_TCP_PORT,
            TEST_CLIENTA_VM_NAME: CLIENTA_SERIAL_TCP_PORT,
            TEST_CLIENTK_VM_NAME: CLIENTK_SERIAL_TCP_PORT,
            TEST_TARGET_VM_NAME: TARGET_SERIAL_TCP_PORT,
        }
        self.assertEqual(ports[TEST_ROUTER_VM_NAME], 2324)
        self.assertEqual(ports[TEST_CLIENTA_VM_NAME], 2325)
        self.assertEqual(ports[TEST_CLIENTK_VM_NAME], 2326)
        self.assertEqual(ports[TEST_TARGET_VM_NAME], 2327)
        self.assertEqual(len(set(ports.values())), 4)

    def test_tap_and_serial_maps(self) -> None:
        expected_taps = {
            TEST_ROUTER_VM_NAME: TAP_ROUTER_LAN,
            TEST_CLIENTA_VM_NAME: TAP_CLIENTA,
            TEST_CLIENTK_VM_NAME: TAP_CLIENTK,
            TEST_TARGET_VM_NAME: TAP_TARGET,
        }
        for name, tap in expected_taps.items():
            self.assertEqual(tap_name_for_vm(name), tap)

        self.assertEqual(default_serial_port_for_vm(TEST_ROUTER_VM_NAME), 2324)
        self.assertEqual(default_serial_port_for_vm(TEST_CLIENTA_VM_NAME), 2325)
        self.assertEqual(default_serial_port_for_vm(TEST_CLIENTK_VM_NAME), 2326)
        self.assertEqual(default_serial_port_for_vm(TEST_TARGET_VM_NAME), 2327)


class QemuHelperTests(unittest.TestCase):
    def test_display_args_headless(self) -> None:
        self.assertEqual(qemu_display_args("headless"), ["-display", "none"])
        self.assertEqual(qemu_display_args("none"), ["-display", "none"])
        self.assertEqual(qemu_display_args("gui"), ["-display", "gtk"])

    def test_serial_tcp_args(self) -> None:
        self.assertEqual(
            qemu_serial_tcp_args(2326),
            ["-serial", "tcp:127.0.0.1:2326,server,nowait"],
        )

    def test_fresh_lab_identity_for_each_vm(self) -> None:
        for name in (
            TEST_ROUTER_VM_NAME,
            TEST_CLIENTA_VM_NAME,
            TEST_CLIENTK_VM_NAME,
            TEST_TARGET_VM_NAME,
        ):
            identity = fresh_lab_identity(name)
            self.assertIn("hardware_uuid", identity)
            self.assertIn("nic1_colon", identity)
            self.assertEqual(identity["nic1_colon"].count(":"), 5)
            if name == TEST_ROUTER_VM_NAME:
                self.assertIn("nic2_colon", identity)

    def test_build_client_argv_uses_tap_serial_and_nic_model(self) -> None:
        with mock.patch.object(common_qemu, "ensure_tap_on_bridge") as ensure_tap:
            argv = build_client_qemu_argv(
                qemu="/usr/bin/qemu-system-x86_64",
                vm_name=TEST_TARGET_VM_NAME,
                qcow_path="/tmp/target.qcow2",
                memory_mib=512,
                cpus=1,
                tap_name=TAP_TARGET,
                mac_colon="00:50:56:11:22:33",
                hardware_uuid="11111111-2222-3333-4444-555555555555",
                serial_port=2327,
                start_type="headless",
                pid_path=Path("/tmp/target.pid"),
                nic_model="e1000",
            )
        ensure_tap.assert_called_once_with(TAP_TARGET)
        self.assertEqual(argv[argv.index("-name") + 1], "target")
        self.assertIn("tap,id=lan,ifname=tap-target,script=no,downscript=no", argv)
        self.assertIn("e1000,netdev=lan,mac=00:50:56:11:22:33", argv)
        self.assertIn("tcp:127.0.0.1:2327,server,nowait", " ".join(argv))
        self.assertEqual(argv[argv.index("-display") + 1], "none")


class RunVMsDefaultTests(unittest.TestCase):
    def test_default_start_type_is_headless(self) -> None:
        args = SimpleNamespace(headless=False, gui=False, start_type="headless")
        self.assertEqual(run_VMs._resolve_start_type(args), "headless")

    def test_gui_flag_overrides_default(self) -> None:
        args = SimpleNamespace(headless=False, gui=True, start_type="headless")
        self.assertEqual(run_VMs._resolve_start_type(args), "gui")

    def test_explicit_start_type_honored(self) -> None:
        args = SimpleNamespace(headless=False, gui=False, start_type="none")
        self.assertEqual(run_VMs._resolve_start_type(args), "none")

    def test_main_parser_defaults_to_headless(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("--headless", action="store_true")
        parser.add_argument("--gui", action="store_true")
        parser.add_argument(
            "--start-type",
            choices=("gui", "headless", "separate", "none"),
            default="headless",
        )
        # Mirror the production defaults we just set in run_VMs.main().
        source = Path(run_VMs.__file__).read_text(encoding="utf-8")
        self.assertIn('default="headless"', source)
        self.assertIn('"--gui"', source)
        args = parser.parse_args([])
        self.assertEqual(run_VMs._resolve_start_type(args), "headless")


if __name__ == "__main__":
    unittest.main()
