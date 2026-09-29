"""Infrastructure tests for lab VM constants, QEMU helpers, and run_VMs defaults."""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import tempfile
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
from VM.kali_client import image_tools as kali_image_tools
from VM.metasploitable_target import image_tools as metasploitable_image_tools


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

    def test_convert_disk_to_qcow2_replaces_destination_after_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "source.vmdk"
            dst = root / "target.qcow2"
            src.write_bytes(b"source")
            dst.write_bytes(b"old")

            def fake_run(command, *, check):
                self.assertEqual(command[-1], str(root / "target.qcow2.partial"))
                Path(command[-1]).write_bytes(b"new")
                return subprocess.CompletedProcess(command, 0)

            with (
                mock.patch.object(common_qemu, "require_qemu_tools", return_value=("/qemu", "/qemu-img")),
                mock.patch.object(common_qemu.shutil, "disk_usage", return_value=SimpleNamespace(free=10**9)),
                mock.patch.object(common_qemu.subprocess, "run", side_effect=fake_run),
            ):
                common_qemu.convert_disk_to_qcow2(str(src), str(dst))

            self.assertEqual(dst.read_bytes(), b"new")
            self.assertFalse((root / "target.qcow2.partial").exists())

    def test_convert_disk_to_qcow2_preserves_destination_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "source.vmdk"
            dst = root / "target.qcow2"
            src.write_bytes(b"source")
            dst.write_bytes(b"old")

            def fake_run(command, *, check):
                Path(command[-1]).write_bytes(b"partial")
                raise subprocess.CalledProcessError(1, command)

            with (
                mock.patch.object(common_qemu, "require_qemu_tools", return_value=("/qemu", "/qemu-img")),
                mock.patch.object(common_qemu.shutil, "disk_usage", return_value=SimpleNamespace(free=10**9)),
                mock.patch.object(common_qemu.subprocess, "run", side_effect=fake_run),
            ):
                with self.assertRaisesRegex(RuntimeError, "qemu-img convert failed"):
                    common_qemu.convert_disk_to_qcow2(str(src), str(dst))

            self.assertEqual(dst.read_bytes(), b"old")
            self.assertFalse((root / "target.qcow2.partial").exists())

    def test_convert_disk_to_qcow2_fails_fast_when_destination_lacks_space(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "source.vmdk"
            dst = root / "target.qcow2"
            src.write_bytes(b"source")

            with (
                mock.patch.object(common_qemu, "require_qemu_tools", return_value=("/qemu", "/qemu-img")),
                mock.patch.object(common_qemu.shutil, "disk_usage", return_value=SimpleNamespace(free=1)),
                mock.patch.object(common_qemu.subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(RuntimeError, "Not enough free space"):
                    common_qemu.convert_disk_to_qcow2(str(src), str(dst))

            run.assert_not_called()

    def test_remove_existing_lab_vm_preserves_named_disk_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            qcow = root / "metasploitable2.qcow2"
            marker = root / "metasploitable2.qcow2.verified"
            log = root / "qemu.log"
            nested = root / "runtime"
            nested.mkdir()
            qcow.write_text("disk\n", encoding="utf-8")
            marker.write_text("verified\n", encoding="utf-8")
            log.write_text("log\n", encoding="utf-8")
            (nested / "state").write_text("state\n", encoding="utf-8")

            with (
                mock.patch.object(common_qemu, "is_qemu_vm_running", return_value=False),
                mock.patch.object(common_qemu, "delete_tap"),
            ):
                common_qemu.remove_existing_lab_vm(
                    TEST_TARGET_VM_NAME,
                    str(root),
                    tap=TAP_TARGET,
                    preserve_names={qcow.name, marker.name},
                )

            self.assertTrue(qcow.is_file())
            self.assertTrue(marker.is_file())
            self.assertFalse(log.exists())
            self.assertFalse(nested.exists())


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


class RunVMsEnvFileTests(unittest.TestCase):
    def test_ensure_vm_env_file_creates_file_from_example(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            example = root / ".env.example"
            env = root / ".env"
            example.write_text(
                "# Local lab VM passwords.\n"
                "OPENWRT_ROOT_PASSWORD=replace-with-a-long-local-password\n"
                "KALI_CLIENT_ROOT_PASSWORD=replace-with-a-long-local-password\n",
                encoding="utf-8",
            )
            with mock.patch.object(run_VMs.secrets, "token_urlsafe", side_effect=["openwrt", "kali"]):
                added = run_VMs.ensure_vm_env_file(env_path=env, example_path=example)

            self.assertEqual(added, ["OPENWRT_ROOT_PASSWORD", "KALI_CLIENT_ROOT_PASSWORD"])
            self.assertEqual(
                env.read_text(encoding="utf-8"),
                "# Local lab VM passwords.\n"
                "OPENWRT_ROOT_PASSWORD=openwrt\n"
                "KALI_CLIENT_ROOT_PASSWORD=kali\n",
            )

    def test_ensure_vm_env_file_appends_new_keys_without_overwriting_existing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            example = root / ".env.example"
            env = root / ".env"
            example.write_text(
                "OPENWRT_ROOT_PASSWORD=replace-with-a-long-local-password\n"
                "ALPINE_CLIENT_ROOT_PASSWORD=replace-with-a-long-local-password\n"
                "KALI_CLIENT_ROOT_PASSWORD=replace-with-a-long-local-password\n",
                encoding="utf-8",
            )
            env.write_text(
                "OPENWRT_ROOT_PASSWORD=keep-openwrt\n"
                "ALPINE_CLIENT_ROOT_PASSWORD=keep-alpine\n",
                encoding="utf-8",
            )
            with mock.patch.object(run_VMs.secrets, "token_urlsafe", return_value="generated-kali"):
                added = run_VMs.ensure_vm_env_file(env_path=env, example_path=example)

            self.assertEqual(added, ["KALI_CLIENT_ROOT_PASSWORD"])
            text = env.read_text(encoding="utf-8")
            self.assertIn("OPENWRT_ROOT_PASSWORD=keep-openwrt\n", text)
            self.assertIn("ALPINE_CLIENT_ROOT_PASSWORD=keep-alpine\n", text)
            self.assertIn("KALI_CLIENT_ROOT_PASSWORD=generated-kali\n", text)
            self.assertEqual(text.count("OPENWRT_ROOT_PASSWORD="), 1)


class KaliImageTests(unittest.TestCase):
    def test_existing_cached_qcow2_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "kali-linux-2026.2-qemu-amd64.7z"
            dest = root / "kali-linux-2026.2-qemu-amd64.qcow2"
            archive.write_bytes(b"archive")
            dest.write_bytes(b"qcow")

            with mock.patch.object(kali_image_tools.subprocess, "run") as run:
                result = kali_image_tools.ensure_kali_disk_image(str(archive), str(dest))

            self.assertEqual(result, str(dest))
            run.assert_not_called()

    def test_qemu_7z_archive_extracts_and_caches_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "kali-linux-2026.2-qemu-amd64.7z"
            dest = root / "kali-linux-2026.2-qemu-amd64.qcow2"
            archive.write_bytes(b"archive")

            def fake_run(command, *, capture_output, text):
                self.assertEqual(command[:3], ["/usr/bin/7z", "x", "-y"])
                out_arg = next(arg for arg in command if arg.startswith("-o"))
                extracted = Path(out_arg[2:]) / "kali-linux-2026.2-qemu-amd64"
                extracted.mkdir(parents=True)
                (extracted / "kali-linux-2026.2-qemu-amd64.qcow2").write_bytes(b"disk")
                return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

            with (
                mock.patch.object(kali_image_tools.shutil, "which", return_value="/usr/bin/7z"),
                mock.patch.object(kali_image_tools.subprocess, "run", side_effect=fake_run) as run,
            ):
                result = kali_image_tools.ensure_kali_disk_image(str(archive), str(dest))

            self.assertEqual(result, str(dest))
            self.assertEqual(dest.read_bytes(), b"disk")
            run.assert_called_once()


class MetasploitableImageTests(unittest.TestCase):
    def test_existing_verified_qcow2_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.vmdk"
            qcow = root / "metasploitable2.qcow2"
            marker = root / "metasploitable2.qcow2.verified"
            source.write_bytes(b"source")
            qcow.write_bytes(b"x" * 100_000_001)
            marker.write_text(
                f"source={metasploitable_image_tools._source_signature(str(source))}\n",
                encoding="utf-8",
            )

            with (
                mock.patch.object(metasploitable_image_tools, "require_qemu_tools", return_value=("/qemu", "/qemu-img")),
                mock.patch.object(metasploitable_image_tools, "download_metasploitable_zip"),
                mock.patch.object(metasploitable_image_tools, "extract_metasploitable_vmdk", return_value=str(source)),
                mock.patch.object(metasploitable_image_tools, "_qcow_basic_check", return_value=True) as check,
                mock.patch.object(metasploitable_image_tools, "_qcow_matches_vmdk") as compare,
                mock.patch.object(metasploitable_image_tools, "convert_disk_to_qcow2") as convert,
            ):
                metasploitable_image_tools.ensure_metasploitable_qcow2(
                    download_dir=str(root),
                    qcow_path=str(qcow),
                )

            check.assert_called_once_with(str(qcow))
            compare.assert_not_called()
            convert.assert_not_called()

    def test_existing_unverified_qcow2_is_rebuilt_when_source_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.vmdk"
            qcow = root / "metasploitable2.qcow2"
            source.write_bytes(b"source")
            qcow.write_bytes(b"x" * 100_000_001)

            with (
                mock.patch.object(metasploitable_image_tools, "require_qemu_tools", return_value=("/qemu", "/qemu-img")),
                mock.patch.object(metasploitable_image_tools, "download_metasploitable_zip"),
                mock.patch.object(metasploitable_image_tools, "extract_metasploitable_vmdk", return_value=str(source)),
                mock.patch.object(metasploitable_image_tools, "_qcow_matches_vmdk", return_value=False),
                mock.patch.object(metasploitable_image_tools, "convert_disk_to_qcow2") as convert,
            ):
                metasploitable_image_tools.ensure_metasploitable_qcow2(
                    download_dir=str(root),
                    qcow_path=str(qcow),
                )

            convert.assert_called_once_with(str(source), str(qcow))
            self.assertTrue((root / "metasploitable2.qcow2.verified").is_file())


if __name__ == "__main__":
    unittest.main()
