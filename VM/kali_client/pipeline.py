"""Small build-pipeline helpers for the Kali test client VM builder."""

from __future__ import annotations

from dataclasses import dataclass

from VM.pipeline_common import BuildStep, BuildStepError, run_pipeline, validate_pipeline_order

__all__ = [
    "BuildStep",
    "BuildStepError",
    "KaliClientBuildOptions",
    "run_kali_client_pipeline",
    "validate_client_pipeline_order",
]


@dataclass(frozen=True)
class KaliClientBuildOptions:
    start_vm: bool = True
    connect_serial: bool = True
    skip_vdi_prime: bool = False
    start_type: str = "gui"


def validate_client_pipeline_order(steps: list[BuildStep], expected: tuple[str, ...]) -> None:
    validate_pipeline_order(steps, expected, vm_label="test clientk")


def run_kali_client_pipeline(steps: list[BuildStep]) -> None:
    run_pipeline(steps, vm_label="test clientk")
