"""Small build-pipeline helpers for the test client VM builder."""

from __future__ import annotations

from dataclasses import dataclass

from VM.pipeline_common import BuildStep, BuildStepError, run_pipeline, validate_pipeline_order

__all__ = [
    "AlpineClientBuildOptions",
    "BuildStep",
    "BuildStepError",
    "run_alpine_client_pipeline",
    "validate_client_pipeline_order",
]


@dataclass(frozen=True)
class AlpineClientBuildOptions:
    start_vm: bool = True
    connect_serial: bool = True
    skip_disk_prime: bool = False
    start_type: str = "gui"


def validate_client_pipeline_order(steps: list[BuildStep], expected: tuple[str, ...]) -> None:
    validate_pipeline_order(steps, expected, vm_label="test clienta")


def run_alpine_client_pipeline(steps: list[BuildStep]) -> None:
    run_pipeline(steps, vm_label="test clienta")
