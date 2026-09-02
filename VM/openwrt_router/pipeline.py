"""Small build-pipeline helpers for the test router VM builder."""

from __future__ import annotations

from dataclasses import dataclass

from VM.pipeline_common import BuildStep, BuildStepError, run_pipeline, validate_pipeline_order

__all__ = [
    "BuildStep",
    "BuildStepError",
    "OpenWrtRouterBuildOptions",
    "run_openwrt_router_pipeline",
    "validate_router_pipeline_order",
]


@dataclass(frozen=True)
class OpenWrtRouterBuildOptions:
    start_type: str = "gui"
    connect_serial: bool = True


def validate_router_pipeline_order(steps: list[BuildStep], expected: tuple[str, ...]) -> None:
    validate_pipeline_order(steps, expected, vm_label="test router")


def run_openwrt_router_pipeline(steps: list[BuildStep]) -> None:
    run_pipeline(steps, vm_label="test router")
