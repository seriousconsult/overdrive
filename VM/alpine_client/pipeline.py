"""Small build-pipeline helpers for the Alpine client VM builder."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

__all__ = [
    "AlpineClientBuildOptions",
    "BuildStep",
    "run_alpine_client_pipeline",
]


@dataclass(frozen=True)
class AlpineClientBuildOptions:
    start_vm: bool = True
    connect_serial: bool = True
    skip_vdi_prime: bool = False


@dataclass(frozen=True)
class BuildStep:
    name: str
    run: Callable[[], None]


def run_alpine_client_pipeline(steps: list[BuildStep]) -> None:
    for index, step in enumerate(steps, start=1):
        print(f"[overdrive] Alpine client stage {index}/{len(steps)}: {step.name}")
        step.run()
