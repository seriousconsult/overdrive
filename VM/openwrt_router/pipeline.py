"""Small build-pipeline helpers for the OpenWrt router VM builder."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

__all__ = [
    "BuildStep",
    "OpenWrtRouterBuildOptions",
    "run_openwrt_router_pipeline",
]


@dataclass(frozen=True)
class OpenWrtRouterBuildOptions:
    start_type: str = "gui"
    connect_serial: bool = True


@dataclass(frozen=True)
class BuildStep:
    name: str
    run: Callable[[], None]


def run_openwrt_router_pipeline(steps: list[BuildStep]) -> None:
    for index, step in enumerate(steps, start=1):
        print(f"[overdrive] OpenWrt router stage {index}/{len(steps)}: {step.name}")
        step.run()
