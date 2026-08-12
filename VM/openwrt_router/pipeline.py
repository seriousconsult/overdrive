"""Small build-pipeline helpers for the OpenWrt router VM builder."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable

__all__ = [
    "BuildStep",
    "BuildStepError",
    "OpenWrtRouterBuildOptions",
    "run_openwrt_router_pipeline",
]


@dataclass(frozen=True)
class OpenWrtRouterBuildOptions:
    start_type: str = "gui"
    connect_serial: bool = True


StepEnabled = bool | Callable[[], bool]


@dataclass(frozen=True)
class BuildStep:
    id: str
    name: str
    run: Callable[[], None]
    enabled: StepEnabled = True
    description: str = ""

    def is_enabled(self) -> bool:
        if callable(self.enabled):
            return bool(self.enabled())
        return bool(self.enabled)


class BuildStepError(RuntimeError):
    """Raised when a named build-pipeline step fails."""

    def __init__(self, step: BuildStep, elapsed_s: float, original: BaseException):
        super().__init__(
            f"OpenWrt router step {step.id!r} ({step.name}) failed "
            f"after {elapsed_s:.1f}s: {original}"
        )
        self.step = step
        self.elapsed_s = elapsed_s
        self.original = original


def run_openwrt_router_pipeline(steps: list[BuildStep]) -> None:
    total_steps = len(steps)
    for index, step in enumerate(steps, start=1):
        if not step.is_enabled():
            print(f"[overdrive] OpenWrt router stage {index}/{total_steps} skip [{step.id}]: {step.name}")
            continue

        print(f"[overdrive] OpenWrt router stage {index}/{total_steps} [{step.id}]: {step.name}")
        if step.description:
            print(f"[overdrive]   {step.description}")
        started = time.monotonic()
        try:
            step.run()
        except Exception as exc:
            elapsed = time.monotonic() - started
            print(f"[overdrive] OpenWrt router stage FAILED [{step.id}] after {elapsed:.1f}s")
            raise BuildStepError(step, elapsed, exc) from exc
        elapsed = time.monotonic() - started
        print(f"[overdrive] OpenWrt router stage done [{step.id}] ({elapsed:.1f}s)")
