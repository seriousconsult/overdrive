"""Small build-pipeline helpers for the test client VM builder."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable

__all__ = [
    "AlpineClientBuildOptions",
    "BuildStep",
    "BuildStepError",
    "run_alpine_client_pipeline",
]


@dataclass(frozen=True)
class AlpineClientBuildOptions:
    start_vm: bool = True
    connect_serial: bool = True
    skip_vdi_prime: bool = False
    start_type: str = "gui"


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
            f"test client step {step.id!r} ({step.name}) failed "
            f"after {elapsed_s:.1f}s: {original}"
        )
        self.step = step
        self.elapsed_s = elapsed_s
        self.original = original


def run_alpine_client_pipeline(steps: list[BuildStep]) -> None:
    total_steps = len(steps)
    for index, step in enumerate(steps, start=1):
        if not step.is_enabled():
            print(f"[overdrive] test client stage {index}/{total_steps} skip [{step.id}]: {step.name}")
            continue

        print(f"[overdrive] test client stage {index}/{total_steps} [{step.id}]: {step.name}")
        if step.description:
            print(f"[overdrive]   {step.description}")
        started = time.monotonic()
        try:
            step.run()
        except Exception as exc:
            elapsed = time.monotonic() - started
            print(f"[overdrive] test client stage FAILED [{step.id}] after {elapsed:.1f}s")
            raise BuildStepError(step, elapsed, exc) from exc
        elapsed = time.monotonic() - started
        print(f"[overdrive] test client stage done [{step.id}] ({elapsed:.1f}s)")
