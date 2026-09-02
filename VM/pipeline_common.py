"""Shared build-pipeline primitives for lab VM builders."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable

__all__ = [
    "BuildStep",
    "BuildStepError",
    "run_pipeline",
    "validate_pipeline_order",
]

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

    def __init__(self, *, vm_label: str, step: BuildStep, elapsed_s: float, original: BaseException):
        super().__init__(
            f"{vm_label} step {step.id!r} ({step.name}) failed after {elapsed_s:.1f}s: {original}"
        )
        self.vm_label = vm_label
        self.step = step
        self.elapsed_s = elapsed_s
        self.original = original


def validate_pipeline_order(steps: list[BuildStep], expected: tuple[str, ...], *, vm_label: str) -> None:
    actual = tuple(step.id for step in steps)
    if actual != expected:
        raise RuntimeError(
            f"{vm_label} pipeline order changed unexpectedly.\n"
            f"Expected: {', '.join(expected)}\n"
            f"Actual:   {', '.join(actual)}"
        )


def run_pipeline(steps: list[BuildStep], *, vm_label: str) -> None:
    """Run build steps in order with consistent logging and failure reporting."""
    total_steps = len(steps)
    print(f"[overdrive] {vm_label} pipeline: {total_steps} stage(s)")
    for index, step in enumerate(steps, start=1):
        if not step.is_enabled():
            print(f"[overdrive] {vm_label} stage {index}/{total_steps} skip [{step.id}]: {step.name}")
            continue

        print(f"[overdrive] {vm_label} stage {index}/{total_steps} [{step.id}]: {step.name}")
        if step.description:
            print(f"[overdrive]   {step.description}")
        started = time.monotonic()
        try:
            step.run()
        except Exception as exc:
            elapsed = time.monotonic() - started
            print(f"[overdrive] {vm_label} stage FAILED [{step.id}] after {elapsed:.1f}s")
            raise BuildStepError(vm_label=vm_label, step=step, elapsed_s=elapsed, original=exc) from exc
        elapsed = time.monotonic() - started
        print(f"[overdrive] {vm_label} stage done [{step.id}] ({elapsed:.1f}s)")
