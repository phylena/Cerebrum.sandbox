"""Sandbox lifecycle state machine. Every state change goes through `check`."""
from enum import StrEnum


class State(StrEnum):
    PENDING = "pending"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    TERMINATED = "terminated"


class InvalidTransition(Exception):
    pass


TRANSITIONS: dict[State, set[State]] = {
    State.PENDING: {State.PROVISIONING, State.FAILED, State.TERMINATED},
    State.PROVISIONING: {State.RUNNING, State.STOPPED, State.FAILED, State.TERMINATED},
    State.RUNNING: {State.PAUSED, State.STOPPING, State.FAILED, State.TERMINATED},
    State.PAUSED: {State.RUNNING, State.STOPPING, State.FAILED, State.TERMINATED},
    State.STOPPING: {State.STOPPED, State.FAILED, State.TERMINATED},
    State.STOPPED: {State.PROVISIONING, State.RUNNING, State.FAILED, State.TERMINATED},
    State.FAILED: {State.TERMINATED},
    State.TERMINATED: set(),
}


def check(current: State, target: State) -> None:
    if target not in TRANSITIONS[current]:
        raise InvalidTransition(f"cannot go from '{current}' to '{target}'")
