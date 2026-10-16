package com.lxgr.dsu.core;

/**
 * Install/boot-load state machine for the DSU app's MEMD loading flow.
 *
 * <p>States: {@code UNKNOWN} (initial) &rarr; {@code NOT_INSTALLED} &rarr;
 * {@code INSTALLED_STOPPED} &rarr; {@code RUNNING}. Any non-terminal state may
 * move to {@code FAILED} with a reason. {@code FAILED} is terminal: once
 * entered, only {@link #reset()} (back to {@code UNKNOWN}) is accepted; every
 * other transition returns an explicit failure.
 *
 * <p>The value is immutable: each transition returns a {@link Transition}
 * carrying either the next {@code LoadState} or an explicit error. Expected
 * failures never throw.
 */
public final class LoadState {

    /** Lifecycle states. */
    public enum State {
        /** Nothing known yet (initial). */
        UNKNOWN,
        /** Driver/package not installed. */
        NOT_INSTALLED,
        /** Installed but not loaded/running. */
        INSTALLED_STOPPED,
        /** Loaded and running. */
        RUNNING,
        /** Terminal failure; see {@link LoadState#reason()}. */
        FAILED
    }

    /** Result of a transition: either {@code value} or {@code error}. */
    public static final class Transition {
        /** True when the transition was accepted and {@link #value} holds the next state. */
        public final boolean ok;
        /** Next state; null when {@link #ok} is false. */
        public final LoadState value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private Transition(boolean ok, LoadState value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful transition. */
        public static Transition success(LoadState value) {
            return new Transition(true, value, null);
        }

        /** Rejected transition with an explicit reason. */
        public static Transition failure(String error) {
            return new Transition(false, null, error);
        }
    }

    private final State state;
    /** Non-empty only when {@code state == FAILED}. */
    private final String reason;

    private LoadState(State state, String reason) {
        this.state = state;
        this.reason = reason;
    }

    /** Initial state: {@code UNKNOWN} with no reason. */
    public static LoadState initial() {
        return new LoadState(State.UNKNOWN, "");
    }

    /** Current state. */
    public State state() {
        return state;
    }

    /** Failure reason; empty unless {@code state == FAILED}. */
    public String reason() {
        return reason;
    }

    /** True only for {@code FAILED}, from which no forward transition is accepted. */
    public boolean isTerminal() {
        return state == State.FAILED;
    }

    /** Explicit reset from any state back to {@code UNKNOWN} (clears any reason). */
    public Transition reset() {
        return Transition.success(new LoadState(State.UNKNOWN, ""));
    }

    /** {@code UNKNOWN} &rarr; {@code NOT_INSTALLED}. */
    public Transition markNotInstalled() {
        if (state != State.UNKNOWN && state != State.INSTALLED_STOPPED && state != State.RUNNING) {
            return reject("markNotInstalled", "NOT_INSTALLED");
        }
        return Transition.success(new LoadState(State.NOT_INSTALLED, ""));
    }

    /** {@code NOT_INSTALLED} &rarr; {@code INSTALLED_STOPPED}. */
    public Transition markInstalledStopped() {
        if (state != State.NOT_INSTALLED && state != State.UNKNOWN && state != State.RUNNING) {
            return reject("markInstalledStopped", "INSTALLED_STOPPED");
        }
        return Transition.success(new LoadState(State.INSTALLED_STOPPED, ""));
    }

    /** {@code INSTALLED_STOPPED} (or {@code UNKNOWN} probe) &rarr; {@code RUNNING}. */
    public Transition markRunning() {
        if (state != State.INSTALLED_STOPPED && state != State.UNKNOWN) {
            return reject("markRunning", "RUNNING");
        }
        return Transition.success(new LoadState(State.RUNNING, ""));
    }

    /** Terminal failure: permission denied (e.g. root/manager refused the load). */
    public Transition failPermissionDenied(String detail) {
        return failWith("permission denied", detail);
    }

    /** Terminal failure: operation timed out. */
    public Transition failTimeout(String detail) {
        return failWith("timeout", detail);
    }

    /** Terminal failure: device/kernel not supported. */
    public Transition failUnsupportedDevice(String detail) {
        return failWith("unsupported device", detail);
    }

    /** Terminal failure with a caller-supplied reason. */
    public Transition fail(String detail) {
        return failWith("failed", detail);
    }

    private Transition failWith(String kind, String detail) {
        if (state == State.FAILED) {
            return Transition.failure("already terminal FAILED; reset() first (cannot fail again: " + kind + ")");
        }
        if (detail == null || detail.trim().isEmpty()) {
            return Transition.failure("failure detail must be non-empty (" + kind + ")");
        }
        return Transition.success(new LoadState(State.FAILED,
                kind + ": " + detail.trim()));
    }

    private Transition reject(String op, String target) {
        if (state == State.FAILED) {
            return Transition.failure(op + " rejected: terminal FAILED (reason: "
                    + reason + "); reset() first");
        }
        return Transition.failure(op + " rejected: cannot move " + state + " -> " + target);
    }

    @Override
    public String toString() {
        if (state == State.FAILED) {
            return "FAILED(" + reason + ")";
        }
        return state.name();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LoadState)) {
            return false;
        }
        LoadState o = (LoadState) obj;
        return state == o.state && reason.equals(o.reason);
    }

    @Override
    public int hashCode() {
        return 31 * state.hashCode() + reason.hashCode();
    }
}
