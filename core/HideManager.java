package com.lxgr.dsu.core;

/**
 * Explicit user-gated hide state machine for the DSU app's self-hide flow.
 *
 * <p>States: {@code IDLE} (visible, initial) &rarr; {@code HIDE_REQUESTED}
 * (user tapped "Hide app") &rarr; {@code HIDDEN} (driver confirmed) or
 * {@code FAILED} (carries a {@code reason()}). {@code HIDDEN},
 * {@code HIDE_REQUESTED}, and {@code FAILED} return to {@code IDLE} only via
 * {@link #requestUnhide(int)} (user tapped unhide).
 *
 * <p>Hiding happens ONLY through an explicit user action. There is no boot
 * hook, no automatic path, and no no-arg hide method: every transition takes
 * an explicit user-action token as a method argument (pid, hide counts, or
 * failure detail), never ambient state. {@link #confirmHidden(int, int)}
 * verifies the driver's hidden count actually increased ({@code after >
 * before}); a flat count is rejected, never reported as success, so the UI
 * can show a visible confirmation or an actionable error.
 *
 * <p>The value is immutable: each transition returns a {@link Transition}
 * carrying either the next {@code HideManager} or an explicit error. Expected
 * failures never throw.
 */
public final class HideManager {

    /** Lifecycle states. */
    public enum State {
        /** Visible; no hide requested (initial). */
        IDLE,
        /** User tapped "Hide app"; awaiting driver confirmation. */
        HIDE_REQUESTED,
        /** Driver confirmed the pid is hidden. */
        HIDDEN,
        /** Hide attempt failed; see {@link HideManager#reason()}. */
        FAILED
    }

    /** Result of a transition: either {@code value} or {@code error}. */
    public static final class Transition {
        /** True when the transition was accepted and {@link #value} holds the next state. */
        public final boolean ok;
        /** Next state; null when {@link #ok} is false. */
        public final HideManager value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private Transition(boolean ok, HideManager value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful transition. */
        public static Transition success(HideManager value) {
            return new Transition(true, value, null);
        }

        /** Rejected transition with an explicit reason. */
        public static Transition failure(String error) {
            return new Transition(false, null, error);
        }
    }

    private final State state;
    /** Requested/confirmed pid; 0 when {@code state == IDLE} (none). */
    private final int pid;
    /** Non-empty only when {@code state == FAILED}. */
    private final String reason;

    private HideManager(State state, int pid, String reason) {
        this.state = state;
        this.pid = pid;
        this.reason = reason;
    }

    /** Initial state: {@code IDLE} with no pid and no reason. Never hidden at boot. */
    public static HideManager initial() {
        return new HideManager(State.IDLE, 0, "");
    }

    /** Current state. */
    public State state() {
        return state;
    }

    /** Requested pid; 0 when {@code state == IDLE} (none). */
    public int pid() {
        return pid;
    }

    /** Failure reason; empty unless {@code state == FAILED}. */
    public String reason() {
        return reason;
    }

    /** True only when {@code state == HIDDEN} (driver-confirmed). */
    public boolean isHidden() {
        return state == State.HIDDEN;
    }

    /**
     * User tapped "Hide app": {@code IDLE} &rarr; {@code HIDE_REQUESTED}.
     *
     * @param pid explicit user-action token: the pid to hide; must be &gt; 0.
     */
    public Transition requestHide(int pid) {
        if (pid <= 0) {
            return Transition.failure("requestHide rejected: pid must be > 0, got " + pid);
        }
        if (state != State.IDLE) {
            return Transition.failure("requestHide rejected: cannot move " + state
                    + " -> HIDE_REQUESTED (pid " + pid + ")");
        }
        return Transition.success(new HideManager(State.HIDE_REQUESTED, pid, ""));
    }

    /**
     * Driver confirmation: {@code HIDE_REQUESTED} &rarr; {@code HIDDEN}.
     * Verifies the hidden count actually increased; a flat or decreased count
     * is rejected (no silent success) so the UI must show an error.
     *
     * @param hiddenCountBefore explicit user-action token: driver hidden count before the request.
     * @param hiddenCountAfter explicit user-action token: driver hidden count after the request.
     */
    public Transition confirmHidden(int hiddenCountBefore, int hiddenCountAfter) {
        if (state != State.HIDE_REQUESTED) {
            return Transition.failure("confirmHidden rejected: cannot move " + state
                    + " -> HIDDEN (confirm only from HIDE_REQUESTED)");
        }
        if (hiddenCountBefore < 0) {
            return Transition.failure("confirmHidden rejected: hiddenCountBefore must be >= 0, got "
                    + hiddenCountBefore);
        }
        if (hiddenCountAfter < 0) {
            return Transition.failure("confirmHidden rejected: hiddenCountAfter must be >= 0, got "
                    + hiddenCountAfter);
        }
        if (hiddenCountAfter <= hiddenCountBefore) {
            return Transition.failure("confirmHidden rejected: hidden count did not increase "
                    + "(before=" + hiddenCountBefore + " after=" + hiddenCountAfter
                    + "); not hidden");
        }
        return Transition.success(new HideManager(State.HIDDEN, pid, ""));
    }

    /**
     * Hide attempt failed: {@code HIDE_REQUESTED} &rarr; {@code FAILED}.
     *
     * @param detail explicit user-action token: failure detail; must be non-blank.
     */
    public Transition fail(String detail) {
        if (state != State.HIDE_REQUESTED) {
            if (state == State.FAILED) {
                return Transition.failure("fail rejected: already terminal FAILED (reason: "
                        + reason + "); requestUnhide() first");
            }
            return Transition.failure("fail rejected: cannot move " + state + " -> FAILED");
        }
        if (detail == null || detail.trim().isEmpty()) {
            return Transition.failure("fail rejected: failure detail must be non-empty");
        }
        return Transition.success(new HideManager(State.FAILED, pid, detail.trim()));
    }

    /**
     * User tapped unhide: {@code HIDDEN}, {@code HIDE_REQUESTED}, or
     * {@code FAILED} &rarr; {@code IDLE}. Idempotent: calling from
     * {@code IDLE} (pid already visible/absent) is success matching driver
     * unhide-absent-is-success semantics.
     *
     * @param pid explicit user-action token: the pid to unhide; must be &gt; 0.
     */
    public Transition requestUnhide(int pid) {
        if (pid <= 0) {
            return Transition.failure("requestUnhide rejected: pid must be > 0, got " + pid);
        }
        if (state == State.IDLE) {
            return Transition.success(new HideManager(State.IDLE, 0, ""));
        }
        return Transition.success(new HideManager(State.IDLE, 0, ""));
    }

    /** One-line human-readable summary for UI display (visible confirmation). */
    public String describe() {
        StringBuilder out = new StringBuilder();
        out.append("hide[").append(state).append(']');
        if (state == State.IDLE) {
            out.append(" pid=none");
        } else {
            out.append(" pid=").append(pid);
        }
        if (state == State.FAILED) {
            out.append(" reason=").append(reason);
        }
        return out.toString();
    }

    @Override
    public String toString() {
        return describe();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof HideManager)) {
            return false;
        }
        HideManager o = (HideManager) obj;
        return state == o.state && pid == o.pid && reason.equals(o.reason);
    }

    @Override
    public int hashCode() {
        int h = state.hashCode();
        h = 31 * h + pid;
        h = 31 * h + reason.hashCode();
        return h;
    }
}
