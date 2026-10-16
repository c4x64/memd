package com.lxgr.dsu;

/**
 * Plain-Java view model for one MEMD/Zygisk-scheme module row.
 *
 * <p>No Android imports: this class is unit-testable with plain javac/JUnit.
 * It carries data only — no I/O, no processes, no privileged operations.
 */
public final class ModuleListItem {

    /** Residency state of the module as last recorded. */
    public enum State {
        UNKNOWN,
        RESIDENT,
        NOT_INSTALLED,
        ERROR
    }

    private final String id;
    private final String name;
    private final String version;
    private final int versionCode;
    private final State state;
    private final String message;

    /**
     * @param id          stable module id (non-null; empty allowed but discouraged).
     * @param name        display name (non-null).
     * @param version     display version string (non-null).
     * @param versionCode numeric version code.
     * @param state       residency state (null maps to UNKNOWN).
     * @param message     detail message; meaningful only for ERROR, otherwise ignored
     *                    except for storage (null maps to "").
     */
    public ModuleListItem(String id, String name, String version, int versionCode,
                          State state, String message) {
        this.id = id == null ? "" : id;
        this.name = name == null ? "" : name;
        this.version = version == null ? "" : version;
        this.versionCode = versionCode;
        this.state = state == null ? State.UNKNOWN : state;
        this.message = message == null ? "" : message;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    public int getVersionCode() {
        return versionCode;
    }

    public State getState() {
        return state;
    }

    /**
     * Detail message (e.g. load/install failure). Only meaningful when
     * {@link #getState()} is {@link State#ERROR}; empty otherwise.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Render-ready one-line summary for the module list row.
     * Example: {@code "Foo (foo.id) — v1.0 (1) — RESIDENT"} with
     * {@code ": message"} appended for ERROR when a message is present.
     */
    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append(" (").append(id).append(")");
        sb.append(" — v").append(version).append(" (").append(versionCode).append(")");
        sb.append(" — ").append(state.name());
        if (state == State.ERROR && !message.isEmpty()) {
            sb.append(": ").append(message);
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return toSummary();
    }
}
