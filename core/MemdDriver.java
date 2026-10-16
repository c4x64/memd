package com.lxgr.dsu.core;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Single decision point for how userspace reaches the MEMD driver, plus
 * driver call specs as data for UI forms and contract tests.
 *
 * <p>Transport policy (in priority order): {@code JNI_DIRECT} when the JNI
 * bridge ({@code Userspace App/native/memd_bridge.c},
 * {@code com.lxgr.dsu.MemdDriver}) is available, else {@code ROOT_SHELL}
 * when a root shell fallback is available, else {@code UNAVAILABLE} with a
 * reason naming exactly what is missing. See {@link #selectTransport}.
 *
 * <p>Call specs (see {@link #callSpec}) pin the six UI-reachable driver
 * operations and their required/optional argument names, grounded in
 * repo-root {@code client.h} via {@code Userspace App/INTEGRATION.md} and
 * the JNI signatures in {@code Userspace App/native/README.md}:
 * {@code version} / {@code learnStatus} are arg-free queries;
 * {@code hide} / {@code unhide} take {@code pid};
 * {@code loadso} takes {@code pid} + {@code path} with optional
 * {@code entry} (empty means dlopen-only), {@code su} (nr 39 su-window
 * variant vs nr 38), and {@code ephemeral} (dlclose after init);
 * {@code unload} takes {@code pid} + {@code handle}. The specs describe
 * argument shapes only; they perform no driver I/O and no hiding.
 *
 * <p>All public entry points return explicit result/selection values;
 * nothing throws for expected failures (null/unknown op names, missing
 * transports).
 */
public final class MemdDriver {

    /** Transport policy, in preference order. */
    public enum Transport {
        /** Direct ioctl path via the JNI bridge. Preferred when present. */
        JNI_DIRECT,
        /** Root shell fallback (e.g. via the installed root manager). */
        ROOT_SHELL,
        /** No usable transport; see the selection reason for what is missing. */
        UNAVAILABLE
    }

    /** Result of {@link #selectTransport}: the chosen transport plus a reason. */
    public static final class Selection {
        private final Transport transport;
        private final String reason;

        private Selection(Transport transport, String reason) {
            this.transport = transport;
            this.reason = reason;
        }

        /** The chosen transport. */
        public Transport transport() {
            return transport;
        }

        /** Human-readable reason; never null or empty. */
        public String reason() {
            return reason;
        }

        /** True unless {@link Transport#UNAVAILABLE}. */
        public boolean isAvailable() {
            return transport != Transport.UNAVAILABLE;
        }

        /** One-line summary for UI display, e.g. {@code "transport=JNI_DIRECT: ..."} */
        public String describe() {
            return "transport=" + transport + ": " + reason;
        }

        @Override
        public String toString() {
            return describe();
        }
    }

    /** Result of {@link #requireTransport}: either {@code value} or {@code error}. */
    public static final class TransportResult {
        /** True when a usable transport was selected. */
        public final boolean ok;
        /** The selection; null when {@link #ok} is false. */
        public final Selection value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private TransportResult(boolean ok, Selection value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful result. */
        public static TransportResult success(Selection value) {
            return new TransportResult(true, value, null);
        }

        /** Failure result with an explicit reason. */
        public static TransportResult failure(String error) {
            return new TransportResult(false, null, error);
        }
    }

    /**
     * Chooses the transport. JNI is preferred whenever it is available,
     * otherwise the root shell when it is available, otherwise
     * {@code UNAVAILABLE} with a message naming every missing piece (the
     * JNI bridge and the root shell).
     */
    public static Selection selectTransport(boolean jniAvailable, boolean rootAvailable) {
        if (jniAvailable) {
            return new Selection(Transport.JNI_DIRECT,
                    "JNI bridge available; using direct ioctl path");
        }
        if (rootAvailable) {
            return new Selection(Transport.ROOT_SHELL,
                    "JNI bridge unavailable; using root shell fallback");
        }
        return new Selection(Transport.UNAVAILABLE,
                "no transport: JNI bridge unavailable and root shell unavailable");
    }

    /**
     * Same choice as {@link #selectTransport}, but a missing transport is
     * reported as an explicit {@link TransportResult} failure instead of an
     * {@code UNAVAILABLE} selection. Never throws for expected failures.
     */
    public static TransportResult requireTransport(boolean jniAvailable, boolean rootAvailable) {
        Selection selection = selectTransport(jniAvailable, rootAvailable);
        if (!selection.isAvailable()) {
            return TransportResult.failure(selection.reason());
        }
        return TransportResult.success(selection);
    }

    /** Canonical op names, in UI order. */
    private static final List<String> KNOWN_OPS = Collections.unmodifiableList(
            Arrays.asList("version", "learnStatus", "hide", "unhide", "loadso", "unload"));

    /** Canonical op names, in UI order (unmodifiable). */
    public static List<String> knownOps() {
        return KNOWN_OPS;
    }

    /** Argument shape for one driver operation: op name plus field names. */
    public static final class CallSpec {
        private final String op;
        private final List<String> requiredFields;
        private final List<String> optionalFields;

        private CallSpec(String op, List<String> requiredFields, List<String> optionalFields) {
            this.op = op;
            this.requiredFields = Collections.unmodifiableList(requiredFields);
            this.optionalFields = Collections.unmodifiableList(optionalFields);
        }

        /** Op name, exactly as passed to {@link MemdDriver#callSpec}. */
        public String op() {
            return op;
        }

        /** Required argument names (unmodifiable). */
        public List<String> requiredFields() {
            return requiredFields;
        }

        /** Optional argument names (unmodifiable). */
        public List<String> optionalFields() {
            return optionalFields;
        }

        /** One-line summary for UI display, e.g. {@code "loadso(pid, path, [entry, su, ephemeral])"}. */
        public String describe() {
            StringBuilder out = new StringBuilder();
            out.append(op).append('(');
            boolean first = true;
            for (String field : requiredFields) {
                if (!first) {
                    out.append(", ");
                }
                out.append(field);
                first = false;
            }
            if (!optionalFields.isEmpty()) {
                if (!first) {
                    out.append(", ");
                }
                out.append('[');
                boolean innerFirst = true;
                for (String field : optionalFields) {
                    if (!innerFirst) {
                        out.append(", ");
                    }
                    out.append(field);
                    innerFirst = false;
                }
                out.append(']');
            }
            out.append(')');
            return out.toString();
        }

        @Override
        public String toString() {
            return describe();
        }
    }

    /** Result of {@link #callSpec}: either {@code value} or {@code error}. */
    public static final class SpecResult {
        /** True when the op name is known and {@link #value} is non-null. */
        public final boolean ok;
        /** The call spec; null when {@link #ok} is false. */
        public final CallSpec value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private SpecResult(boolean ok, CallSpec value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful result. */
        public static SpecResult success(CallSpec value) {
            return new SpecResult(true, value, null);
        }

        /** Failure result with an explicit reason. */
        public static SpecResult failure(String error) {
            return new SpecResult(false, null, error);
        }
    }

    /**
     * Returns the expected argument shape for one of the six driver
     * operations ({@code version}, {@code learnStatus}, {@code hide},
     * {@code unhide}, {@code loadso}, {@code unload}). Unknown, null, or
     * blank names yield an explicit failure listing the known ops; never
     * throws.
     *
     * <p>{@code version} and {@code learnStatus} are arg-free queries (the
     * driver fd is transport-supplied, not a form field). {@code hide} and
     * {@code unhide} require {@code pid} (positive target id, per
     * {@code struct memd_hide_proc_cmd}). {@code loadso} requires
     * {@code pid} and {@code path} (absolute, per
     * {@code struct memd_loadso_cmd}); {@code entry} (empty = dlopen-only),
     * {@code su}, and {@code ephemeral} are optional. {@code unload}
     * requires {@code pid} and {@code handle} (per
     * {@code struct memd_loadso_unload_cmd}).
     */
    public static SpecResult callSpec(String opName) {
        if (opName == null || opName.isEmpty()) {
            return SpecResult.failure("unknown op: "
                    + (opName == null ? "null" : "empty")
                    + " (expected one of " + KNOWN_OPS + ")");
        }
        if ("version".equals(opName)) {
            return SpecResult.success(new CallSpec(opName,
                    Collections.<String>emptyList(), Collections.<String>emptyList()));
        }
        if ("learnStatus".equals(opName)) {
            return SpecResult.success(new CallSpec(opName,
                    Collections.<String>emptyList(), Collections.<String>emptyList()));
        }
        if ("hide".equals(opName)) {
            return SpecResult.success(new CallSpec(opName,
                    Arrays.asList("pid"), Collections.<String>emptyList()));
        }
        if ("unhide".equals(opName)) {
            return SpecResult.success(new CallSpec(opName,
                    Arrays.asList("pid"), Collections.<String>emptyList()));
        }
        if ("loadso".equals(opName)) {
            return SpecResult.success(new CallSpec(opName,
                    Arrays.asList("pid", "path"),
                    Arrays.asList("entry", "su", "ephemeral")));
        }
        if ("unload".equals(opName)) {
            return SpecResult.success(new CallSpec(opName,
                    Arrays.asList("pid", "handle"), Collections.<String>emptyList()));
        }
        return SpecResult.failure("unknown op: " + opName
                + " (expected one of " + KNOWN_OPS + ")");
    }

    private MemdDriver() {
    }
}
