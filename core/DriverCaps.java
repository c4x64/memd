package com.lxgr.dsu.core;

/**
 * Models the {@code MEMD_IOCTL_VERSION} surface ({@code struct
 * memd_version_cmd}): wire ABI tag, driver version triple, capability flags,
 * and learned-generation index.
 *
 * <p>Constants mirror {@code client.h} / {@code kmod/memd/ioctl/memd_ioctl.h}:
 * {@code MEMD_ABI_VERSION == 1}, {@code MEMD_F_BOOTSTRAP_DONE == 1},
 * {@code MEMD_F_LEARNED_OFFSETS == 2}. {@code gen} is the learned generation
 * index, or -1 when unknown.
 *
 * <p>Construction validates via {@link #create}; expected failures yield a
 * {@link CapsResult} error, never an exception.
 */
public final class DriverCaps {

    /** Wire ABI this app speaks. Must equal the driver's ABI for compat. */
    public static final int EXPECTED_ABI = 1;
    /** Flag: driver completed symbol bootstrap. */
    public static final int FLAG_BOOTSTRAP_DONE = 1;
    /** Flag: driver learned runtime offsets. */
    public static final int FLAG_LEARNED_OFFSETS = 2;
    /** Generation value meaning "unknown". */
    public static final int GEN_UNKNOWN = -1;

    /** Result of {@link #create}: either {@code value} or {@code error}. */
    public static final class CapsResult {
        /** True when creation succeeded and {@link #value} is non-null. */
        public final boolean ok;
        /** Capability record; null when {@link #ok} is false. */
        public final DriverCaps value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private CapsResult(boolean ok, DriverCaps value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful result. */
        public static CapsResult success(DriverCaps value) {
            return new CapsResult(true, value, null);
        }

        /** Failure result with an explicit reason. */
        public static CapsResult failure(String error) {
            return new CapsResult(false, null, error);
        }
    }

    private final int abi;
    private final int major;
    private final int minor;
    private final int patch;
    private final int flags;
    private final int gen;

    private DriverCaps(int abi, int major, int minor, int patch, int flags, int gen) {
        this.abi = abi;
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.flags = flags;
        this.gen = gen;
    }

    /**
     * Validates raw fields and builds a record. Rejects negative ABI/version
     * components, negative flags, and {@code gen} values below -1. Any ABI
     * value is representable (a mismatch simply reports incompatible via
     * {@link #isCompatible()} rather than failing validation).
     */
    public static CapsResult create(int abi, int major, int minor, int patch,
                                    int flags, int gen) {
        if (abi < 0) {
            return CapsResult.failure("abi must be >= 0, got " + abi);
        }
        if (major < 0) {
            return CapsResult.failure("major must be >= 0, got " + major);
        }
        if (minor < 0) {
            return CapsResult.failure("minor must be >= 0, got " + minor);
        }
        if (patch < 0) {
            return CapsResult.failure("patch must be >= 0, got " + patch);
        }
        if (flags < 0) {
            return CapsResult.failure("flags must be >= 0, got " + flags);
        }
        if (gen < GEN_UNKNOWN) {
            return CapsResult.failure("gen must be -1 (unknown) or >= 0, got " + gen);
        }
        return CapsResult.success(new DriverCaps(abi, major, minor, patch, flags, gen));
    }

    public int abi() {
        return abi;
    }

    public int major() {
        return major;
    }

    public int minor() {
        return minor;
    }

    public int patch() {
        return patch;
    }

    public int flags() {
        return flags;
    }

    /** Learned generation index, or -1 when unknown. */
    public int gen() {
        return gen;
    }

    /** True when the bootstrap-done flag is set. */
    public boolean isBootstrapDone() {
        return (flags & FLAG_BOOTSTRAP_DONE) != 0;
    }

    /** True when the learned-offsets flag is set. */
    public boolean hasLearnedOffsets() {
        return (flags & FLAG_LEARNED_OFFSETS) != 0;
    }

    /** Compatible when the wire ABI matches ({@code abi == 1}). */
    public boolean isCompatible() {
        return abi == EXPECTED_ABI;
    }

    /**
     * One-line human-readable summary for UI display, e.g.
     * {@code "driver v1.0.0 (abi 1, compatible) flags=[BOOTSTRAP_DONE|LEARNED_OFFSETS] gen=3"}.
     * Unknown flag bits are listed numerically so future drivers stay visible.
     */
    public String describe() {
        StringBuilder out = new StringBuilder();
        out.append("driver v").append(major).append('.').append(minor).append('.').append(patch);
        out.append(" (abi ").append(abi);
        if (isCompatible()) {
            out.append(", compatible");
        } else {
            out.append(", INCOMPATIBLE: expected abi ").append(EXPECTED_ABI);
        }
        out.append(") flags=[").append(flagNames()).append(']');
        out.append(' ');
        if (gen == GEN_UNKNOWN) {
            out.append("gen=unknown");
        } else {
            out.append("gen=").append(gen);
        }
        return out.toString();
    }

    private String flagNames() {
        StringBuilder names = new StringBuilder();
        if (isBootstrapDone()) {
            names.append("BOOTSTRAP_DONE");
        }
        if (hasLearnedOffsets()) {
            if (names.length() > 0) {
                names.append('|');
            }
            names.append("LEARNED_OFFSETS");
        }
        int known = FLAG_BOOTSTRAP_DONE | FLAG_LEARNED_OFFSETS;
        int unknown = flags & ~known;
        if (unknown != 0) {
            if (names.length() > 0) {
                names.append('|');
            }
            names.append("unknown(0x").append(Integer.toHexString(unknown)).append(')');
        }
        if (names.length() == 0) {
            names.append("none");
        }
        return names.toString();
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
        if (!(obj instanceof DriverCaps)) {
            return false;
        }
        DriverCaps o = (DriverCaps) obj;
        return abi == o.abi && major == o.major && minor == o.minor
                && patch == o.patch && flags == o.flags && gen == o.gen;
    }

    @Override
    public int hashCode() {
        int h = abi;
        h = 31 * h + major;
        h = 31 * h + minor;
        h = 31 * h + patch;
        h = 31 * h + flags;
        h = 31 * h + gen;
        return h;
    }
}
