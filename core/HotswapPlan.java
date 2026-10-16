package com.lxgr.dsu.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Hotswap plan mirroring {@code tools/lxgr_load.py} {@code cmd_hotswap}
 * semantics: load the new payload first (install via the MEMD driver), run
 * its entry point when one is given, then unload the old resident handle.
 *
 * <p>Ordered steps: {@code LOAD_NEW} &rarr; {@code RUN_ENTRY} (only when
 * {@code entry} is non-empty) &rarr; {@code UNLOAD_OLD} (only when
 * {@code oldHandle != 0}, where 0 means "no previous install").
 *
 * <p>Validation mirrors the driver's {@code ioctl_load}/{@code ioctl_unload}
 * guards in {@code lxgr_load.py}: path must be absolute and fit in 255 UTF-8
 * bytes, entry must fit in 63 UTF-8 bytes with no slashes, and an unload
 * handle must be nonzero. Expected failures yield a {@link PlanResult} error,
 * never an exception.
 */
public final class HotswapPlan {

    /** Ordered plan steps. */
    public enum Step {
        /** Load the new payload via the driver (install). */
        LOAD_NEW,
        /** Call the payload entry symbol after load (skipped when entry is empty). */
        RUN_ENTRY,
        /** Unload the previous resident handle (skipped when oldHandle is 0). */
        UNLOAD_OLD
    }

    /** Result of {@link #plan}: either {@code value} or {@code error}. */
    public static final class PlanResult {
        /** True when planning succeeded and {@link #value} is non-null. */
        public final boolean ok;
        /** The plan; null when {@link #ok} is false. */
        public final HotswapPlan value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private PlanResult(boolean ok, HotswapPlan value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful result. */
        public static PlanResult success(HotswapPlan value) {
            return new PlanResult(true, value, null);
        }

        /** Failure result with an explicit reason. */
        public static PlanResult failure(String error) {
            return new PlanResult(false, null, error);
        }
    }

    /** Max path bytes (driver {@code path[256]} incl. NUL). */
    public static final int MAX_PATH_BYTES = 255;
    /** Max entry bytes (driver {@code entry[64]} incl. NUL). */
    public static final int MAX_ENTRY_BYTES = 63;

    private final long oldHandle;
    private final String newPath;
    private final String entry;
    private final boolean su;
    private final List<Step> steps;

    private HotswapPlan(long oldHandle, String newPath, String entry,
                        boolean su, List<Step> steps) {
        this.oldHandle = oldHandle;
        this.newPath = newPath;
        this.entry = entry;
        this.su = su;
        this.steps = Collections.unmodifiableList(steps);
    }

    /**
     * Builds the ordered step list.
     *
     * @param oldHandle previous resident handle; 0 means none (fresh install,
     *                  no UNLOAD_OLD step). Must not be negative.
     * @param newPath   staged payload path; must be absolute, NUL-free, and
     *                  fit in 255 UTF-8 bytes. Null yields a failure, not an NPE.
     * @param entry     payload entry symbol; null/empty means "skip"
     *                  (no RUN_ENTRY step). Otherwise must be NUL-free, contain
     *                  no slash, and fit in 63 UTF-8 bytes.
     * @param su        true to load via the su-window variant
     *                  ({@code loadsosutoapp}), false for {@code loadsotoapp}.
     */
    public static PlanResult plan(long oldHandle, String newPath, String entry, boolean su) {
        if (oldHandle < 0) {
            return PlanResult.failure("old handle must be 0 (none) or positive, got " + oldHandle);
        }
        if (newPath == null) {
            return PlanResult.failure("new path is null (expected absolute path)");
        }
        if (newPath.isEmpty()) {
            return PlanResult.failure("new path is empty (expected absolute path)");
        }
        if (!newPath.startsWith("/")) {
            return PlanResult.failure("new path must be absolute: " + newPath);
        }
        if (newPath.indexOf('\0') >= 0) {
            return PlanResult.failure("new path must not contain NUL bytes");
        }
        int pathBytes = newPath.getBytes(StandardCharsets.UTF_8).length;
        if (pathBytes > MAX_PATH_BYTES) {
            return PlanResult.failure("new path exceeds " + MAX_PATH_BYTES
                    + " bytes (" + pathBytes + " bytes)");
        }
        String entryNorm = entry == null ? "" : entry;
        if (entryNorm.indexOf('\0') >= 0) {
            return PlanResult.failure("entry must not contain NUL bytes");
        }
        if (!entryNorm.isEmpty()) {
            if (entryNorm.indexOf('/') >= 0) {
                return PlanResult.failure("entry must not contain '/': " + entryNorm);
            }
            int entryBytes = entryNorm.getBytes(StandardCharsets.UTF_8).length;
            if (entryBytes > MAX_ENTRY_BYTES) {
                return PlanResult.failure("entry exceeds " + MAX_ENTRY_BYTES
                        + " bytes (" + entryBytes + " bytes)");
            }
        }
        List<Step> steps = new ArrayList<Step>();
        steps.add(Step.LOAD_NEW);
        if (!entryNorm.isEmpty()) {
            steps.add(Step.RUN_ENTRY);
        }
        if (oldHandle != 0) {
            steps.add(Step.UNLOAD_OLD);
        }
        return PlanResult.success(new HotswapPlan(oldHandle, newPath, entryNorm, su, steps));
    }

    /** Previous resident handle; 0 means none. */
    public long oldHandle() {
        return oldHandle;
    }

    /** Staged payload path. */
    public String newPath() {
        return newPath;
    }

    /** Entry symbol; empty means "skip entry call". */
    public String entry() {
        return entry;
    }

    /** True for the su-window load variant. */
    public boolean su() {
        return su;
    }

    /** Ordered steps (unmodifiable). */
    public List<Step> steps() {
        return steps;
    }

    /** One-line human-readable summary for UI display. */
    public String describe() {
        StringBuilder out = new StringBuilder();
        out.append(su ? "hotswap(su) " : "hotswap ");
        out.append(newPath);
        out.append(" entry=").append(entry.isEmpty() ? "<skip>" : entry);
        if (oldHandle == 0) {
            out.append(" old=none");
        } else {
            out.append(" old=0x").append(Long.toHexString(oldHandle));
        }
        out.append(" steps=").append(steps);
        return out.toString();
    }

    @Override
    public String toString() {
        return describe();
    }
}
