package com.lxgr.dsu.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * In-memory module registry over caller-supplied records.
 *
 * <p>The registry performs no file IO: callers list module directories (or
 * parse {@code module.prop} files) themselves and hand {@link Record}s to
 * {@link #upsert}. This keeps the class pure-Java and unit-testable without
 * Android or filesystem access.
 *
 * <p>Validation mirrors {@code tools/lxgr_load.py} ({@code check_module_id} /
 * {@code parse_module_prop}): the id must be filesystem-safe
 * ({@code [A-Za-z0-9._-]+}) and {@code versionCode} is required. As a strict
 * safety superset, the bare traversal ids {@code "."} and {@code ".."} are
 * additionally rejected (they pass the charset check but resolve to parent /
 * self directories when joined to a staging root). Expected failures yield
 * explicit result objects, never exceptions.
 *
 * <p>Duplicate-{@code upsert} semantics: last-write-wins full replace by id.
 * Re-upserting an existing id replaces the stored record outright; no version
 * ordering is consulted on write. {@link #compareVersionCode} is a pure
 * helper for callers (UI sorting, update checks), not a write gate.
 */
public final class ModuleRegistry {

    /** Result of {@link Record#create}: either {@code value} or {@code error}. */
    public static final class RecordResult {
        /** True when creation succeeded and {@link #value} is non-null. */
        public final boolean ok;
        /** The record; null when {@link #ok} is false. */
        public final Record value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private RecordResult(boolean ok, Record value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful result. */
        public static RecordResult success(Record value) {
            return new RecordResult(true, value, null);
        }

        /** Failure result with an explicit reason. */
        public static RecordResult failure(String error) {
            return new RecordResult(false, null, error);
        }
    }

    /** Result of {@link ModuleRegistry#upsert} / {@link ModuleRegistry#remove}. */
    public static final class WriteResult {
        /** True when the write was applied and {@link #record} holds the affected record. */
        public final boolean ok;
        /** Stored record (upsert) or removed record (remove); null when {@link #ok} is false. */
        public final Record record;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private WriteResult(boolean ok, Record record, String error) {
            this.ok = ok;
            this.record = record;
            this.error = error;
        }

        /** Successful result. */
        public static WriteResult success(Record record) {
            return new WriteResult(true, record, null);
        }

        /** Failure result with an explicit reason. */
        public static WriteResult failure(String error) {
            return new WriteResult(false, null, error);
        }
    }

    /** Result of {@link ModuleRegistry#findByHandle}: either {@code value} or {@code error}. */
    public static final class FindResult {
        /** True when a record was found and {@link #value} is non-null. */
        public final boolean ok;
        /** Matching record; null when {@link #ok} is false. */
        public final Record value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private FindResult(boolean ok, Record value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful result. */
        public static FindResult success(Record value) {
            return new FindResult(true, value, null);
        }

        /** Failure result with an explicit reason. */
        public static FindResult failure(String error) {
            return new FindResult(false, null, error);
        }
    }

    /**
     * Immutable module record: directory id, display name, version string,
     * versionCode string, driver handle, and resident flag.
     */
    public static final class Record {
        private final String id;
        private final String name;
        private final String version;
        private final String versionCode;
        private final long handle;
        private final boolean resident;

        private Record(String id, String name, String version,
                       String versionCode, long handle, boolean resident) {
            this.id = id;
            this.name = name;
            this.version = version;
            this.versionCode = versionCode;
            this.handle = handle;
            this.resident = resident;
        }

        /**
         * Validates fields and builds a record. Null yields a failure, not an
         * NPE. {@code name} / {@code version} are optional (null becomes "",
         * surrounding whitespace trimmed, mirroring {@code module.prop}
         * stripping in {@code lxgr_load.py}); {@code id} and
         * {@code versionCode} are required.
         *
         * @param id          module directory id: non-empty,
         *                    {@code [A-Za-z0-9._-]+}, and not {@code "."} / {@code ".."}.
         * @param name        display name; null becomes "".
         * @param version     version string; null becomes "".
         * @param versionCode version code string; required, must be non-blank
         *                    after trimming (mirrors {@code module.prop} requiring
         *                    {@code versionCode=}); any non-blank value is
         *                    representable (ordering is callers' concern via
         *                    {@link ModuleRegistry#compareVersionCode}).
         * @param handle      driver handle; 0 means "none" (fresh/staged, not
         *                    loaded). Must not be negative.
         * @param resident    true when the payload is currently loaded resident.
         */
        public static RecordResult create(String id, String name, String version,
                                          String versionCode, long handle, boolean resident) {
            String idError = validateId(id);
            if (idError != null) {
                return RecordResult.failure(idError);
            }
            if (versionCode == null) {
                return RecordResult.failure("versionCode is null (module.prop requires versionCode=)");
            }
            String code = versionCode.trim();
            if (code.isEmpty()) {
                return RecordResult.failure("versionCode is required (module.prop has no versionCode=)");
            }
            if (handle < 0) {
                return RecordResult.failure("handle must be 0 (none) or positive, got " + handle);
            }
            String cleanName = name == null ? "" : name.trim();
            String cleanVersion = version == null ? "" : version.trim();
            return RecordResult.success(new Record(id, cleanName, cleanVersion, code, handle, resident));
        }

        /**
         * Returns null when {@code id} is valid, else a human-readable reason.
         * Mirrors {@code lxgr_load.py check_module_id} (non-empty, charset
         * {@code [A-Za-z0-9._-]+}) plus rejection of {@code "."} / {@code ".."}.
         */
        public static String validateId(String id) {
            if (id == null) {
                return "id is null (expected filesystem-safe [A-Za-z0-9._-]+)";
            }
            if (id.isEmpty()) {
                return "id is empty (expected filesystem-safe [A-Za-z0-9._-]+)";
            }
            for (int i = 0; i < id.length(); i++) {
                char c = id.charAt(i);
                boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                if (!ok) {
                    return "id is not filesystem-safe (allowed: [A-Za-z0-9._-]): " + id;
                }
            }
            if (id.equals(".") || id.equals("..")) {
                return "id must not be a traversal path (\".\" / \"..\"): " + id;
            }
            return null;
        }

        /** Module directory id. */
        public String id() {
            return id;
        }

        /** Display name ("" when absent). */
        public String name() {
            return name;
        }

        /** Version string ("" when absent). */
        public String version() {
            return version;
        }

        /** Version code string (always non-blank). */
        public String versionCode() {
            return versionCode;
        }

        /** Driver handle; 0 means none. */
        public long handle() {
            return handle;
        }

        /** True when the payload is currently loaded resident. */
        public boolean resident() {
            return resident;
        }

        /** One-line human-readable summary for UI display. */
        public String describe() {
            StringBuilder out = new StringBuilder();
            out.append(id);
            out.append(" \"").append(name).append('"');
            out.append(" v").append(version.isEmpty() ? "<unknown>" : version);
            out.append(" (code ").append(versionCode).append(')');
            if (handle == 0) {
                out.append(" handle=none");
            } else {
                out.append(" handle=0x").append(Long.toHexString(handle));
            }
            out.append(resident ? " resident" : " staged");
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
            if (!(obj instanceof Record)) {
                return false;
            }
            Record o = (Record) obj;
            return id.equals(o.id) && name.equals(o.name) && version.equals(o.version)
                    && versionCode.equals(o.versionCode) && handle == o.handle
                    && resident == o.resident;
        }

        @Override
        public int hashCode() {
            int h = id.hashCode();
            h = 31 * h + name.hashCode();
            h = 31 * h + version.hashCode();
            h = 31 * h + versionCode.hashCode();
            h = 31 * h + (int) (handle ^ (handle >>> 32));
            h = 31 * h + (resident ? 1 : 0);
            return h;
        }
    }

    private final Map<String, Record> byId = new TreeMap<String, Record>();

    /** Empty registry. */
    public ModuleRegistry() {
    }

    /**
     * Inserts or replaces the record for its id (last-write-wins full
     * replace; no version comparison on write). A null record yields a
     * failure, not an NPE.
     */
    public synchronized WriteResult upsert(Record record) {
        if (record == null) {
            return WriteResult.failure("record is null (expected a validated Record)");
        }
        byId.put(record.id(), record);
        return WriteResult.success(record);
    }

    /**
     * Removes the record with {@code id}. An invalid or unknown id yields an
     * explicit failure; the stored (removed) record is returned on success.
     */
    public synchronized WriteResult remove(String id) {
        String idError = Record.validateId(id);
        if (idError != null) {
            return WriteResult.failure("remove rejected: " + idError);
        }
        Record removed = byId.remove(id);
        if (removed == null) {
            return WriteResult.failure("remove rejected: no module with id \"" + id + "\"");
        }
        return WriteResult.success(removed);
    }

    /** All records sorted by id (unmodifiable snapshot). */
    public synchronized List<Record> list() {
        return Collections.unmodifiableList(new ArrayList<Record>(byId.values()));
    }

    /**
     * Finds the record holding {@code handle}. A negative handle yields a
     * failure; handle 0 (none) may be queried and simply reports not-found
     * unless a record was stored with handle 0. When several records share
     * a handle (caller error; handles should be unique), the smallest-id
     * holder is returned.
     */
    public synchronized FindResult findByHandle(long handle) {
        if (handle < 0) {
            return FindResult.failure("handle must be 0 (none) or positive, got " + handle);
        }
        for (Record record : byId.values()) {
            if (record.handle() == handle) {
                return FindResult.success(record);
            }
        }
        return FindResult.failure("no module with handle "
                + (handle == 0 ? "none (0)" : "0x" + Long.toHexString(handle)));
    }

    /** Number of stored records. */
    public synchronized int size() {
        return byId.size();
    }

    /**
     * Orders two versionCode strings: numeric comparison (via
     * {@code Long.parseLong}) when both parse, else lexical
     * {@code String.compareTo}. Null normalizes to "" (never throws).
     * Overflowing {@code long} range, empty, or alphanumeric codes (e.g.
     * {@code "1.2b"}) fall back to lexical order. Returns
     * negative/zero/positive as {@code a} is older/equal/newer.
     */
    public static int compareVersionCode(String a, String b) {
        String x = a == null ? "" : a.trim();
        String y = b == null ? "" : b.trim();
        Long nx = parseLongOrNull(x);
        Long ny = parseLongOrNull(y);
        if (nx != null && ny != null) {
            return nx.compareTo(ny);
        }
        return x.compareTo(y);
    }

    private static Long parseLongOrNull(String s) {
        try {
            return Long.valueOf(s);
        } catch (NumberFormatException notNumeric) {
            return null;
        }
    }
}
