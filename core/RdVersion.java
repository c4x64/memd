package com.lxgr.dsu.core;

/**
 * Parses, validates, and compares DSU release versions of the form
 * {@code RD-YYYYMMDD-HHMM[-seq]} (see Userspace App/AGENTS.md: timestamp is
 * UTC, 24-hour clock; {@code -seq} is appended only for additional releases
 * within the same minute, e.g. {@code RD-20261016-0614-2}).
 *
 * <p>Invalid input never throws: {@link #parse(String)} returns an explicit
 * {@link ParseResult} carrying either the value or a human-readable error.
 */
public final class RdVersion implements Comparable<RdVersion> {

    /** Result of {@link #parse(String)}: either {@code value} or {@code error}. */
    public static final class ParseResult {
        /** True when parsing succeeded and {@link #value} is non-null. */
        public final boolean ok;
        /** Parsed version; null when {@link #ok} is false. */
        public final RdVersion value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private ParseResult(boolean ok, RdVersion value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful result. */
        public static ParseResult success(RdVersion value) {
            return new ParseResult(true, value, null);
        }

        /** Failure result with an explicit reason. */
        public static ParseResult failure(String error) {
            return new ParseResult(false, null, error);
        }
    }

    private final int year;
    private final int month;
    private final int day;
    private final int hour;
    private final int minute;
    /** Optional sequence suffix; 0 means absent (sorts as 1, before any -seq). */
    private final int seq;
    private final String canonical;

    private RdVersion(int year, int month, int day, int hour, int minute, int seq) {
        this.year = year;
        this.month = month;
        this.day = day;
        this.hour = hour;
        this.minute = minute;
        this.seq = seq;
        String base = String.format("RD-%04d%02d%02d-%02d%02d",
                year, month, day, hour, minute);
        this.canonical = seq > 0 ? base + "-" + seq : base;
    }

    /**
     * Parses {@code text} as an {@code RD-YYYYMMDD-HHMM[-seq]} version.
     * Never throws for malformed input; returns {@link ParseResult#failure}
     * with a reason instead. A null reference yields a failure (not an NPE).
     */
    public static ParseResult parse(String text) {
        if (text == null) {
            return ParseResult.failure("version is null (expected RD-YYYYMMDD-HHMM[-seq])");
        }
        String s = text.trim();
        if (s.isEmpty()) {
            return ParseResult.failure("version is empty (expected RD-YYYYMMDD-HHMM[-seq])");
        }
        // Base form is exactly 16 chars: "RD-" + 8 date digits + "-" + 4 time digits.
        if (!s.startsWith("RD-")) {
            return ParseResult.failure("version must start with \"RD-\": " + s);
        }
        String rest = s.substring(3);
        // Split optional -seq: date/time parts contain exactly one '-'.
        int dash = rest.indexOf('-');
        if (dash < 0) {
            return ParseResult.failure("version must be RD-YYYYMMDD-HHMM[-seq]: " + s);
        }
        String date = rest.substring(0, dash);
        String afterDash = rest.substring(dash + 1);
        String time;
        String seqText = null;
        int secondDash = afterDash.indexOf('-');
        if (secondDash < 0) {
            time = afterDash;
        } else {
            time = afterDash.substring(0, secondDash);
            seqText = afterDash.substring(secondDash + 1);
            if (seqText.indexOf('-') >= 0) {
                return ParseResult.failure("too many '-' separators: " + s);
            }
        }
        if (date.length() != 8 || !allDigits(date)) {
            return ParseResult.failure("date must be 8 digits YYYYMMDD: " + s);
        }
        if (time.length() != 4 || !allDigits(time)) {
            return ParseResult.failure("time must be 4 digits HHMM (UTC, 24h): " + s);
        }
        int year = Integer.parseInt(date.substring(0, 4));
        int month = Integer.parseInt(date.substring(4, 6));
        int day = Integer.parseInt(date.substring(6, 8));
        int hour = Integer.parseInt(time.substring(0, 2));
        int minute = Integer.parseInt(time.substring(2, 4));
        if (month < 1 || month > 12) {
            return ParseResult.failure("month out of range 01-12: " + s);
        }
        int maxDay = daysInMonth(year, month);
        if (day < 1 || day > maxDay) {
            return ParseResult.failure("day out of range 01-"
                    + String.format("%02d", maxDay) + " for month "
                    + String.format("%02d", month) + ": " + s);
        }
        if (hour < 0 || hour > 23) {
            return ParseResult.failure("hour out of range 00-23 (24h UTC): " + s);
        }
        if (minute < 0 || minute > 59) {
            return ParseResult.failure("minute out of range 00-59: " + s);
        }
        int seq = 0;
        if (seqText != null) {
            if (seqText.isEmpty() || seqText.length() > 9 || !allDigits(seqText)) {
                return ParseResult.failure("sequence suffix must be digits: " + s);
            }
            long seqLong = Long.parseLong(seqText);
            if (seqLong < 2 || seqLong > Integer.MAX_VALUE) {
                return ParseResult.failure(
                        "sequence suffix must be >= 2 (first release of a minute has no suffix): " + s);
            }
            seq = (int) seqLong;
        }
        return ParseResult.success(new RdVersion(year, month, day, hour, minute, seq));
    }

    private static boolean allDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    private static boolean isLeapYear(int year) {
        return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    }

    private static int daysInMonth(int year, int month) {
        switch (month) {
            case 1: case 3: case 5: case 7: case 8: case 10: case 12:
                return 31;
            case 4: case 6: case 9: case 11:
                return 30;
            case 2:
                return isLeapYear(year) ? 29 : 28;
            default:
                return 0;
        }
    }

    public int year() {
        return year;
    }

    public int month() {
        return month;
    }

    public int day() {
        return day;
    }

    public int hour() {
        return hour;
    }

    public int minute() {
        return minute;
    }

    /**
     * Sequence suffix, or 0 when absent. Absent sorts as 1 (the first release
     * of a minute precedes any {@code -seq} rerelease).
     */
    public int seq() {
        return seq;
    }

    /** True when a {@code -seq} suffix is present. */
    public boolean hasSeq() {
        return seq > 0;
    }

    /**
     * Chronological comparison: timestamp first, then sequence (absent sorts
     * before any suffix). Returns negative/zero/positive as this version is
     * older/equal/newer. A null argument is a caller error; it is reported
     * via {@link #compareResult(RdVersion)} instead of throwing here only
     * when callers need it -- this method throws NullPointerException on null
     * per {@link Comparable} convention for programming errors (not for
     * expected input failures, which {@link #parse} already covers).
     */
    @Override
    public int compareTo(RdVersion other) {
        int c;
        c = Integer.compare(year, other.year);
        if (c != 0) {
            return c;
        }
        c = Integer.compare(month, other.month);
        if (c != 0) {
            return c;
        }
        c = Integer.compare(day, other.day);
        if (c != 0) {
            return c;
        }
        c = Integer.compare(hour, other.hour);
        if (c != 0) {
            return c;
        }
        c = Integer.compare(minute, other.minute);
        if (c != 0) {
            return c;
        }
        return Integer.compare(effectiveSeq(), other.effectiveSeq());
    }

    private int effectiveSeq() {
        return seq > 0 ? seq : 1;
    }

    /** Explicit-error comparison: null other yields a failure string, never an NPE. */
    public String compareResult(RdVersion other) {
        if (other == null) {
            return "cannot compare: other version is null";
        }
        int c = compareTo(other);
        if (c < 0) {
            return "older";
        } else if (c > 0) {
            return "newer";
        }
        return "equal";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RdVersion)) {
            return false;
        }
        RdVersion o = (RdVersion) obj;
        return year == o.year && month == o.month && day == o.day
                && hour == o.hour && minute == o.minute && seq == o.seq;
    }

    @Override
    public int hashCode() {
        int h = year;
        h = 31 * h + month;
        h = 31 * h + day;
        h = 31 * h + hour;
        h = 31 * h + minute;
        h = 31 * h + seq;
        return h;
    }

    @Override
    public String toString() {
        return canonical;
    }
}
