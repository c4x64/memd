package com.lxgr.dsu.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Explicit opt-in boot-loading model for the DSU app's MEMD loading flow.
 *
 * <p>States: {@code DISABLED} (initial; no boot-time action) and
 * {@code ENABLED} (a validated load script is stored and
 * {@link #generateScript()} emits the exact shell lines). Enabling requires
 * all three preconditions at once:
 *
 * <ol>
 *   <li>explicit user confirmation ({@code userConfirmed == true});</li>
 *   <li>a validated load script (see {@link #validateScript(String)}:
 *       non-empty, absolute paths only, no shell metacharacters outside the
 *       strict whitelist);</li>
 *   <li>driver-present precondition ({@code driverPresent == true}, passed in
 *       by the caller; no live probing happens here).</li>
 * </ol>
 *
 * <p>Checked in that order; the first unmet precondition yields the error.
 *
 * <p>Double-enable rule: enabling while already {@code ENABLED} with
 * byte-identical (normalized) script text is a successful no-op
 * (idempotent); enabling while {@code ENABLED} with <em>different</em>
 * script text is rejected -- call {@link #disable()} first to change the
 * script. Disabling clears the stored script and is itself idempotent.
 *
 * <p>The value is immutable: {@link #enable} / {@link #disable} return a
 * {@link BootResult} carrying either the next {@code BootManager} or an
 * explicit error. Expected failures never throw. Pure Java, no Android
 * imports.
 */
public final class BootManager {

    /** Boot-loading states. */
    public enum State {
        /** No boot-time action (initial). */
        DISABLED,
        /** Validated script stored; boot-time loading opted in. */
        ENABLED
    }

    /** Result of {@link #enable} / {@link #disable}: either {@code value} or {@code error}. */
    public static final class BootResult {
        /** True when the transition was accepted and {@link #value} is non-null. */
        public final boolean ok;
        /** Next manager; null when {@link #ok} is false. */
        public final BootManager value;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private BootResult(boolean ok, BootManager value, String error) {
            this.ok = ok;
            this.value = value;
            this.error = error;
        }

        /** Successful result. */
        public static BootResult success(BootManager value) {
            return new BootResult(true, value, null);
        }

        /** Failure result with an explicit reason. */
        public static BootResult failure(String error) {
            return new BootResult(false, null, error);
        }
    }

    /** Result of {@link #validateScript} / {@link #generateScript}. */
    public static final class ScriptResult {
        /** True when validation/generation succeeded. */
        public final boolean ok;
        /** Exact shell text; null when {@link #ok} is false. */
        public final String script;
        /** Shell lines (unmodifiable); null when {@link #ok} is false. */
        public final List<String> lines;
        /** Human-readable reason; null when {@link #ok} is true. */
        public final String error;

        private ScriptResult(boolean ok, String script, List<String> lines, String error) {
            this.ok = ok;
            this.script = script;
            this.lines = lines;
            this.error = error;
        }

        /** Successful result. */
        public static ScriptResult success(String script, List<String> lines) {
            return new ScriptResult(true, script,
                    Collections.unmodifiableList(new ArrayList<String>(lines)), null);
        }

        /** Failure result with an explicit reason. */
        public static ScriptResult failure(String error) {
            return new ScriptResult(false, null, null, error);
        }
    }

    /** Max accepted script length in chars (keeps boot payloads reviewable). */
    public static final int MAX_SCRIPT_CHARS = 4096;

    /** Generated-script shebang line. */
    public static final String SHEBANG = "#!/system/bin/sh";
    /** Generated-script header comment (states the opt-out). */
    public static final String HEADER_COMMENT =
            "# DSU boot-load (explicit opt-in; disable stops automatic loading)";

    /** Shell metacharacters that are always rejected in code lines. */
    private static final String METACHARS = ";|&$()`";

    private final State state;
    /** Normalized validated script (code + comment lines); empty unless ENABLED. */
    private final String script;

    private BootManager(State state, String script) {
        this.state = state;
        this.script = script;
    }

    /** Initial manager: {@code DISABLED} with no stored script. */
    public static BootManager disabled() {
        return new BootManager(State.DISABLED, "");
    }

    /** Current state. */
    public State state() {
        return state;
    }

    /** True only when {@code state == ENABLED}. */
    public boolean isEnabled() {
        return state == State.ENABLED;
    }

    /**
     * Stored normalized script; empty unless {@code ENABLED}. Disabling
     * clears it, so a disabled manager carries no residual boot payload.
     */
    public String script() {
        return script;
    }

    /**
     * Attempts to enable boot loading. All preconditions are checked in
     * order: explicit user confirmation, driver-present precondition, then
     * script validity. Enabling while already {@code ENABLED} with
     * byte-identical (normalized) script text succeeds as a no-op;
     * enabling while {@code ENABLED} with different script text is
     * rejected (disable first). Null script text yields a failure, never
     * an NPE.
     *
     * @param userConfirmed must be true (explicit opt-in)
     * @param scriptText    load script to validate and store
     * @param driverPresent caller-observed driver presence; no probing here
     */
    public BootResult enable(boolean userConfirmed, String scriptText, boolean driverPresent) {
        if (!userConfirmed) {
            return BootResult.failure(
                    "explicit user confirmation required (pass userConfirmed=true to opt in)");
        }
        if (!driverPresent) {
            return BootResult.failure(
                    "driver not present (enable requires the MEMD driver to be installed)");
        }
        ScriptResult checked = validateScript(scriptText);
        if (!checked.ok) {
            return BootResult.failure("invalid load script: " + checked.error);
        }
        if (state == State.ENABLED) {
            if (checked.script.equals(script)) {
                return BootResult.success(new BootManager(State.ENABLED, script));
            }
            return BootResult.failure(
                    "already ENABLED with a different script; disable() first to change it");
        }
        return BootResult.success(new BootManager(State.ENABLED, checked.script));
    }

    /**
     * Disables boot loading and clears any stored script. Idempotent:
     * disabling an already-{@code DISABLED} manager succeeds.
     */
    public BootResult disable() {
        return BootResult.success(new BootManager(State.DISABLED, ""));
    }

    /**
     * Returns the exact shell lines to install as the boot script. Fails
     * when {@code DISABLED} (nothing to emit). The output is the shebang,
     * the opt-in header comment, then the stored validated lines, joined
     * with {@code '\n'} plus a trailing newline.
     */
    public ScriptResult generateScript() {
        if (state != State.ENABLED) {
            return ScriptResult.failure("boot loading is DISABLED (nothing to emit; enable() first)");
        }
        List<String> lines = new ArrayList<String>();
        lines.add(SHEBANG);
        lines.add(HEADER_COMMENT);
        for (String line : script.split("\n")) {
            lines.add(line);
        }
        StringBuilder out = new StringBuilder();
        for (String line : lines) {
            out.append(line).append('\n');
        }
        return ScriptResult.success(out.toString(), lines);
    }

    /**
     * Pure validation of a candidate load script. Never throws for
     * malformed input; returns a {@link ScriptResult} failure instead
     * (null input included).
     *
     * <p>Rules:
     *
     * <ul>
     *   <li>script must be non-null, non-blank, NUL-free, and at most
     *       {@link #MAX_SCRIPT_CHARS} chars;</li>
     *   <li>at least one non-blank, non-comment line is required;</li>
     *   <li>comment lines (first non-whitespace char {@code '#'}) are
     *       carried through uninspected (except NUL/length);</li>
     *   <li>each code line may only contain the whitelist
     *       {@code [A-Za-z0-9 / . - _ : = " ' # ,]} plus space/tab.
     *       Anything else -- in particular the shell metacharacters
     *       {@code ; | & $ ( ) `} and friends ({@code * ? ! ~ < > \})
     *       -- is rejected with the offending character named;</li>
     *   <li>absolute paths only: every whitespace-separated token that
     *       contains a {@code '/'} must start with {@code '/'} (so
     *       {@code relative/path.so}, {@code ./x}, {@code ../x},
     *       {@code ~/x} are rejected), and each code line must contain
     *       at least one such absolute-path token.</li>
     * </ul>
     *
     * <p>On success the value is the normalized script: non-blank lines
     * with trailing whitespace stripped, joined by {@code '\n'} (no
     * trailing newline).
     */
    public static ScriptResult validateScript(String scriptText) {
        if (scriptText == null) {
            return ScriptResult.failure("script is null (expected non-empty load script)");
        }
        if (scriptText.indexOf('\0') >= 0) {
            return ScriptResult.failure("script must not contain NUL bytes");
        }
        if (scriptText.length() > MAX_SCRIPT_CHARS) {
            return ScriptResult.failure("script exceeds " + MAX_SCRIPT_CHARS
                    + " chars (" + scriptText.length() + " chars)");
        }
        String[] raw = scriptText.split("\n", -1);
        List<String> kept = new ArrayList<String>();
        for (String rawLine : raw) {
            String line = rawLine.endsWith("\r")
                    ? rawLine.substring(0, rawLine.length() - 1) : rawLine;
            String stripped = rtrim(line);
            if (stripped.trim().isEmpty()) {
                continue;
            }
            kept.add(stripped);
        }
        if (kept.isEmpty()) {
            return ScriptResult.failure("script is empty (expected at least one command line)");
        }
        for (String line : kept) {
            if (isComment(line)) {
                continue;
            }
            String bad = checkWhitelist(line);
            if (bad != null) {
                return ScriptResult.failure(bad);
            }
            String pathProblem = checkPaths(line);
            if (pathProblem != null) {
                return ScriptResult.failure(pathProblem);
            }
        }
        StringBuilder norm = new StringBuilder();
        for (int i = 0; i < kept.size(); i++) {
            if (i > 0) {
                norm.append('\n');
            }
            norm.append(kept.get(i));
        }
        return ScriptResult.success(norm.toString(), kept);
    }

    private static boolean isComment(String line) {
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == ' ' || c == '\t') {
                continue;
            }
            return c == '#';
        }
        return false;
    }

    private static String rtrim(String s) {
        int end = s.length();
        while (end > 0) {
            char c = s.charAt(end - 1);
            if (c == ' ' || c == '\t') {
                end--;
            } else {
                break;
            }
        }
        return s.substring(0, end);
    }

    private static String checkWhitelist(String line) {
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (isAllowed(c)) {
                continue;
            }
            if (METACHARS.indexOf(c) >= 0 || c == '\\' || c == '*'
                    || c == '?' || c == '!' || c == '~'
                    || c == '<' || c == '>') {
                return "script rejects shell metacharacter '" + c + "' in line: " + line;
            }
            return "script rejects character '" + describeChar(c) + "' in line: " + line;
        }
        return null;
    }

    private static boolean isAllowed(char c) {
        if (c >= 'a' && c <= 'z') {
            return true;
        }
        if (c >= 'A' && c <= 'Z') {
            return true;
        }
        if (c >= '0' && c <= '9') {
            return true;
        }
        switch (c) {
            case ' ':
            case '\t':
            case '/':
            case '.':
            case '-':
            case '_':
            case ':':
            case '=':
            case '"':
            case '\'':
            case '#':
            case ',':
                return true;
            default:
                return false;
        }
    }

    private static String describeChar(char c) {
        if (c == '\r') {
            return "\\r";
        }
        if (c < 32 || c > 126) {
            return "U+" + Integer.toHexString(c);
        }
        return String.valueOf(c);
    }

    private static String checkPaths(String line) {
        String[] tokens = line.split("[ \t]+");
        boolean sawAbsolute = false;
        for (String token : tokens) {
            if (token.isEmpty()) {
                continue;
            }
            String t = stripQuotes(token);
            if (t.indexOf('/') < 0) {
                continue;
            }
            if (!t.startsWith("/")) {
                return "script paths must be absolute (no relative paths): '" + token
                        + "' in line: " + line;
            }
            sawAbsolute = true;
        }
        if (!sawAbsolute) {
            return "script line has no absolute path: " + line;
        }
        return null;
    }

    private static String stripQuotes(String token) {
        if (token.length() >= 2) {
            char first = token.charAt(0);
            char last = token.charAt(token.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return token.substring(1, token.length() - 1);
            }
        }
        return token;
    }

    /** One-line human-readable summary for UI display. */
    public String describe() {
        if (state == State.DISABLED) {
            return "boot DISABLED (no boot-time action)";
        }
        int lines = script.isEmpty() ? 0 : script.split("\n").length;
        return "boot ENABLED lines=" + lines;
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
        if (!(obj instanceof BootManager)) {
            return false;
        }
        BootManager o = (BootManager) obj;
        return state == o.state && script.equals(o.script);
    }

    @Override
    public int hashCode() {
        return 31 * state.hashCode() + script.hashCode();
    }
}
