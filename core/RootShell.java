package com.lxgr.dsu.core;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.Locale;

/**
 * Privileged command transport for the DSU userspace app.
 *
 * <p>All privileged invocations go through
 * {@link #runAsRoot(String[], long, LogSink, Executor)}: the exact command
 * line is echoed to the caller-supplied {@link LogSink} <em>before</em> any
 * execution attempt, a mandatory timeout is enforced (the running task is
 * cancelled/interrupted and {@link Status#TIMEOUT} is reported), and outcomes
 * are mapped to an explicit {@link Status} with no silent fallbacks.
 *
 * <p>Pure Java only: no Android framework imports. The testable path
 * ({@link #runAsRoot}) never calls {@code Runtime.exec} /
 * {@code ProcessBuilder} directly; process creation lives solely behind the
 * {@link Executor} contract so production ({@code su -c}, see
 * {@link ProcessExecutor}) and tests (fakes) share one seam.
 */
public final class RootShell {

    /** Minimum allowed timeout: 1 second. */
    public static final long MIN_TIMEOUT_MS = 1_000L;
    /** Maximum allowed timeout: 5 minutes. */
    public static final long MAX_TIMEOUT_MS = 300_000L;

    /** Exit codes treated as denial (refused / no su / command rejected). */
    private static final int[] DENIED_EXIT_CODES = {126, 127, 255};

    /**
     * Case-insensitive output fragments treated as denial when the process
     * exits non-zero (checked against stdout + stderr).
     */
    private static final String[] DENIED_OUTPUT_PATTERNS = {
        "permission denied",
        "not allowed",
        "denied",
        "not rooted",
        "no superuser",
        "unauthorized",
        "operation not permitted",
        "must be rooted",
        "su: permission",
        "permission denied:",
    };

    private RootShell() {
    }

    /** Outcome of one {@link Executor#exec} attempt (transport level). */
    public static final class ExecResult {
        /** Process exit code; undefined when {@link #timedOut} is true. */
        public final int exitCode;
        /** Captured stdout (never null). */
        public final String stdout;
        /** Captured stderr (never null). */
        public final String stderr;
        /** True when the executor itself killed the process on timeout. */
        public final boolean timedOut;

        public ExecResult(int exitCode, String stdout, String stderr, boolean timedOut) {
            this.exitCode = exitCode;
            this.stdout = stdout == null ? "" : stdout;
            this.stderr = stderr == null ? "" : stderr;
            this.timedOut = timedOut;
        }

        /** Completed process with exit code and captured streams. */
        public static ExecResult completed(int exitCode, String stdout, String stderr) {
            return new ExecResult(exitCode, stdout, stderr, false);
        }

        /** Executor-side timeout: process was killed for exceeding the deadline. */
        public static ExecResult timedOut(String stdout, String stderr) {
            return new ExecResult(-1, stdout, stderr, true);
        }
    }

    /**
     * Transport seam: runs {@code argv} with a mandatory {@code timeoutMs}
     * deadline. Production uses {@code su -c} (see {@link ProcessExecutor});
     * tests supply fakes. Implementations should honour the timeout
     * (kill the process and return {@link ExecResult#timedOut}) but
     * {@link #runAsRoot} enforces the deadline independently as well.
     */
    public interface Executor {
        /**
         * Execute {@code argv} and wait up to {@code timeoutMs}.
         *
         * @param argv command vector; {@code argv[0]} is an absolute binary path
         * @param timeoutMs deadline in milliseconds
         * @return transport-level result, never null
         * @throws Exception any transport failure; mapped to
         *                 {@link Status#ERROR} by {@link #runAsRoot}
         */
        ExecResult exec(String[] argv, long timeoutMs) throws Exception;
    }

    /** Caller-supplied log sink receiving the exact command line before execution. */
    public interface LogSink {
        /** Record one line (the exact command about to run). */
        void log(String line);
    }

    /** Mapped outcome of {@link #runAsRoot}. */
    public enum Status {
        /** Process exited 0 with no denial signal. */
        OK,
        /** Deadline exceeded; the task was cancelled/killed. */
        TIMEOUT,
        /** Root/manager refused: exit 126/127/255 or denial output pattern. */
        DENIED,
        /** Non-zero exit that is not a denial pattern. */
        FAILED,
        /** Validation or transport failure (never a silent fallback). */
        ERROR
    }

    /** Explicit result of {@link #runAsRoot}: status plus evidence, never null fields. */
    public static final class Result {
        /** Mapped outcome. */
        public final Status status;
        /**
         * Process exit code, or -1 when no process completed
         * (validation, timeout-by-kill, transport error).
         */
        public final int exitCode;
        /** Captured stdout ("" when unavailable). */
        public final String stdout;
        /** Captured stderr ("" when unavailable). */
        public final String stderr;
        /** Human-readable detail; never null/empty. */
        public final String message;

        public Result(Status status, int exitCode, String stdout, String stderr, String message) {
            this.status = status;
            this.exitCode = exitCode;
            this.stdout = stdout == null ? "" : stdout;
            this.stderr = stderr == null ? "" : stderr;
            this.message = (message == null || message.isEmpty()) ? status.name() : message;
        }
    }

    /**
     * Validate, log, then execute one privileged command.
     *
     * <ol>
     *   <li>Validates: {@code argv} non-empty with a non-blank absolute
     *       ({@code /}-rooted) {@code argv[0]}, and
     *       {@code 1000 <= timeoutMs <= 300000}.</li>
     *   <li>Echoes the exact shell-quoted command line to {@code logSink}
     *       <em>before</em> invoking the executor.</li>
     *   <li>Enforces the deadline: a task running past {@code timeoutMs} is
     *       cancelled (interrupted) and reported as {@link Status#TIMEOUT}.</li>
     *   <li>Maps the outcome: executor-side timeout or caller-side deadline
     *       breach -&gt; {@code TIMEOUT}; exit 126/127/255 or (non-zero exit
     *       plus denial output pattern) -&gt; {@code DENIED}; exit 0 -&gt;
     *       {@code OK}; other non-zero -&gt; {@code FAILED}; validation or
     *       transport exception -&gt; {@code ERROR}.</li>
     * </ol>
     *
     * @param argv command vector; {@code argv[0]} must be an absolute binary path
     * @param timeoutMs deadline, 1000..300000 ms inclusive
     * @param logSink receives the exact command line before execution; must be non-null
     * @param executor transport; must be non-null
     * @return explicit result; never null, never throws for expected failures
     */
    public static Result runAsRoot(String[] argv, long timeoutMs, LogSink logSink, Executor executor) {
        if (logSink == null) {
            return new Result(Status.ERROR, -1, "", "", "logSink must not be null");
        }
        if (executor == null) {
            return new Result(Status.ERROR, -1, "", "", "executor must not be null");
        }
        if (argv == null || argv.length == 0) {
            return new Result(Status.ERROR, -1, "", "", "argv must be non-empty");
        }
        if (argv[0] == null || argv[0].isEmpty()) {
            return new Result(Status.ERROR, -1, "", "", "argv[0] (binary path) must be non-empty");
        }
        for (int i = 0; i < argv.length; i++) {
            if (argv[i] == null) {
                return new Result(Status.ERROR, -1, "", "",
                        "argv[" + i + "] must not be null");
            }
        }
        if (!argv[0].startsWith("/")) {
            return new Result(Status.ERROR, -1, "", "",
                    "argv[0] must be an absolute binary path, got: " + argv[0]);
        }
        if (timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) {
            return new Result(Status.ERROR, -1, "", "",
                    "timeoutMs out of range [1000..300000], got: " + timeoutMs);
        }

        final String[] snapshot = argv.clone();
        final String commandLine = joinCommand(snapshot);
        try {
            logSink.log(commandLine);
        } catch (Exception e) {
            return new Result(Status.ERROR, -1, "", "",
                    "logSink threw before execution: " + e);
        }

        ExecutorService runner = Executors.newSingleThreadExecutor(new java.util.concurrent.ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "rootshell-run");
                t.setDaemon(true);
                return t;
            }
        });
        Future<ExecResult> future = runner.submit(new Callable<ExecResult>() {
            @Override
            public ExecResult call() throws Exception {
                return executor.exec(snapshot.clone(), timeoutMs);
            }
        });
        ExecResult execResult;
        try {
            execResult = future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            future.cancel(true);
            runner.shutdownNow();
            return new Result(Status.TIMEOUT, -1, "", "",
                    "timed out after " + timeoutMs + "ms; killed: " + commandLine);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            future.cancel(true);
            runner.shutdownNow();
            return new Result(Status.ERROR, -1, "", "",
                    "interrupted while waiting for: " + commandLine);
        } catch (java.util.concurrent.ExecutionException ee) {
            runner.shutdownNow();
            Throwable cause = ee.getCause() == null ? ee : ee.getCause();
            return new Result(Status.ERROR, -1, "", "",
                    "executor threw: " + cause + " for: " + commandLine);
        } finally {
            runner.shutdownNow();
        }

        if (execResult == null) {
            return new Result(Status.ERROR, -1, "", "",
                    "executor returned null for: " + commandLine);
        }
        if (execResult.timedOut) {
            return new Result(Status.TIMEOUT, -1, execResult.stdout, execResult.stderr,
                    "executor reported timeout (killed) for: " + commandLine);
        }
        int exit = execResult.exitCode;
        for (int denied : DENIED_EXIT_CODES) {
            if (exit == denied) {
                return new Result(Status.DENIED, exit, execResult.stdout, execResult.stderr,
                        "denied (exit " + exit + ") for: " + commandLine);
            }
        }
        if (exit == 0) {
            return new Result(Status.OK, 0, execResult.stdout, execResult.stderr,
                    "ok: " + commandLine);
        }
        if (matchesDeniedPattern(execResult.stdout) || matchesDeniedPattern(execResult.stderr)) {
            return new Result(Status.DENIED, exit, execResult.stdout, execResult.stderr,
                    "denied (output pattern, exit " + exit + ") for: " + commandLine);
        }
        return new Result(Status.FAILED, exit, execResult.stdout, execResult.stderr,
                "failed with exit " + exit + " for: " + commandLine);
    }

    /**
     * Join {@code argv} into one shell-readable command line (single-quote
     * arguments containing anything outside {@code [A-Za-z0-9_./:=-]}).
     * This is the exact string echoed to the {@link LogSink} and, for
     * {@link ProcessExecutor}, the string passed to {@code su -c}.
     */
    public static String joinCommand(String[] argv) {
        if (argv == null || argv.length == 0) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < argv.length; i++) {
            if (i > 0) {
                b.append(' ');
            }
            b.append(quoteArg(argv[i]));
        }
        return b.toString();
    }

    private static String quoteArg(String arg) {
        if (arg == null || arg.isEmpty()) {
            return "''";
        }
        int n = arg.length();
        boolean plain = true;
        for (int i = 0; i < n; i++) {
            char c = arg.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '_' || c == '.' || c == '/' || c == ':'
                    || c == '=' || c == '-';
            if (!ok) {
                plain = false;
                break;
            }
        }
        if (plain) {
            return arg;
        }
        return "'" + arg.replace("'", "'\"'\"'") + "'";
    }

    private static boolean matchesDeniedPattern(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        String lower = text.toLowerCase(Locale.ROOT);
        for (String p : DENIED_OUTPUT_PATTERNS) {
            if (lower.contains(p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Production {@link Executor}: runs the command via {@code su -c}.
     * This is the only place that touches {@code ProcessBuilder}; the testable
     * path ({@link #runAsRoot}) never creates processes directly.
     */
    public static final class ProcessExecutor implements Executor {
        /** argv used for elevation: {@code su -c "<joined command>"}. */
        public static String[] wrapForSu(String[] argv) {
            String[] out = new String[3];
            out[0] = "su";
            out[1] = "-c";
            out[2] = joinCommand(argv);
            return out;
        }

        @Override
        public ExecResult exec(String[] argv, long timeoutMs) throws Exception {
            if (argv == null || argv.length == 0 || argv[0] == null || !argv[0].startsWith("/")) {
                throw new IllegalArgumentException("argv[0] must be an absolute binary path");
            }
            if (timeoutMs < MIN_TIMEOUT_MS || timeoutMs > MAX_TIMEOUT_MS) {
                throw new IllegalArgumentException("timeoutMs out of range [1000..300000]");
            }
            String[] suArgv = wrapForSu(argv);
            ProcessBuilder pb = new ProcessBuilder(suArgv);
            pb.redirectInput(ProcessBuilder.Redirect.PIPE);
            final Process proc = pb.start();
            StreamGobbler outGobbler = new StreamGobbler(proc.getInputStream());
            StreamGobbler errGobbler = new StreamGobbler(proc.getErrorStream());
            Thread outThread = new Thread(outGobbler, "rootshell-stdout");
            Thread errThread = new Thread(errGobbler, "rootshell-stderr");
            outThread.setDaemon(true);
            errThread.setDaemon(true);
            outThread.start();
            errThread.start();
            boolean done = proc.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!done) {
                proc.destroyForcibly();
                boolean exited = proc.waitFor(5, TimeUnit.SECONDS);
                closeQuietly(proc);
                outThread.join(2000L);
                errThread.join(2000L);
                return ExecResult.timedOut(outGobbler.text(), errGobbler.text()
                        + (exited ? "" : " (process did not exit after destroy)"));
            }
            outThread.join(5000L);
            errThread.join(5000L);
            closeQuietly(proc);
            return ExecResult.completed(proc.exitValue(), outGobbler.text(), errGobbler.text());
        }

        private static void closeQuietly(Process proc) {
            try {
                proc.getInputStream().close();
            } catch (Exception ignored) {
                // best effort
            }
            try {
                proc.getErrorStream().close();
            } catch (Exception ignored) {
                // best effort
            }
            try {
                proc.getOutputStream().close();
            } catch (Exception ignored) {
                // best effort
            }
        }

        private static final class StreamGobbler implements Runnable {
            private final InputStream in;
            private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

            StreamGobbler(InputStream in) {
                this.in = in;
            }

            @Override
            public void run() {
                byte[] chunk = new byte[4096];
                try {
                    int r;
                    while ((r = in.read(chunk)) != -1) {
                        synchronized (buf) {
                            buf.write(chunk, 0, r);
                        }
                    }
                } catch (Exception ignored) {
                    // stream closed on kill; captured bytes so far are kept
                }
            }

            String text() {
                synchronized (buf) {
                    return new String(buf.toByteArray(), StandardCharsets.UTF_8);
                }
            }
        }
    }

    /** Exposed for tests/docs: the denial output fragments (lowercase). */
    static List<String> deniedPatternsForTest() {
        List<String> out = new ArrayList<String>();
        for (String p : DENIED_OUTPUT_PATTERNS) {
            out.add(p);
        }
        return out;
    }
}
