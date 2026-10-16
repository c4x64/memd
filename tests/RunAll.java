package com.lxgr.dsu.core;

import java.util.Arrays;
import java.util.List;

/**
 * Plain-{@code main} test harness (no JUnit dependency): compiles with
 * stock {@code javac} and runs on any JVM. Prints PASS/FAIL per case and
 * exits nonzero when any case fails.
 */
public final class RunAll {

    private static int passed = 0;
    private static int failed = 0;

    private RunAll() {
    }

    public static void main(String[] args) {
        versionValid();
        versionInvalid();
        versionCompare();
        capsValid();
        capsInvalid();
        stateMachine();
        stateFailures();
        hotswapValid();
        hotswapInvalid();

        System.out.println("----");
        System.out.println("passed=" + passed + " failed=" + failed);
        if (failed > 0) {
            System.out.println("RESULT: FAIL");
            System.exit(1);
        }
        System.out.println("RESULT: PASS");
    }

    // ---- helpers ----

    private static void check(boolean cond, String name) {
        if (cond) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name);
        }
    }

    private static void check(boolean cond, String name, String detail) {
        if (cond) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name + " :: " + detail);
        }
    }

    private static String repeat(String unit, int times) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < times; i++) {
            b.append(unit);
        }
        return b.toString();
    }

    // ---- RdVersion ----

    private static void versionValid() {
        RdVersion.ParseResult r1 = RdVersion.parse("RD-20261016-0614");
        check(r1.ok && r1.value != null && r1.error == null
                && "RD-20261016-0614".equals(r1.value.toString()),
                "version: parse base form");

        RdVersion.ParseResult r2 = RdVersion.parse("RD-20261016-0614-2");
        check(r2.ok && r2.value != null && r2.value.hasSeq() && r2.value.seq() == 2
                && "RD-20261016-0614-2".equals(r2.value.toString()),
                "version: parse seq form (AGENTS.md example)");

        RdVersion.ParseResult leap = RdVersion.parse("RD-20240229-1200");
        check(leap.ok && leap.value != null, "version: leap day 2024-02-29 accepted");

        RdVersion.ParseResult midnight = RdVersion.parse("RD-20260101-0000");
        check(midnight.ok && midnight.value != null
                && midnight.value.hour() == 0 && midnight.value.minute() == 0,
                "version: midnight 00:00 accepted");

        RdVersion.ParseResult endOfDay = RdVersion.parse("RD-20261231-2359");
        check(endOfDay.ok && endOfDay.value != null
                && endOfDay.value.hour() == 23 && endOfDay.value.minute() == 59,
                "version: 23:59 accepted");
    }

    private static void versionInvalid() {
        check(!RdVersion.parse(null).ok, "version: null rejected");
        check(!RdVersion.parse("").ok, "version: empty rejected");
        check(!RdVersion.parse("   ").ok, "version: blank rejected");
        check(!RdVersion.parse("AD-20261016-0614").ok, "version: AD prefix rejected");
        check(!RdVersion.parse("ID-20261016-0614").ok, "version: ID prefix rejected");
        check(!RdVersion.parse("rd-20261016-0614").ok, "version: lowercase rd rejected");
        check(!RdVersion.parse("RD-20261301-0000").ok, "version: month 13 rejected");
        check(!RdVersion.parse("RD-20260001-0000").ok, "version: month 00 rejected");
        check(!RdVersion.parse("RD-20260230-0000").ok, "version: Feb 30 rejected");
        check(!RdVersion.parse("RD-20230229-0000").ok, "version: non-leap Feb 29 rejected");
        check(!RdVersion.parse("RD-20260431-0000").ok, "version: Apr 31 rejected");
        check(!RdVersion.parse("RD-20261016-2400").ok, "version: hour 24 rejected");
        check(!RdVersion.parse("RD-20261016-1260").ok, "version: minute 60 rejected");
        check(!RdVersion.parse("RD-20261016-0614-1").ok, "version: seq 1 rejected (first release has no suffix)");
        check(!RdVersion.parse("RD-20261016-0614-0").ok, "version: seq 0 rejected");
        check(!RdVersion.parse("RD-20261016-0614-").ok, "version: empty seq rejected");
        check(!RdVersion.parse("RD-20261016-0614-2-3").ok, "version: double seq rejected");
        check(!RdVersion.parse("RD-20261016-0614-x").ok, "version: non-numeric seq rejected");
        check(!RdVersion.parse("RD-2026101-0614").ok, "version: short date rejected");
        check(!RdVersion.parse("RD-20261016-614").ok, "version: short time rejected");
        check(!RdVersion.parse("RD-2026ABCD-0614").ok, "version: non-digit date rejected");
        check(!RdVersion.parse("RD-20261016").ok, "version: missing time rejected");
        check(!RdVersion.parse("RX-20261016-0614").ok, "version: wrong tag rejected");
        RdVersion.ParseResult bad = RdVersion.parse("nope");
        check(!bad.ok && bad.value == null && bad.error != null && !bad.error.isEmpty(),
                "version: error value carries message, value is null");
    }

    private static void versionCompare() {
        RdVersion base = RdVersion.parse("RD-20261016-0614").value;
        RdVersion seq2 = RdVersion.parse("RD-20261016-0614-2").value;
        RdVersion seq3 = RdVersion.parse("RD-20261016-0614-3").value;
        RdVersion later = RdVersion.parse("RD-20261016-0615").value;
        RdVersion earlier = RdVersion.parse("RD-20261015-2359").value;

        check(base.compareTo(seq2) < 0, "version: base < -2 (first release precedes rerelease)");
        check(seq2.compareTo(seq3) < 0, "version: -2 < -3");
        check(seq2.compareTo(later) < 0, "version: same-minute seq < next minute");
        check(earlier.compareTo(base) < 0, "version: earlier day < later day");
        check(base.compareTo(RdVersion.parse("RD-20261016-0614").value) == 0,
                "version: equal versions compare 0");
        check(base.equals(RdVersion.parse("RD-20261016-0614").value)
                && base.hashCode() == RdVersion.parse("RD-20261016-0614").value.hashCode(),
                "version: equals/hashCode consistent");
        check(!base.equals(seq2), "version: base != -2");
        check("older".equals(base.compareResult(seq2)), "version: compareResult older");
        check("newer".equals(seq2.compareResult(base)), "version: compareResult newer");
        check("equal".equals(base.compareResult(
                RdVersion.parse("RD-20261016-0614").value)), "version: compareResult equal");
        check(base.compareResult(null) != null, "version: compareResult(null) explicit, no throw");
    }

    // ---- DriverCaps ----

    private static void capsValid() {
        DriverCaps.CapsResult r = DriverCaps.create(1, 1, 0, 0,
                DriverCaps.FLAG_BOOTSTRAP_DONE | DriverCaps.FLAG_LEARNED_OFFSETS, -1);
        check(r.ok && r.value != null, "caps: valid create ok");
        check(r.value.isCompatible(), "caps: abi=1 compatible");
        check(r.value.isBootstrapDone() && r.value.hasLearnedOffsets(), "caps: flag accessors");
        String d = r.value.describe();
        check(d.contains("compatible") && d.contains("BOOTSTRAP_DONE")
                && d.contains("LEARNED_OFFSETS") && d.contains("v1.0.0")
                && d.contains("unknown"),
                "caps: describe mentions compat/flags/version/gen", d);

        DriverCaps.CapsResult incompatible = DriverCaps.create(2, 1, 0, 0, 0, 5);
        check(incompatible.ok && incompatible.value != null
                && !incompatible.value.isCompatible(),
                "caps: abi=2 representable but incompatible");
        check(incompatible.value.describe().contains("INCOMPATIBLE"),
                "caps: describe flags incompatibility",
                incompatible.value.describe());
        check(incompatible.value.gen() == 5, "caps: gen passthrough");

        DriverCaps.CapsResult bare = DriverCaps.create(1, 2, 3, 4, 0, 0);
        check(bare.ok && bare.value.describe().contains("none"),
                "caps: flags=0 describes as none", bare.value.describe());
    }

    private static void capsInvalid() {
        check(!DriverCaps.create(-1, 1, 0, 0, 0, -1).ok, "caps: negative abi rejected");
        check(!DriverCaps.create(1, -1, 0, 0, 0, -1).ok, "caps: negative major rejected");
        check(!DriverCaps.create(1, 1, -1, 0, 0, -1).ok, "caps: negative minor rejected");
        check(!DriverCaps.create(1, 1, 0, -1, 0, -1).ok, "caps: negative patch rejected");
        check(!DriverCaps.create(1, 1, 0, 0, -1, -1).ok, "caps: negative flags rejected");
        check(!DriverCaps.create(1, 1, 0, 0, 0, -2).ok, "caps: gen < -1 rejected");
        DriverCaps.CapsResult bad = DriverCaps.create(1, -1, 0, 0, 0, 0);
        check(!bad.ok && bad.value == null && bad.error != null && !bad.error.isEmpty(),
                "caps: error value carries message, value is null");
    }

    // ---- LoadState ----

    private static void stateMachine() {
        LoadState s0 = LoadState.initial();
        check(s0.state() == LoadState.State.UNKNOWN && s0.reason().isEmpty()
                && !s0.isTerminal(), "state: initial UNKNOWN, non-terminal, no reason");

        LoadState.Transition t1 = s0.markNotInstalled();
        check(t1.ok && t1.value.state() == LoadState.State.NOT_INSTALLED,
                "state: UNKNOWN -> NOT_INSTALLED");

        LoadState.Transition bad = t1.value.markRunning();
        check(!bad.ok && bad.value == null && bad.error != null,
                "state: NOT_INSTALLED -> RUNNING rejected", bad.error);

        LoadState.Transition t2 = t1.value.markInstalledStopped();
        check(t2.ok && t2.value.state() == LoadState.State.INSTALLED_STOPPED,
                "state: NOT_INSTALLED -> INSTALLED_STOPPED");

        LoadState.Transition t3 = t2.value.markRunning();
        check(t3.ok && t3.value.state() == LoadState.State.RUNNING
                && t3.value.reason().isEmpty(), "state: INSTALLED_STOPPED -> RUNNING");

        LoadState.Transition t4 = t3.value.markInstalledStopped();
        check(t4.ok && t4.value.state() == LoadState.State.INSTALLED_STOPPED,
                "state: RUNNING -> INSTALLED_STOPPED (stop)");

        LoadState.Transition t5 = t4.value.markNotInstalled();
        check(t5.ok && t5.value.state() == LoadState.State.NOT_INSTALLED,
                "state: INSTALLED_STOPPED -> NOT_INSTALLED (uninstall)");

        LoadState.Transition reset = t3.value.reset();
        check(reset.ok && reset.value.state() == LoadState.State.UNKNOWN,
                "state: reset() returns to UNKNOWN");
    }

    private static void stateFailures() {
        LoadState running = LoadState.initial()
                .markNotInstalled().value
                .markInstalledStopped().value
                .markRunning().value;

        LoadState.Transition p = running.failPermissionDenied("root manager refused load");
        check(p.ok && p.value.state() == LoadState.State.FAILED
                && p.value.isTerminal() && !p.value.reason().isEmpty()
                && p.value.reason().contains("permission denied"),
                "state: permission-denied -> terminal FAILED with message",
                p.ok ? p.value.reason() : p.error);

        LoadState.Transition t = running.failTimeout("driver did not respond in 10s");
        check(t.ok && t.value.isTerminal() && t.value.reason().contains("timeout"),
                "state: timeout -> terminal FAILED with message",
                t.ok ? t.value.reason() : t.error);

        LoadState.Transition u = running.failUnsupportedDevice("kernel 3.10 not supported");
        check(u.ok && u.value.isTerminal() && u.value.reason().contains("unsupported device"),
                "state: unsupported-device -> terminal FAILED with message",
                u.ok ? u.value.reason() : u.error);

        LoadState.Transition g = LoadState.initial().fail("partial install: payload staged, load refused");
        check(g.ok && g.value.isTerminal(), "state: generic fail from UNKNOWN -> FAILED");

        // Terminal stickiness: no forward move out of FAILED.
        LoadState failed = p.value;
        check(!failed.markRunning().ok, "state: FAILED -> RUNNING rejected");
        check(!failed.markInstalledStopped().ok, "state: FAILED -> INSTALLED_STOPPED rejected");
        check(!failed.markNotInstalled().ok, "state: FAILED -> NOT_INSTALLED rejected");
        check(!failed.failTimeout("again").ok, "state: FAILED cannot fail again");
        LoadState.Transition back = failed.reset();
        check(back.ok && back.value.state() == LoadState.State.UNKNOWN
                && back.value.reason().isEmpty() && !back.value.isTerminal(),
                "state: FAILED reset() -> UNKNOWN clears reason");

        // Failure detail is required: empty detail is an explicit rejection.
        check(!running.failPermissionDenied("").ok, "state: empty failure detail rejected");
        check(!running.failTimeout(null).ok, "state: null failure detail rejected");
        check(!running.fail("   ").ok, "state: blank failure detail rejected");
    }

    // ---- HotswapPlan ----

    private static void hotswapValid() {
        HotswapPlan.PlanResult fresh = HotswapPlan.plan(0, "/data/local/tmp/lxgr/mod/payload.so",
                "lxgr_main", false);
        check(fresh.ok && fresh.value != null, "hotswap: fresh install plans ok");
        check(fresh.value.steps().equals(Arrays.asList(
                HotswapPlan.Step.LOAD_NEW, HotswapPlan.Step.RUN_ENTRY)),
                "hotswap: fresh install steps LOAD_NEW -> RUN_ENTRY",
                fresh.value.steps().toString());

        HotswapPlan.PlanResult swap = HotswapPlan.plan(0x7f3a2b1cL,
                "/data/local/tmp/lxgr/mod/payload.so", "lxgr_main", false);
        check(swap.ok && swap.value.steps().equals(Arrays.asList(
                HotswapPlan.Step.LOAD_NEW, HotswapPlan.Step.RUN_ENTRY,
                HotswapPlan.Step.UNLOAD_OLD)),
                "hotswap: hotswap steps LOAD_NEW -> RUN_ENTRY -> UNLOAD_OLD",
                swap.value.steps().toString());

        HotswapPlan.PlanResult noEntry = HotswapPlan.plan(123L,
                "/data/local/tmp/lxgr/mod/payload.so", "", true);
        check(noEntry.ok && noEntry.value.steps().equals(Arrays.asList(
                HotswapPlan.Step.LOAD_NEW, HotswapPlan.Step.UNLOAD_OLD)),
                "hotswap: empty entry skips RUN_ENTRY",
                noEntry.value.steps().toString());

        HotswapPlan.PlanResult nullEntry = HotswapPlan.plan(0,
                "/data/local/tmp/lxgr/mod/payload.so", null, true);
        check(nullEntry.ok && nullEntry.value.steps().equals(
                Arrays.asList(HotswapPlan.Step.LOAD_NEW)),
                "hotswap: null entry + no old handle = LOAD_NEW only",
                nullEntry.value.steps().toString());

        HotswapPlan.PlanResult su = HotswapPlan.plan(9L, "/x/p.so", "e", true);
        check(su.ok && su.value.su() && su.value.oldHandle() == 9L
                && su.value.describe().contains("su"),
                "hotswap: su flag and handle accessors", su.value.describe());

        List<HotswapPlan.Step> steps = swap.value.steps();
        boolean unmodifiable = false;
        try {
            steps.add(HotswapPlan.Step.LOAD_NEW);
        } catch (UnsupportedOperationException expected) {
            unmodifiable = true;
        }
        check(unmodifiable, "hotswap: steps list unmodifiable");
    }

    private static void hotswapInvalid() {
        check(!HotswapPlan.plan(0, "relative/path.so", "lxgr_main", false).ok,
                "hotswap: relative path rejected");
        check(!HotswapPlan.plan(0, "", "lxgr_main", false).ok,
                "hotswap: empty path rejected");
        check(!HotswapPlan.plan(0, null, "lxgr_main", false).ok,
                "hotswap: null path rejected");
        check(!HotswapPlan.plan(0, "/x/p.so", "bad/entry", false).ok,
                "hotswap: entry with slash rejected");
        check(!HotswapPlan.plan(0, "/x/p\0.so", "e", false).ok,
                "hotswap: NUL in path rejected");
        check(!HotswapPlan.plan(0, "/x/p.so", "e\0", false).ok,
                "hotswap: NUL in entry rejected");
        check(!HotswapPlan.plan(-1L, "/x/p.so", "e", false).ok,
                "hotswap: negative handle rejected");

        String longPath = "/" + repeat("a", 300);
        check(!HotswapPlan.plan(0, longPath, "e", false).ok,
                "hotswap: >255-byte path rejected");
        String longEntry = repeat("e", 64);
        check(!HotswapPlan.plan(0, "/x/p.so", longEntry, false).ok,
                "hotswap: >63-byte entry rejected");

        HotswapPlan.PlanResult bad = HotswapPlan.plan(0, "rel.so", "e", false);
        check(!bad.ok && bad.value == null && bad.error != null && !bad.error.isEmpty(),
                "hotswap: error value carries message, value is null");

        // Boundary: exactly 255-byte path and 63-byte entry are accepted.
        String edgePath = "/" + repeat("a", 254);
        check(HotswapPlan.plan(0, edgePath, "e", false).ok,
                "hotswap: 255-byte path accepted");
        check(HotswapPlan.plan(0, "/x/p.so", repeat("e", 63), false).ok,
                "hotswap: 63-byte entry accepted");
    }
}
