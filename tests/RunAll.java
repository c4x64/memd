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
        registryUpsertListRemove();
        registryIdValidation();
        registryVersionOrdering();
        registryFindReplace();
        bootEnableDisable();
        bootValidateRejects();
        bootGenerateShape();
        bootDoubleEnable();
        rootshellSuccess();
        rootshellTimeout();
        rootshellDenied();
        rootshellValidation();
        rootshellLogBeforeRun();
        driverSelection();
        driverRequire();
        driverSpecs();
        hideLifecycle();
        hideFailures();
        hideNoAutoHide();

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

    // ---- BootManager ----

    private static final String BOOT_GOOD = "/system/bin/memd_load /data/local/tmp/lxgr/mod/payload.so";

    private static void bootEnableDisable() {
        BootManager off = BootManager.disabled();
        check(off.state() == BootManager.State.DISABLED && !off.isEnabled()
                && off.script().isEmpty(), "boot: initial DISABLED, no stored script");

        BootManager.BootResult noConfirm = off.enable(false, BOOT_GOOD, true);
        check(!noConfirm.ok && noConfirm.value == null && noConfirm.error != null,
                "boot: enable without user confirmation rejected");

        BootManager.BootResult noDriver = off.enable(true, BOOT_GOOD, false);
        check(!noDriver.ok && noDriver.value == null && noDriver.error != null
                && noDriver.error.contains("driver"),
                "boot: enable without driver-present rejected", noDriver.error);

        BootManager.BootResult badScript = off.enable(true, "relative/path.so", true);
        check(!badScript.ok && badScript.value == null,
                "boot: enable with invalid script rejected");

        BootManager.BootResult on = off.enable(true, BOOT_GOOD, true);
        check(on.ok && on.value != null && on.value.isEnabled()
                && on.value.state() == BootManager.State.ENABLED,
                "boot: enable with confirmation+script+driver -> ENABLED",
                on.ok ? on.value.describe() : on.error);

        BootManager.BootResult stop = on.value.disable();
        check(stop.ok && stop.value != null && !stop.value.isEnabled()
                && stop.value.script().isEmpty(),
                "boot: disable() -> DISABLED and clears script");

        BootManager.BootResult stopAgain = stop.value.disable();
        check(stopAgain.ok && !stopAgain.value.isEnabled(),
                "boot: disable() idempotent on DISABLED");

        BootManager.ScriptResult genOff = stop.value.generateScript();
        check(!genOff.ok && genOff.script == null,
                "boot: generateScript() fails when DISABLED");
    }

    private static void bootValidateRejects() {
        check(!BootManager.validateScript(null).ok, "boot: null script rejected");
        check(!BootManager.validateScript("").ok, "boot: empty script rejected");
        check(!BootManager.validateScript("   \n  ").ok, "boot: blank script rejected");
        check(!BootManager.validateScript("relative/path.so").ok,
                "boot: relative path rejected");
        check(!BootManager.validateScript("/bin/load ./payload.so").ok,
                "boot: ./ relative path rejected");
        check(!BootManager.validateScript("/bin/load ../payload.so").ok,
                "boot: ../ relative path rejected");
        check(!BootManager.validateScript("load payload.so").ok,
                "boot: line without absolute path rejected");

        String[] metachars = {";", "|", "&", "$", "(", ")", "`"};
        for (String m : metachars) {
            BootManager.ScriptResult r =
                    BootManager.validateScript("/bin/load /x/p.so " + m);
            check(!r.ok && r.script == null && r.error != null,
                    "boot: metachar '" + m + "' rejected");
        }
        check(!BootManager.validateScript("/bin/load /x/p.so && /bin/other").ok,
                "boot: && chain rejected");
        check(!BootManager.validateScript("/bin/load /x/p.so | /bin/other").ok,
                "boot: pipe rejected");
        check(!BootManager.validateScript("/x/p\0.so").ok,
                "boot: NUL byte rejected");

        BootManager.ScriptResult ok = BootManager.validateScript(BOOT_GOOD);
        check(ok.ok && ok.script != null && ok.lines != null && !ok.lines.isEmpty(),
                "boot: valid script accepted");
        BootManager.ScriptResult comment = BootManager.validateScript(
                "# scheduled by user\n" + BOOT_GOOD);
        check(comment.ok, "boot: comment lines accepted");
    }

    private static void bootGenerateShape() {
        BootManager on = BootManager.disabled().enable(true, BOOT_GOOD, true).value;
        BootManager.ScriptResult gen = on.generateScript();
        check(gen.ok && gen.script != null && gen.lines != null,
                "boot: generateScript() ok when ENABLED");
        check(gen.script.startsWith(BootManager.SHEBANG + "\n"),
                "boot: generated script starts with shebang", gen.script);
        check(gen.script.contains(BOOT_GOOD), "boot: generated script contains payload line");
        check(gen.script.endsWith("\n"), "boot: generated script ends with newline");
        check(gen.lines.get(0).equals(BootManager.SHEBANG)
                && gen.lines.get(1).equals(BootManager.HEADER_COMMENT),
                "boot: generated lines header shape", gen.lines.toString());
        check(gen.lines.get(gen.lines.size() - 1).equals(BOOT_GOOD),
                "boot: generated lines end with payload line");

        boolean unmodifiable = false;
        try {
            gen.lines.add("extra");
        } catch (UnsupportedOperationException expected) {
            unmodifiable = true;
        }
        check(unmodifiable, "boot: generated lines unmodifiable");

        BootManager.ScriptResult roundTrip = BootManager.validateScript(gen.script);
        check(roundTrip.ok, "boot: generated script re-validates");
    }

    private static void bootDoubleEnable() {
        BootManager off = BootManager.disabled();
        BootManager on = off.enable(true, BOOT_GOOD, true).value;

        BootManager.BootResult same = on.enable(true, BOOT_GOOD, true);
        check(same.ok && same.value != null && same.value.isEnabled()
                && same.value.script().equals(on.script()),
                "boot: double-enable same script is idempotent no-op");

        String other = "/system/bin/memd_load /data/local/tmp/lxgr/mod/other.so";
        BootManager.BootResult different = on.enable(true, other, true);
        check(!different.ok && different.value == null,
                "boot: double-enable different script rejected (disable first)");

        BootManager.BootResult afterDisable = on.disable().value.enable(true, other, true);
        check(afterDisable.ok && afterDisable.value.script().contains("other.so"),
                "boot: disable then enable with new script accepted");
    }


    // ---- HideManager ----

    private static void hideLifecycle() {
        HideManager idle = HideManager.initial();
        check(idle.state() == HideManager.State.IDLE && !idle.isHidden()
                && idle.pid() == 0 && idle.reason().isEmpty(),
                "hide: initial IDLE, visible, no pid (never hidden at boot)");

        HideManager.Transition req = idle.requestHide(1234);
        check(req.ok && req.value != null
                && req.value.state() == HideManager.State.HIDE_REQUESTED
                && req.value.pid() == 1234 && !req.value.isHidden(),
                "hide: IDLE -> HIDE_REQUESTED via requestHide(pid)",
                req.ok ? req.value.describe() : req.error);

        HideManager.Transition confirmed = req.value.confirmHidden(0, 1);
        check(confirmed.ok && confirmed.value != null
                && confirmed.value.state() == HideManager.State.HIDDEN
                && confirmed.value.isHidden() && confirmed.value.pid() == 1234,
                "hide: HIDE_REQUESTED -> HIDDEN when count increased",
                confirmed.ok ? confirmed.value.describe() : confirmed.error);

        HideManager.Transition unhide = confirmed.value.requestUnhide(1234);
        check(unhide.ok && unhide.value != null
                && unhide.value.state() == HideManager.State.IDLE
                && !unhide.value.isHidden() && unhide.value.pid() == 0,
                "hide: HIDDEN -> IDLE via requestUnhide(pid)",
                unhide.ok ? unhide.value.describe() : unhide.error);

        HideManager.Transition req2 = unhide.value.requestHide(77);
        HideManager.Transition failed = req2.value.fail("driver refused hide");
        check(failed.ok && failed.value.state() == HideManager.State.FAILED
                && !failed.value.reason().isEmpty(),
                "hide: HIDE_REQUESTED -> FAILED via fail(detail)",
                failed.ok ? failed.value.describe() : failed.error);
        HideManager.Transition back = failed.value.requestUnhide(77);
        check(back.ok && back.value.state() == HideManager.State.IDLE,
                "hide: FAILED -> IDLE via requestUnhide(pid)",
                back.ok ? back.value.describe() : back.error);

        HideManager pending = HideManager.initial().requestHide(55).value;
        HideManager.Transition cancel = pending.requestUnhide(55);
        check(cancel.ok && cancel.value.state() == HideManager.State.IDLE,
                "hide: HIDE_REQUESTED -> IDLE via requestUnhide(pid) (cancel)");

        check(confirmed.value.describe().contains("HIDDEN")
                && confirmed.value.describe().contains("1234"),
                "hide: describe() gives visible confirmation",
                confirmed.value.describe());
    }

    private static void hideFailures() {
        HideManager idle = HideManager.initial();
        check(!idle.requestHide(0).ok, "hide: requestHide(0) rejected");
        check(!idle.requestHide(-5).ok, "hide: requestHide(negative) rejected");
        check(!idle.requestUnhide(0).ok, "hide: requestUnhide(0) rejected");
        check(!idle.requestUnhide(-1).ok, "hide: requestUnhide(negative) rejected");

        HideManager pending = idle.requestHide(42).value;
        HideManager.Transition flat = pending.confirmHidden(3, 3);
        check(!flat.ok && flat.value == null && flat.error != null,
                "hide: confirmHidden(3,3) rejected (no increase)", flat.error);
        HideManager.Transition decreased = pending.confirmHidden(3, 1);
        check(!decreased.ok, "hide: confirmHidden(3,1) rejected (decrease)");
        HideManager.Transition negBefore = pending.confirmHidden(-1, 1);
        check(!negBefore.ok, "hide: confirmHidden(-1,1) rejected (negative before)");
        HideManager.Transition negAfter = pending.confirmHidden(0, -1);
        check(!negAfter.ok, "hide: confirmHidden(0,-1) rejected (negative after)");
        check(pending.state() == HideManager.State.HIDE_REQUESTED
                && !pending.isHidden(),
                "hide: rejected confirm leaves HIDE_REQUESTED, still visible");

        check(!idle.confirmHidden(0, 1).ok, "hide: confirmHidden from IDLE rejected");
        HideManager hidden = pending.confirmHidden(0, 2).value;
        check(!hidden.confirmHidden(2, 3).ok, "hide: confirmHidden from HIDDEN rejected");

        check(!pending.requestHide(99).ok, "hide: second requestHide without unhide rejected");
        check(!hidden.requestHide(99).ok, "hide: requestHide from HIDDEN rejected");

        check(!pending.fail(null).ok, "hide: fail(null) rejected");
        check(!pending.fail("   ").ok, "hide: fail(blank) rejected");
        HideManager.Transition f = pending.fail("timeout waiting for driver");
        check(f.ok && f.value.reason().contains("timeout"),
                "hide: fail(detail) carries reason",
                f.ok ? f.value.reason() : f.error);

        HideManager.Transition absent = idle.requestUnhide(9999);
        check(absent.ok && absent.value.state() == HideManager.State.IDLE,
                "hide: requestUnhide(absent pid) from IDLE is success",
                absent.ok ? absent.value.describe() : absent.error);
    }

    private static void hideNoAutoHide() {
        check(HideManager.initial().state() == HideManager.State.IDLE,
                "hide: no auto-hide at construction (initial is IDLE)");
        boolean noArgHide = false;
        String noArgName = "";
        for (java.lang.reflect.Method m : HideManager.class.getMethods()) {
            String n = m.getName();
            if (n.equals("requestHide") || n.equals("requestUnhide")
                    || n.equals("confirmHidden") || n.equals("fail")) {
                if (m.getParameterTypes().length == 0) {
                    noArgHide = true;
                    noArgName = n;
                }
            }
            String lower = n.toLowerCase(java.util.Locale.US);
            if (lower.contains("autohide") || lower.contains("hideatboot")
                    || lower.contains("hideonboot") || lower.equals("hide")
                    || lower.equals("boot")) {
                noArgHide = true;
                noArgName = n;
            }
        }
        check(!noArgHide, "hide: no method hides without an explicit request call"
                + (noArgName.isEmpty() ? "" : " (" + noArgName + ")"));
        boolean sigsOk;
        try {
            sigsOk = HideManager.class.getMethod("requestHide", int.class) != null
                    && HideManager.class.getMethod("requestUnhide", int.class) != null
                    && HideManager.class.getMethod("confirmHidden", int.class, int.class) != null;
        } catch (NoSuchMethodException e) {
            sigsOk = false;
        }
        check(sigsOk, "hide: request methods require explicit pid/count args");
    }

    // ---- MemdDriver ----

    private static void driverSelection() {
        MemdDriver.Selection both = MemdDriver.selectTransport(true, true);
        check(both.transport() == MemdDriver.Transport.JNI_DIRECT && both.isAvailable(),
                "driver: both available -> JNI_DIRECT (JNI preferred)");

        MemdDriver.Selection jniOnly = MemdDriver.selectTransport(true, false);
        check(jniOnly.transport() == MemdDriver.Transport.JNI_DIRECT && jniOnly.isAvailable(),
                "driver: JNI only -> JNI_DIRECT");

        MemdDriver.Selection rootOnly = MemdDriver.selectTransport(false, true);
        check(rootOnly.transport() == MemdDriver.Transport.ROOT_SHELL && rootOnly.isAvailable(),
                "driver: root only -> ROOT_SHELL");

        MemdDriver.Selection neither = MemdDriver.selectTransport(false, false);
        check(neither.transport() == MemdDriver.Transport.UNAVAILABLE && !neither.isAvailable(),
                "driver: neither available -> UNAVAILABLE");

        check(both.reason() != null && !both.reason().isEmpty(),
                "driver: JNI reason non-empty", String.valueOf(both.reason()));
        check(jniOnly.reason() != null && !jniOnly.reason().isEmpty(),
                "driver: JNI-only reason non-empty", String.valueOf(jniOnly.reason()));
        check(rootOnly.reason() != null && !rootOnly.reason().isEmpty(),
                "driver: root-shell reason non-empty", String.valueOf(rootOnly.reason()));
        check(neither.reason() != null && !neither.reason().isEmpty(),
                "driver: UNAVAILABLE reason non-empty", String.valueOf(neither.reason()));
        check(neither.reason().contains("JNI") && neither.reason().contains("root"),
                "driver: UNAVAILABLE reason names missing JNI bridge and root shell",
                neither.reason());
        check(both.describe().contains("JNI_DIRECT") && rootOnly.describe().contains("ROOT_SHELL")
                && neither.describe().contains("UNAVAILABLE"),
                "driver: describe mentions the chosen transport");
    }

    private static void driverRequire() {
        MemdDriver.TransportResult both = MemdDriver.requireTransport(true, true);
        check(both.ok && both.value != null && both.error == null
                && both.value.transport() == MemdDriver.Transport.JNI_DIRECT,
                "driver: require both -> ok JNI_DIRECT");

        MemdDriver.TransportResult jniOnly = MemdDriver.requireTransport(true, false);
        check(jniOnly.ok && jniOnly.value != null
                && jniOnly.value.transport() == MemdDriver.Transport.JNI_DIRECT,
                "driver: require JNI only -> ok JNI_DIRECT");

        MemdDriver.TransportResult rootOnly = MemdDriver.requireTransport(false, true);
        check(rootOnly.ok && rootOnly.value != null
                && rootOnly.value.transport() == MemdDriver.Transport.ROOT_SHELL,
                "driver: require root only -> ok ROOT_SHELL");

        MemdDriver.TransportResult neither = MemdDriver.requireTransport(false, false);
        check(!neither.ok && neither.value == null
                && neither.error != null && !neither.error.isEmpty(),
                "driver: require neither -> explicit error, no throw");
        check(neither.error != null && neither.error.contains("JNI")
                && neither.error.contains("root"),
                "driver: require-neither error names missing transports",
                String.valueOf(neither.error));
    }

    private static void driverSpecs() {
        check(MemdDriver.knownOps().equals(Arrays.asList(
                "version", "learnStatus", "hide", "unhide", "loadso", "unload")),
                "driver: knownOps pins the six-op contract");

        MemdDriver.SpecResult version = MemdDriver.callSpec("version");
        check(version.ok && version.value != null
                && "version".equals(version.value.op())
                && version.value.requiredFields().isEmpty()
                && version.value.optionalFields().isEmpty(),
                "driver: version takes no form fields");

        MemdDriver.SpecResult learnStatus = MemdDriver.callSpec("learnStatus");
        check(learnStatus.ok && learnStatus.value != null
                && "learnStatus".equals(learnStatus.value.op())
                && learnStatus.value.requiredFields().isEmpty(),
                "driver: learnStatus takes no form fields");

        MemdDriver.SpecResult hide = MemdDriver.callSpec("hide");
        check(hide.ok && hide.value != null
                && hide.value.requiredFields().equals(Arrays.asList("pid")),
                "driver: hide requires pid", hide.ok ? hide.value.describe() : hide.error);

        MemdDriver.SpecResult unhide = MemdDriver.callSpec("unhide");
        check(unhide.ok && unhide.value != null
                && unhide.value.requiredFields().equals(Arrays.asList("pid")),
                "driver: unhide requires pid", unhide.ok ? unhide.value.describe() : unhide.error);

        MemdDriver.SpecResult loadso = MemdDriver.callSpec("loadso");
        check(loadso.ok && loadso.value != null
                && loadso.value.requiredFields().equals(Arrays.asList("pid", "path")),
                "driver: loadso requires pid + path",
                loadso.ok ? loadso.value.describe() : loadso.error);
        check(loadso.ok && loadso.value.optionalFields().equals(
                Arrays.asList("entry", "su", "ephemeral")),
                "driver: loadso optionals are entry/su/ephemeral",
                loadso.ok ? loadso.value.describe() : loadso.error);

        MemdDriver.SpecResult unload = MemdDriver.callSpec("unload");
        check(unload.ok && unload.value != null
                && unload.value.requiredFields().equals(Arrays.asList("pid", "handle")),
                "driver: unload requires pid + handle",
                unload.ok ? unload.value.describe() : unload.error);

        check(loadso.ok && loadso.value.describe().contains("loadso")
                && loadso.value.describe().contains("pid"),
                "driver: describe summarizes op and fields",
                loadso.ok ? loadso.value.describe() : "loadso spec failed");

        List<String> required = loadso.value.requiredFields();
        boolean unmodifiable = false;
        try {
            required.add("evil");
        } catch (UnsupportedOperationException expected) {
            unmodifiable = true;
        }
        check(unmodifiable, "driver: requiredFields list unmodifiable");

        MemdDriver.SpecResult unknown = MemdDriver.callSpec("reboot");
        check(!unknown.ok && unknown.value == null
                && unknown.error != null && !unknown.error.isEmpty(),
                "driver: unknown op rejected with explicit error, no throw");
        check(!MemdDriver.callSpec(null).ok, "driver: null op rejected, no throw");
        check(!MemdDriver.callSpec("").ok, "driver: empty op rejected");
        check(!MemdDriver.callSpec("LOADSO").ok, "driver: op names case-sensitive");
    }

    // ---- RootShell ----

    /** Fake transport sharing the production Executor contract. */
    private static final class FakeExecutor implements RootShell.Executor {
        private final RootShell.ExecResult scripted;
        private final long sleepMs;
        private final RuntimeException toThrow;
        private final List<String> events;
        int calls = 0;

        FakeExecutor(RootShell.ExecResult scripted, List<String> events) {
            this.scripted = scripted;
            this.sleepMs = 0;
            this.toThrow = null;
            this.events = events;
        }

        FakeExecutor(long sleepMs, RootShell.ExecResult afterSleep, List<String> events) {
            this.scripted = afterSleep;
            this.sleepMs = sleepMs;
            this.toThrow = null;
            this.events = events;
        }

        FakeExecutor(RuntimeException toThrow, List<String> events) {
            this.scripted = null;
            this.sleepMs = 0;
            this.toThrow = toThrow;
            this.events = events;
        }

        @Override
        public RootShell.ExecResult exec(String[] argv, long timeoutMs) throws Exception {
            calls++;
            if (events != null) {
                events.add("exec");
            }
            if (toThrow != null) {
                throw toThrow;
            }
            if (sleepMs > 0) {
                Thread.sleep(sleepMs);
            }
            return scripted;
        }
    }

    private static final class ListSink implements RootShell.LogSink {
        final List<String> lines = new java.util.ArrayList<String>();
        final List<String> events;

        ListSink(List<String> events) {
            this.events = events;
        }

        @Override
        public void log(String line) {
            lines.add(line);
            if (events != null) {
                events.add("log:" + line);
            }
        }
    }

    private static final class RecordingTimeoutExec implements RootShell.Executor {
        long seen = -1;

        @Override
        public RootShell.ExecResult exec(String[] argv, long timeoutMs) {
            seen = timeoutMs;
            return RootShell.ExecResult.completed(0, "", "");
        }
    }

    private static void rootshellSuccess() {
        List<String> events = new java.util.ArrayList<String>();
        ListSink sink = new ListSink(events);
        FakeExecutor fake = new FakeExecutor(
                RootShell.ExecResult.completed(0, "hello\n", ""), events);
        RootShell.Result r = RootShell.runAsRoot(
                new String[]{"/bin/echo", "hello"}, 5000L, sink, fake);
        check(r.status == RootShell.Status.OK && r.exitCode == 0
                && "hello\n".equals(r.stdout),
                "rootshell: success echo maps to OK");
        check(fake.calls == 1, "rootshell: executor invoked exactly once on success");
        check(sink.lines.size() == 1 && "/bin/echo hello".equals(sink.lines.get(0)),
                "rootshell: exact command line logged", sink.lines.toString());
    }

    private static void rootshellTimeout() {
        // Case A: executor itself reports a kill.
        ListSink sinkA = new ListSink(null);
        FakeExecutor selfReport = new FakeExecutor(
                RootShell.ExecResult.timedOut("", "killed"), null);
        RootShell.Result a = RootShell.runAsRoot(
                new String[]{"/system/bin/sleep", "30"}, 1000L, sinkA, selfReport);
        check(a.status == RootShell.Status.TIMEOUT,
                "rootshell: executor-reported kill maps to TIMEOUT");

        // Case B: runAsRoot enforces the deadline on a hung transport.
        List<String> events = new java.util.ArrayList<String>();
        ListSink sinkB = new ListSink(events);
        FakeExecutor hung = new FakeExecutor(
                10000L, RootShell.ExecResult.completed(0, "late", ""), events);
        long t0 = System.currentTimeMillis();
        RootShell.Result b = RootShell.runAsRoot(
                new String[]{"/system/bin/sleep", "30"}, 1000L, sinkB, hung);
        long elapsed = System.currentTimeMillis() - t0;
        check(b.status == RootShell.Status.TIMEOUT,
                "rootshell: hung executor killed and reported TIMEOUT");
        check(elapsed < 8000L,
                "rootshell: deadline enforced promptly (elapsed=" + elapsed + "ms)");
        check(sinkB.lines.size() == 1, "rootshell: timeout still logged the command first");
    }

    private static void rootshellDenied() {
        ListSink sink = new ListSink(null);
        int[] codes = {126, 127, 255};
        for (int code : codes) {
            FakeExecutor fake = new FakeExecutor(
                    RootShell.ExecResult.completed(code, "", "exit " + code), null);
            RootShell.Result r = RootShell.runAsRoot(
                    new String[]{"/system/bin/tool"}, 5000L, sink, fake);
            check(r.status == RootShell.Status.DENIED && r.exitCode == code,
                    "rootshell: exit " + code + " maps to DENIED");
        }
        // Non-zero exit plus denial text on stderr.
        FakeExecutor textDenied = new FakeExecutor(
                RootShell.ExecResult.completed(1, "", "su: permission denied"), null);
        RootShell.Result d = RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 5000L, sink, textDenied);
        check(d.status == RootShell.Status.DENIED,
                "rootshell: denial output pattern maps to DENIED");

        // Plain non-zero exit without denial signals is FAILED, not DENIED.
        FakeExecutor plain = new FakeExecutor(
                RootShell.ExecResult.completed(2, "", "usage: tool [--flag]"), null);
        RootShell.Result f = RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 5000L, sink, plain);
        check(f.status == RootShell.Status.FAILED && f.exitCode == 2,
                "rootshell: plain exit 2 maps to FAILED");

        // Transport exception is ERROR, never a silent fallback.
        FakeExecutor boom = new FakeExecutor(new RuntimeException("EPIPE"), null);
        RootShell.Result e = RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 5000L, sink, boom);
        check(e.status == RootShell.Status.ERROR,
                "rootshell: executor exception maps to ERROR");
    }

    private static void rootshellValidation() {
        ListSink sink = new ListSink(null);
        FakeExecutor fake = new FakeExecutor(
                RootShell.ExecResult.completed(0, "x", ""), null);

        check(RootShell.runAsRoot(null, 5000L, sink, fake).status == RootShell.Status.ERROR,
                "rootshell: null argv rejected");
        check(RootShell.runAsRoot(new String[]{}, 5000L, sink, fake).status == RootShell.Status.ERROR,
                "rootshell: empty argv rejected");
        check(RootShell.runAsRoot(
                new String[]{"bin/tool"}, 5000L, sink, fake).status == RootShell.Status.ERROR,
                "rootshell: relative binary rejected");
        check(RootShell.runAsRoot(
                new String[]{""}, 5000L, sink, fake).status == RootShell.Status.ERROR,
                "rootshell: empty binary rejected");
        check(RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 999L, sink, fake).status == RootShell.Status.ERROR,
                "rootshell: timeout below 1s rejected");
        check(RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 0L, sink, fake).status == RootShell.Status.ERROR,
                "rootshell: timeout 0 rejected");
        check(RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 300001L, sink, fake).status == RootShell.Status.ERROR,
                "rootshell: timeout above 5min rejected");
        check(RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 5000L, null, fake).status == RootShell.Status.ERROR,
                "rootshell: null logSink rejected");
        check(RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 5000L, sink, null).status == RootShell.Status.ERROR,
                "rootshell: null executor rejected");

        int callsBefore = fake.calls;
        int loggedBefore = sink.lines.size();
        RootShell.runAsRoot(new String[]{"relative/tool"}, 5000L, sink, fake);
        check(fake.calls == callsBefore,
                "rootshell: rejected input never reaches the executor");
        check(sink.lines.size() == loggedBefore,
                "rootshell: rejected input logs nothing");

        // Boundary timeouts are accepted (executor echoes them back).
        RecordingTimeoutExec rec = new RecordingTimeoutExec();
        RootShell.Result lo = RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 1000L, sink, rec);
        check(lo.status == RootShell.Status.OK && rec.seen == 1000L,
                "rootshell: 1s lower-bound timeout accepted");
        RootShell.Result hi = RootShell.runAsRoot(
                new String[]{"/system/bin/tool"}, 300000L, sink, rec);
        check(hi.status == RootShell.Status.OK && rec.seen == 300000L,
                "rootshell: 5min upper-bound timeout accepted");
    }

    private static void rootshellLogBeforeRun() {
        List<String> events = new java.util.ArrayList<String>();
        ListSink sink = new ListSink(events);
        FakeExecutor fake = new FakeExecutor(
                RootShell.ExecResult.completed(0, "ok", ""), events);
        String[] argv = {"/system/bin/cmd", "a b", "c"};
        RootShell.Result r = RootShell.runAsRoot(argv, 5000L, sink, fake);
        check(r.status == RootShell.Status.OK, "rootshell: ordering run completes OK");
        check(events.size() == 2 && events.get(0).startsWith("log:") && "exec".equals(events.get(1)),
                "rootshell: log emitted BEFORE executor runs", events.toString());
        String expected = RootShell.joinCommand(argv);
        check(expected.equals(sink.lines.get(0)) && events.get(0).equals("log:" + expected),
                "rootshell: logged line is the exact command", events.toString());
        // Quoting proof: the arg with a space must be quoted in the log.
        check(expected.contains("'a b'"),
                "rootshell: args with spaces are quoted in the log", expected);
    }

    // ---- ModuleRegistry ----

    private static ModuleRegistry.Record validRecord(String id, String code, long handle) {
        ModuleRegistry.RecordResult r = ModuleRegistry.Record.create(
                id, "Name of " + id, "1.0", code, handle, handle != 0);
        check(r.ok && r.value != null, "registry: fixture create ok for " + id,
                r.ok ? "" : String.valueOf(r.error));
        return r.value;
    }

    private static void registryUpsertListRemove() {
        ModuleRegistry reg = new ModuleRegistry();
        check(reg.size() == 0 && reg.list().isEmpty(), "registry: starts empty");

        check(!reg.upsert(null).ok, "registry: upsert(null) rejected, no throw");
        check(reg.upsert(null).record == null, "registry: failed upsert carries null record");

        check(reg.upsert(validRecord("b.mod", "2", 200L)).ok, "registry: upsert b.mod");
        check(reg.upsert(validRecord("a.mod", "1", 100L)).ok, "registry: upsert a.mod");
        check(reg.upsert(validRecord("c-mod_1", "3", 0L)).ok, "registry: upsert c-mod_1 (handle none)");
        check(reg.size() == 3, "registry: size tracks upserts");

        List<ModuleRegistry.Record> all = reg.list();
        check(all.size() == 3
                && "a.mod".equals(all.get(0).id())
                && "b.mod".equals(all.get(1).id())
                && "c-mod_1".equals(all.get(2).id()),
                "registry: list sorted by id", all.toString());

        boolean unmodifiable = false;
        try {
            all.add(validRecord("z.mod", "9", 900L));
        } catch (UnsupportedOperationException expected) {
            unmodifiable = true;
        }
        check(unmodifiable, "registry: list snapshot unmodifiable");
        check(reg.size() == 3, "registry: mutating snapshot does not affect registry");

        ModuleRegistry.WriteResult removed = reg.remove("b.mod");
        check(removed.ok && removed.record != null && "b.mod".equals(removed.record.id()),
                "registry: remove returns stored record");
        check(reg.size() == 2, "registry: size shrinks after remove");

        ModuleRegistry.WriteResult again = reg.remove("b.mod");
        check(!again.ok && again.record == null && again.error != null && !again.error.isEmpty(),
                "registry: double remove explicit failure, record null");

        ModuleRegistry.WriteResult unknown = reg.remove("ghost.mod");
        check(!unknown.ok && unknown.error != null, "registry: remove unknown id rejected");

        ModuleRegistry.WriteResult badId = reg.remove("../evil");
        check(!badId.ok && badId.error != null, "registry: remove traversal id rejected");
        ModuleRegistry.WriteResult nullId = reg.remove(null);
        check(!nullId.ok && nullId.error != null, "registry: remove(null) rejected, no throw");
    }

    private static void registryIdValidation() {
        check(!ModuleRegistry.Record.create(null, "n", "1", "1", 0L, false).ok,
                "registry: null id rejected");
        check(!ModuleRegistry.Record.create("", "n", "1", "1", 0L, false).ok,
                "registry: empty id rejected");
        check(!ModuleRegistry.Record.create("../evil", "n", "1", "1", 0L, false).ok,
                "registry: traversal ../evil rejected");
        check(!ModuleRegistry.Record.create("a/b", "n", "1", "1", 0L, false).ok,
                "registry: slash in id rejected");
        check(!ModuleRegistry.Record.create("/abs", "n", "1", "1", 0L, false).ok,
                "registry: absolute id rejected");
        check(!ModuleRegistry.Record.create("..", "n", "1", "1", 0L, false).ok,
                "registry: bare .. rejected");
        check(!ModuleRegistry.Record.create(".", "n", "1", "1", 0L, false).ok,
                "registry: bare . rejected");
        check(!ModuleRegistry.Record.create("a b", "n", "1", "1", 0L, false).ok,
                "registry: space in id rejected");
        check(!ModuleRegistry.Record.create("mod!", "n", "1", "1", 0L, false).ok,
                "registry: bang in id rejected");
        check(!ModuleRegistry.Record.create("mod\\x", "n", "1", "1", 0L, false).ok,
                "registry: backslash in id rejected");

        check(ModuleRegistry.Record.create("a", "n", "1", "1", 0L, false).ok,
                "registry: single-char id accepted");
        check(ModuleRegistry.Record.create("my.mod-1_2", "n", "1", "1", 0L, false).ok,
                "registry: [A-Za-z0-9._-] id accepted");
        check(ModuleRegistry.Record.create("A9", "n", "1", "1", 0L, false).ok,
                "registry: alnum id accepted");

        check(!ModuleRegistry.Record.create("ok.mod", "n", "1", null, 0L, false).ok,
                "registry: null versionCode rejected");
        check(!ModuleRegistry.Record.create("ok.mod", "n", "1", "", 0L, false).ok,
                "registry: empty versionCode rejected");
        check(!ModuleRegistry.Record.create("ok.mod", "n", "1", "   ", 0L, false).ok,
                "registry: blank versionCode rejected");
        check(ModuleRegistry.Record.create("ok.mod", "n", "1", "1.2b", 0L, false).ok,
                "registry: non-numeric versionCode representable (ordering falls back to lexical)");
        check(!ModuleRegistry.Record.create("ok.mod", "n", "1", "1", -1L, false).ok,
                "registry: negative handle rejected");

        ModuleRegistry.RecordResult nulled = ModuleRegistry.Record.create(
                "nulls.mod", null, null, "7", 0L, false);
        check(nulled.ok && "".equals(nulled.value.name()) && "".equals(nulled.value.version())
                && "7".equals(nulled.value.versionCode()),
                "registry: null name/version normalize to empty");

        ModuleRegistry.RecordResult bad = ModuleRegistry.Record.create("", "n", "1", "1", 0L, false);
        check(!bad.ok && bad.value == null && bad.error != null && !bad.error.isEmpty(),
                "registry: error value carries message, value is null");

        ModuleRegistry.Record r1 = ModuleRegistry.Record.create(
                "eq.mod", "N", "1.0", "5", 42L, true).value;
        ModuleRegistry.Record r2 = ModuleRegistry.Record.create(
                "eq.mod", "N", "1.0", "5", 42L, true).value;
        check(r1.equals(r2) && r1.hashCode() == r2.hashCode(),
                "registry: equals/hashCode consistent");
        check(!r1.equals(ModuleRegistry.Record.create(
                "other.mod", "N", "1.0", "5", 42L, true).value),
                "registry: different id not equal");
        check(r1.describe().contains("eq.mod") && r1.describe().contains("5")
                && r1.describe().contains("resident"),
                "registry: describe mentions id/code/residency", r1.describe());
    }

    private static void registryVersionOrdering() {
        check(ModuleRegistry.compareVersionCode("9", "10") < 0,
                "registry: numeric 9 < 10 (lexical would say otherwise)");
        check(ModuleRegistry.compareVersionCode("10", "9") > 0,
                "registry: numeric 10 > 9");
        check(ModuleRegistry.compareVersionCode("007", "7") == 0,
                "registry: leading zeros compare numerically equal");
        check(ModuleRegistry.compareVersionCode("2", "2") == 0,
                "registry: equal codes compare 0");
        check(ModuleRegistry.compareVersionCode("1.2a", "1.10") > 0,
                "registry: non-numeric falls back to lexical (\"1.2a\" > \"1.10\")");
        check(ModuleRegistry.compareVersionCode("beta", "alpha") > 0,
                "registry: alpha < beta lexically");
        check(ModuleRegistry.compareVersionCode("rc1", "rc1") == 0,
                "registry: identical non-numeric codes equal");
        check(ModuleRegistry.compareVersionCode(null, "1") < 0,
                "registry: null normalizes to empty, no throw");
        check(ModuleRegistry.compareVersionCode(null, null) == 0,
                "registry: null vs null equal, no throw");
        check(ModuleRegistry.compareVersionCode("99999999999999999999", "100") > 0,
                "registry: long-overflow falls back to lexical ('9...' > '100')");
    }

    private static void registryFindReplace() {
        ModuleRegistry reg = new ModuleRegistry();
        reg.upsert(validRecord("m.mod", "1", 111L));

        ModuleRegistry.FindResult hit = reg.findByHandle(111L);
        check(hit.ok && hit.value != null && "m.mod".equals(hit.value.id()),
                "registry: findByHandle hits stored record");

        ModuleRegistry.FindResult miss = reg.findByHandle(999L);
        check(!miss.ok && miss.value == null && miss.error != null && !miss.error.isEmpty(),
                "registry: findByHandle miss explicit failure, value null");

        ModuleRegistry.FindResult neg = reg.findByHandle(-5L);
        check(!neg.ok && neg.error != null,
                "registry: findByHandle negative rejected, no throw");

        // Duplicate upsert = last-write-wins full replace (documented semantics).
        ModuleRegistry.Record v1 = ModuleRegistry.Record.create(
                "dup.mod", "Dup", "1.0", "1", 111L, false).value;
        ModuleRegistry.Record v2 = ModuleRegistry.Record.create(
                "dup.mod", "Dup", "2.0", "2", 222L, true).value;
        check(reg.upsert(v1).ok, "registry: upsert dup.mod v1");
        check(reg.size() == 2, "registry: first dup upsert adds one entry");
        ModuleRegistry.WriteResult rep = reg.upsert(v2);
        check(rep.ok && rep.record != null && "2".equals(rep.record.versionCode())
                && rep.record.resident(),
                "registry: duplicate upsert replaces (last-write-wins)");
        check(reg.size() == 2, "registry: replace does not grow the registry");
        ModuleRegistry.FindResult stale = reg.findByHandle(111L);
        check(!stale.ok || !"dup.mod".equals(stale.value.id()),
                "registry: old handle no longer maps to dup.mod");
        ModuleRegistry.FindResult now = reg.findByHandle(222L);
        check(now.ok && "dup.mod".equals(now.value.id()) && "2.0".equals(now.value.version()),
                "registry: new handle maps to replaced record");

        // No version gate on write: a lower versionCode still replaces.
        ModuleRegistry.Record v0 = ModuleRegistry.Record.create(
                "dup.mod", "Dup", "0.9", "0", 333L, false).value;
        check(reg.upsert(v0).ok, "registry: downgrade upsert accepted (no write gate)");
        check("0".equals(reg.findByHandle(333L).value.versionCode()),
                "registry: downgrade stored as-is");
    }
}
