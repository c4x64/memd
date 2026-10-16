package com.lxgr.dsu;

import android.app.Activity;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TabHost;
import android.widget.TextView;

/**
 * DSU entry Activity.
 *
 * Three tabs (greenfield — there is no existing KSU modules page in this
 * repo, so these tabs are our own, see README):
 *   MEMD Modules — MEMD/Zygisk-scheme module list (stub, see MemdModulesFragment).
 *   KSU Modules  — UNSUPPORTED placeholder: KernelSU/DirtyFrag upstreams are
 *                  NOT vendored in this repo, so this tab explains that.
 *   Settings     — explicit opt-in boot-load toggle (see SettingsFragment).
 *
 * No driver connection is attempted here. Every privileged action must be
 * user-initiated, visible, and explained in UI copy (no stealth/persistence).
 */
public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TabHost tabs = new TabHost(this);
        tabs.setup();

        // Tab content hosts (plain views; fragments are scaffold stubs only).
        LinearLayout memdContent = tabContent("No driver connection. "
                + "MEMD module list is not wired yet — see MEMD Modules tab stub.");
        LinearLayout ksuContent = tabContent("KSU Modules: UNSUPPORTED. "
                + "KernelSU / DirtyFrag upstreams are NOT vendored in this repo, "
                + "so KernelSU module management is unavailable in this build.");
        LinearLayout settingsContent = tabContent("Boot-load MEMD at startup: OFF (default). "
                + "Enable only via Settings toggle. Loading at boot is never silent.");

        tabs.addView(memdContent);
        tabs.addView(ksuContent);
        tabs.addView(settingsContent);

        addTab(tabs, "memd", "MEMD Modules", memdContent.getId());
        addTab(tabs, "ksu", "KSU Modules", ksuContent.getId());
        addTab(tabs, "settings", "Settings", settingsContent.getId());

        setContentView(tabs);
    }

    private static int nextId = 0x1000;

    private LinearLayout tabContent(String text) {
        LinearLayout layout = new LinearLayout(this);
        layout.setId(++nextId);
        layout.setOrientation(LinearLayout.VERTICAL);
        TextView view = new TextView(this);
        view.setText(text);
        layout.addView(view);
        return layout;
    }

    private void addTab(TabHost tabs, String tag, String label, int contentId) {
        TabHost.TabSpec spec = tabs.newTabSpec(tag);
        spec.setIndicator(label);
        spec.setContent(contentId);
        tabs.addTab(spec);
    }
}
