package com.lxgr.dsu;

import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.os.Bundle;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TabHost;
import android.widget.TabWidget;
import android.widget.Toast;

/**
 * DSU entry Activity.
 *
 * Bottom/tab navigation across three fragments (each with a no-argument
 * constructor and an explicit user-visible label):
 *   MEMD Modules — MEMD/Zygisk-scheme module list (stub, see MemdModulesFragment).
 *   KSU Modules  — UNSUPPORTED placeholder: KernelSU upstreams are NOT
 *                  vendored in this build, so no module data is shown
 *                  (see KsuModulesFragment).
 *   Settings     — explicit opt-in boot-load toggle (see SettingsFragment).
 *
 * No driver connection is attempted here. Every privileged action must be
 * user-initiated, visible, and explained in UI copy (no stealth/persistence).
 */
public class MainActivity extends Activity implements TabHost.OnTabChangeListener,
        MemdModulesFragment.ModuleActions {

    private static final String TAG_MEMD = "memd";
    private static final String TAG_KSU = "ksu";
    private static final String TAG_SETTINGS = "settings";

    private TabHost tabs;
    /** Fixed view id for the fragment container (avoids API-17 generateViewId). */
    private static final int FRAGMENT_CONTAINER_ID = 0x7f000001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);

        tabs = new TabHost(this);
        tabs.setId(android.R.id.tabhost);
        tabs.setup();

        TabWidget tabWidget = new TabWidget(this);
        tabWidget.setId(android.R.id.tabs);

        FrameLayout tabContent = new FrameLayout(this);
        tabContent.setId(android.R.id.tabcontent);
        tabContent.setVisibility(View.GONE);

        FrameLayout fragmentContainer = new FrameLayout(this);
        fragmentContainer.setId(FRAGMENT_CONTAINER_ID);

        LinearLayout tabLayout = new LinearLayout(this);
        tabLayout.setOrientation(LinearLayout.VERTICAL);
        tabLayout.addView(tabWidget);
        tabLayout.addView(tabContent, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 0f));
        tabs.addView(tabLayout);

        root.addView(tabs, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));
        root.addView(fragmentContainer, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT, 1f));

        addTab(TAG_MEMD, "MEMD Modules");
        addTab(TAG_KSU, "KSU Modules");
        addTab(TAG_SETTINGS, "Settings");

        tabs.setOnTabChangedListener(this);

        setContentView(root);

        if (savedInstanceState == null) {
            tabs.setCurrentTabByTag(TAG_MEMD);
            showFragment(TAG_MEMD);
        } else {
            showFragment(tabs.getCurrentTabTag());
        }
    }

    private void addTab(String tag, String label) {
        TabHost.TabSpec spec = tabs.newTabSpec(tag);
        spec.setIndicator(label);
        spec.setContent(new TabHost.TabContentFactory() {
            @Override
            public View createTabContent(String tabTag) {
                View stub = new View(MainActivity.this);
                stub.setMinimumWidth(0);
                stub.setMinimumHeight(0);
                return stub;
            }
        });
        tabs.addTab(spec);
    }

    @Override
    public void onTabChanged(String tabId) {
        showFragment(tabId);
    }

    /* ModuleActions: the driver bridge is not wired yet, so every
     * request is acknowledged visibly and executed never. This keeps
     * the no-silent-action contract: the user always sees what
     * happened (nothing), and why. */
    @Override
    public void onInstallRequested(ModuleListItem item) {
        showPending(item == null ? null : item.getId(), "Install");
    }

    @Override
    public void onHotswapRequested(ModuleListItem item) {
        showPending(item == null ? null : item.getId(), "Hotswap");
    }

    @Override
    public void onUninstallRequested(ModuleListItem item) {
        showPending(item == null ? null : item.getId(), "Uninstall");
    }

    @Override
    public void onRetryRequested() {
        Toast.makeText(this, "Retry requested — driver bridge pending,"
                + " nothing was executed.", Toast.LENGTH_LONG).show();
    }

    private void showPending(String id, String action) {
        String target = (id == null || id.length() == 0) ? "module" : id;
        Toast.makeText(this, action + " requested for " + target
                + " — driver bridge pending, nothing was executed.",
                Toast.LENGTH_LONG).show();
    }

    private void showFragment(String tag) {
        Fragment fragment;
        if (TAG_KSU.equals(tag)) {
            fragment = new KsuModulesFragment();
        } else if (TAG_SETTINGS.equals(tag)) {
            fragment = new SettingsFragment();
        } else {
            fragment = new MemdModulesFragment();
        }
        FragmentTransaction tx = getFragmentManager().beginTransaction();
        tx.replace(FRAGMENT_CONTAINER_ID, fragment, tag);
        tx.commit();
    }
}
