package com.lxgr.dsu;

import android.app.Activity;
import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * MEMD Modules sub-tab: renders a list of {@link ModuleListItem}.
 *
 * <p>States handled explicitly:
 * <ul>
 *   <li>loading — "Loading MEMD modules…"</li>
 *   <li>error — error message plus a Retry button</li>
 *   <li>empty — "no resident modules recorded"</li>
 *   <li>list — one row per item with Install / Hotswap / Uninstall buttons</li>
 * </ul>
 *
 * <p>No stealth: this fragment executes NO privileged operations and spawns
 * NOTHING silently. The Install / Hotswap / Uninstall / Retry buttons only
 * call back through {@link ModuleActions}, which the hosting Activity (or
 * later wiring) implements. All privileged work stays user-initiated with
 * visible confirmation outside this fragment.
 */
public class MemdModulesFragment extends Fragment {

    /**
     * Callback implemented by the hosting Activity (or later code) to handle
     * user-initiated module actions. The fragment never performs the actions
     * itself.
     */
    public interface ModuleActions {
        void onInstallRequested(ModuleListItem item);
        void onHotswapRequested(ModuleListItem item);
        void onUninstallRequested(ModuleListItem item);
        void onRetryRequested();
    }

    private List<ModuleListItem> modules = Collections.emptyList();
    private boolean loading = false;
    private String errorMessage = null;
    private ModuleActions actions = null;
    private TextView noticeView = null;
    private LinearLayout root = null;

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        if (activity instanceof ModuleActions) {
            actions = (ModuleActions) activity;
        }
    }

    @Override
    public void onDetach() {
        super.onDetach();
        actions = null;
    }

    /** Explicit wiring; also auto-wired via onAttach when the host implements it. */
    public void setModuleActions(ModuleActions actions) {
        this.actions = actions;
    }

    /** Replace the rendered module list (null clears to empty). */
    public void setModules(List<ModuleListItem> items) {
        if (items == null) {
            this.modules = Collections.emptyList();
        } else {
            this.modules = new ArrayList<ModuleListItem>(items);
        }
        this.loading = false;
        this.errorMessage = null;
        refreshView();
    }

    public void setLoading(boolean loading) {
        this.loading = loading;
        if (loading) {
            this.errorMessage = null;
        }
        refreshView();
    }

    /** Show the error state; null/empty message clears back to empty/list. */
    public void setError(String message) {
        this.errorMessage = message;
        this.loading = false;
        refreshView();
    }

    public void clearError() {
        this.errorMessage = null;
        refreshView();
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        root = new LinearLayout(getActivity());
        root.setOrientation(LinearLayout.VERTICAL);

        TextView header = new TextView(getActivity());
        header.setText("MEMD Modules. Actions here only notify the host activity; "
                + "nothing is installed, swapped, or removed until you confirm "
                + "the explicit action there. No driver connection is attempted "
                + "by this tab on its own.");
        root.addView(header);

        noticeView = new TextView(getActivity());
        root.addView(noticeView);

        refreshView();
        return root;
    }

    private void refreshView() {
        if (root == null || getActivity() == null) {
            return;
        }
        // Keep header (0) + notice (1); drop previously rendered rows.
        while (root.getChildCount() > 2) {
            root.removeViewAt(2);
        }
        noticeView.setText("");

        if (loading) {
            noticeView.setText("Loading MEMD modules…");
            return;
        }

        if (errorMessage != null && !errorMessage.isEmpty()) {
            noticeView.setText("MEMD module list failed: " + errorMessage);
            Button retry = new Button(getActivity());
            retry.setText("Retry");
            retry.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (actions != null) {
                        actions.onRetryRequested();
                    } else {
                        noticeView.setText("Retry requested — no handler wired, "
                                + "nothing was executed.");
                    }
                }
            });
            root.addView(retry);
            return;
        }

        if (modules.isEmpty()) {
            noticeView.setText("no resident modules recorded");
            return;
        }

        for (final ModuleListItem item : modules) {
            LinearLayout row = new LinearLayout(getActivity());
            row.setOrientation(LinearLayout.VERTICAL);

            TextView summary = new TextView(getActivity());
            summary.setText(item.toSummary());
            row.addView(summary);

            LinearLayout buttons = new LinearLayout(getActivity());
            buttons.setOrientation(LinearLayout.HORIZONTAL);

            Button install = new Button(getActivity());
            install.setText("Install");
            install.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (actions != null) {
                        actions.onInstallRequested(item);
                    } else {
                        noticeView.setText("Install requested for " + item.getId()
                                + " — no handler wired, nothing was executed.");
                    }
                }
            });
            buttons.addView(install);

            Button hotswap = new Button(getActivity());
            hotswap.setText("Hotswap");
            hotswap.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (actions != null) {
                        actions.onHotswapRequested(item);
                    } else {
                        noticeView.setText("Hotswap requested for " + item.getId()
                                + " — no handler wired, nothing was executed.");
                    }
                }
            });
            buttons.addView(hotswap);

            Button uninstall = new Button(getActivity());
            uninstall.setText("Uninstall");
            uninstall.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (actions != null) {
                        actions.onUninstallRequested(item);
                    } else {
                        noticeView.setText("Uninstall requested for " + item.getId()
                                + " — no handler wired, nothing was executed.");
                    }
                }
            });
            buttons.addView(uninstall);

            row.addView(buttons);
            root.addView(row);
        }
    }
}
