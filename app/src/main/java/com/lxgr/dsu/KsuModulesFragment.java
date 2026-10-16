package com.lxgr.dsu;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * KSU Modules tab: honest UNSUPPORTED placeholder.
 *
 * KernelSU integration does NOT exist upstream in this build: no KernelSU
 * sources are vendored here, so this tab lists no modules and fabricates no
 * module data. The refresh action is present but disabled, with copy
 * explaining why it cannot run.
 */
public class KsuModulesFragment extends Fragment {

    /** No-argument constructor required for fragment re-instantiation. */
    public KsuModulesFragment() {
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        LinearLayout layout = new LinearLayout(getActivity());
        layout.setOrientation(LinearLayout.VERTICAL);

        TextView title = new TextView(getActivity());
        title.setText("KSU Modules");
        layout.addView(title);

        TextView expl = new TextView(getActivity());
        expl.setText("KernelSU integration is unavailable in this build. "
                + "KernelSU upstream sources are not vendored in this "
                + "repository, so no KernelSU module list can be shown here "
                + "and none is fabricated. If KernelSU support is added in a "
                + "future build, modules will appear here.");
        layout.addView(expl);

        Button refresh = new Button(getActivity());
        refresh.setText("Refresh");
        refresh.setEnabled(false);
        layout.addView(refresh);

        TextView whyDisabled = new TextView(getActivity());
        whyDisabled.setText("Refresh is disabled: there is no KernelSU "
                + "upstream in this build to refresh from.");
        layout.addView(whyDisabled);

        return layout;
    }
}
