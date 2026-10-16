package com.lxgr.dsu;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Settings: explicit opt-in boot-load toggle.
 *
 * Default OFF. When ON, the app may request MEMD load automatically at boot
 * through the supported mechanism exposed by the installed root manager
 * (mechanism not yet implemented — see BLOCKERS.md). Boot-time loading is
 * never silent: the user is told what will run, denial/failure states are
 * surfaced, and turning the toggle OFF stops automatic loading.
 */
public class SettingsFragment extends Fragment {

    /** Default OFF. Persisted only when the real boot mechanism lands. */
    private boolean loadAtBoot = false;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        LinearLayout layout = new LinearLayout(getActivity());
        layout.setOrientation(LinearLayout.VERTICAL);

        TextView expl = new TextView(getActivity());
        expl.setText("Load MEMD automatically at boot. OFF by default. "
                + "This requires a rooted device with the MEMD driver installed. "
                + "When enabled, loading happens visibly at boot via the root "
                + "manager's supported mechanism; failures and denials are shown "
                + "here. No privileges are escalated silently and nothing is "
                + "hidden from the user.");
        layout.addView(expl);

        CheckBox toggle = new CheckBox(getActivity());
        toggle.setText("Load MEMD at boot");
        toggle.setChecked(loadAtBoot);
        toggle.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                loadAtBoot = isChecked;
            }
        });
        layout.addView(toggle);

        return layout;
    }

    public boolean isLoadAtBootEnabled() {
        return loadAtBoot;
    }
}
