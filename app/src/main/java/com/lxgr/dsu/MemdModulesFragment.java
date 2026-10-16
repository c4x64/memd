package com.lxgr.dsu;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

/**
 * MEMD Modules sub-tab (stub).
 *
 * Wired to nothing yet: shows the no-driver-connection state. Future work
 * will list MEMD/Zygisk-scheme modules installed via loadsotoapp /
 * loadsosutoapp (see INTEGRATION.md) once a verified driver channel exists.
 * Kept distinct from the KSU Modules placeholder tab.
 */
public class MemdModulesFragment extends Fragment {

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        TextView view = new TextView(getActivity());
        view.setText("MEMD Modules: no driver connection. "
                + "Module list unavailable — driver channel not implemented in this stub.");
        return view;
    }
}
