package it.spydetector.app.core;

import android.app.ActivityManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.provider.Settings;
import android.provider.Telephony;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Lettura dello stato reale dei "canali di sorveglianza" dell'OS:
 * accessibilita', lettura notifiche, admin del dispositivo, overlay, tastiere,
 * VPN, app SMS/browser predefinite, debug USB, posizione finta.
 *
 * Tutto viene letto con API pubbliche o impostazioni leggibili; quando un dato
 * non e' accessibile senza permessi speciali lo stato resta "non determinato"
 * invece di essere inventato.
 */
public final class AccessState {

    public final List<String> accessibilityComponents = new ArrayList<>();
    public final List<String> notificationComponents = new ArrayList<>();
    public final List<String> deviceAdmins = new ArrayList<>();
    public final List<String> enabledInputMethods = new ArrayList<>();
    public boolean adbEnabled;
    public boolean mockLocationEnabled;
    public boolean vpnActive;
    public String vpnPackage = "";
    public String defaultSmsPackage = "";
    public String defaultBrowserPackage = "";
    public boolean servicesReadable;

    private AccessState() {}

    private static String secure(ContentResolver cr, String key) {
        try {
            String v = Settings.Secure.getString(cr, key);
            return v == null ? "" : v;
        } catch (Throwable t) {
            return "";
        }
    }

    private static String global(ContentResolver cr, String key) {
        try {
            int v = Settings.Global.getInt(cr, key);
            return String.valueOf(v);
        } catch (Throwable t) {
            return "";
        }
    }

    public static AccessState read(Context ctx) {
        AccessState st = new AccessState();
        ContentResolver cr = ctx.getContentResolver();

        // --- Servizi di accessibilita' -------------------------------------
        // Su Android 9+ l'elenco e' leggibile dalle impostazioni secure; se il
        // sistema lo nasconde la stringa resta vuota (nessuna invenzione).
        String acc = secure(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        st.servicesReadable = !acc.isEmpty();
        for (String c : acc.split(":")) {
            if (!c.trim().isEmpty()) st.accessibilityComponents.add(c.trim());
        }

        // --- Lettura notifiche (Notification Listener) ---------------------
        String nl = secure(cr, "enabled_notification_listeners");
        for (String c : nl.split(":")) {
            if (!c.trim().isEmpty()) st.notificationComponents.add(c.trim());
        }

        // --- Amministratori del dispositivo --------------------------------
        try {
            DevicePolicyManager dpm = (DevicePolicyManager)
                    ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            if (dpm != null) {
                List<ComponentName> admins = dpm.getActiveAdmins();
                if (admins != null) for (ComponentName cn : admins) {
                    st.deviceAdmins.add(cn.getPackageName() + "/" + cn.getClassName());
                }
            }
        } catch (Throwable ignored) {}

        // --- Tastiere abilitate -------------------------------------------
        for (String s : secure(cr, "enabled_input_methods").split(":")) {
            if (!s.trim().isEmpty()) st.enabledInputMethods.add(s.trim());
        }

        // --- Debug USB / posizione finta / VPN ----------------------------
        st.adbEnabled = "1".equals(global(cr, "adb_enabled"));
        st.mockLocationEnabled = "1".equals(secure(cr, "mock_location"));
        String alwaysOnVpn = secure(cr, "always_on_vpn_app");
        st.vpnPackage = alwaysOnVpn;

        try {
            ConnectivityManager cm = (ConnectivityManager)
                    ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network active = cm == null ? null : cm.getActiveNetwork();
            NetworkCapabilities nc = active == null ? null : cm.getNetworkCapabilities(active);
            st.vpnActive = nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        } catch (Throwable ignored) {}

        // --- App SMS predefinita ------------------------------------------
        try {
            String sms = Telephony.Sms.getDefaultSmsPackage(ctx);
            st.defaultSmsPackage = sms == null ? "" : sms;
        } catch (Throwable ignored) {}

        // --- Browser predefinito ------------------------------------------
        try {
            Intent view = new Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://example.com"));
            android.content.pm.ResolveInfo ri = ctx.getPackageManager()
                    .resolveActivity(view, PackageManager.MATCH_DEFAULT_ONLY);
            if (ri != null && ri.activityInfo != null) st.defaultBrowserPackage = ri.activityInfo.packageName;
        } catch (Throwable ignored) {}

        return st;
    }

    /** Raggruppa "pkg/classe" in pkg -> component. */
    public static Map<String, String> byPackage(List<String> components) {
        Map<String, String> m = new HashMap<>();
        for (String c : components) {
            int i = c.indexOf('/');
            String pkg = i > 0 ? c.substring(0, i) : c;
            m.put(pkg, c);
        }
        return m;
    }

    public Set<String> accessibilityPackages() {
        return byPackage(accessibilityComponents).keySet();
    }

    public Set<String> notificationPackages() {
        return byPackage(notificationComponents).keySet();
    }

    public Set<String> adminPackages() {
        return byPackage(deviceAdmins).keySet();
    }

    public Set<String> uniqueInputMethodPackages() {
        Set<String> out = new HashSet<>();
        for (String s : enabledInputMethods) {
            int i = s.indexOf('/');
            out.add(i > 0 ? s.substring(0, i) : s);
        }
        return out;
    }
}
