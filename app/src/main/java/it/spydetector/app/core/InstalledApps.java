package it.spydetector.app.core;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Enumera le app installate con i dati che servono all'audit. */
public final class InstalledApps {

    public static final class App {
        public final String pkg;
        public final String label;
        public final boolean system;
        public final boolean enabled;
        public final String installer;
        public final long firstInstall;
        public final long lastUpdate;
        public final long versionCode;
        public final String versionName;
        public final String targetSdk;
        public final String[] requested;
        public final long apkSize;

        App(PackageInfo pi, PackageManager pm, ApplicationInfo ai) {
            this.pkg = pi.packageName;
            CharSequence l = ai.loadLabel(pm);
            this.label = l == null ? pi.packageName : l.toString();
            this.system = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                    && (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
            this.enabled = ai.enabled;
            String inst = null;
            try { inst = pm.getInstallerPackageName(pi.packageName); } catch (Exception ignored) {}
            this.installer = inst == null ? "" : inst;
            this.firstInstall = pi.firstInstallTime;
            this.lastUpdate = pi.lastUpdateTime;
            this.versionCode = Build.VERSION.SDK_INT >= 28 ? pi.getLongVersionCode() : pi.versionCode;
            this.versionName = pi.versionName == null ? "" : pi.versionName;
            this.targetSdk = String.valueOf(ai.targetSdkVersion);
            this.requested = pi.requestedPermissions == null ? new String[0] : pi.requestedPermissions;
            this.apkSize = ai.sourceDir == null ? 0 : new java.io.File(ai.sourceDir).length();
        }
    }

    private final List<App> apps = new ArrayList<>();

    public static InstalledApps scan(Context ctx) {
        InstalledApps out = new InstalledApps();
        PackageManager pm = ctx.getPackageManager();
        int flags = PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES;
        List<PackageInfo> infos;
        if (Build.VERSION.SDK_INT >= 33) {
            infos = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags));
        } else {
            infos = pm.getInstalledPackages(flags);
        }
        for (PackageInfo pi : infos) {
            if (pi.applicationInfo == null) continue;
            try {
                out.apps.add(new App(pi, pm, pi.applicationInfo));
            } catch (Exception ignored) {}
        }
        Collections.sort(out.apps, new Comparator<App>() {
            @Override public int compare(App a, App b) {
                return a.label.compareToIgnoreCase(b.label);
            }
        });
        return out;
    }

    public List<App> all() {
        return apps;
    }

    public List<App> user() {
        List<App> out = new ArrayList<>();
        for (App a : apps) if (!a.system) out.add(a);
        return out;
    }

    public App get(String pkg) {
        for (App a : apps) if (a.pkg.equals(pkg)) return a;
        return null;
    }

    public Set<String> packages() {
        Set<String> s = new HashSet<>();
        for (App a : apps) s.add(a.pkg);
        return s;
    }

    public int count() {
        return apps.size();
    }
}
