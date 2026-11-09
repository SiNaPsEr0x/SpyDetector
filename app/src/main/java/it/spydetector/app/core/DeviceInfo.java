package it.spydetector.app.core;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;

/** Informazioni hardware/OS mostrate nell'header della dashboard. */
public final class DeviceInfo {

    public final String manufacturer;
    public final String model;
    public final String androidVersion;
    public final String sdk;
    public final String securityPatch;
    public final String kernel;
    public final String buildId;
    public final long ramMb;
    public final String cpuAbi;
    public final String fingerprint;

    private DeviceInfo(Context ctx) {
        this.manufacturer = Build.MANUFACTURER == null ? "" : capitalize(Build.MANUFACTURER);
        this.model = Build.MODEL == null ? "" : Build.MODEL;
        this.androidVersion = Build.VERSION.RELEASE == null ? "" : Build.VERSION.RELEASE;
        this.sdk = String.valueOf(Build.VERSION.SDK_INT);
        this.securityPatch = Build.VERSION.SDK_INT >= 23 && Build.VERSION.SECURITY_PATCH != null
                ? Build.VERSION.SECURITY_PATCH : "";
        this.kernel = System.getProperty("os.version") == null ? "" : System.getProperty("os.version");
        this.buildId = Build.ID == null ? "" : Build.ID;
        this.cpuAbi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0
                ? Build.SUPPORTED_ABIS[0] : "";
        this.fingerprint = Build.FINGERPRINT == null ? "" : Build.FINGERPRINT;
        ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
        long ram = 0;
        try {
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) { am.getMemoryInfo(mi); ram = mi.totalMem / (1024 * 1024); }
        } catch (Throwable ignored) {}
        this.ramMb = ram;
    }

    public static DeviceInfo load(Context ctx) {
        return new DeviceInfo(ctx);
    }

    public String summary() {
        return manufacturer + " " + model;
    }

    private static String capitalize(String s) {
        if (s.isEmpty()) return s;
        String low = s.length() > 1 ? s.substring(1).toLowerCase() : "";
        return s.substring(0, 1).toUpperCase() + low;
    }
}
