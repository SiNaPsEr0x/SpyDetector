package it.spydetector.app.core;

import android.content.Context;

/** Dati raccolti una sola volta e condivisi da tutti i check. */
public final class ScanData {

    public final Context ctx;
    public final DeviceInfo device;
    public final InstalledApps apps;
    public final AccessState access;

    public ScanData(Context ctx) {
        this.ctx = ctx.getApplicationContext();
        this.device = DeviceInfo.load(this.ctx);
        this.apps = InstalledApps.scan(this.ctx);
        this.access = AccessState.read(this.ctx);
    }
}
