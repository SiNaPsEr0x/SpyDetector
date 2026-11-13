package it.spydetector.app.core;

import android.app.DownloadManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Controlla aggiornamenti remoto:
 *
 * 1) Scarica il database aggiornato delle firme ufficiali da GitHub e lo
 *    applica a ThreatDb (pkg -> SHA-256). Questo permette di riconoscere
 *    app ufficiali senza ricompilare l'APK.
 *
 * 2) Verifica la presenza di una nuova versione dell'app su GitHub Releases.
 *    Se trova un APK piu' recente, lo scarica e propone l'installazione.
 *
 * Nessun dato utente viene inviato: solo GET verso i repository GitHub pubblici.
 */
public final class UpdateChecker {

    private UpdateChecker() {}

    /** URL del database delle firme ufficiali su GitHub raw. */
    public static final String SIGNATURES_URL =
            "https://raw.githubusercontent.com/SiNaPsEr0x/SpyDetector/main/data/official-signatures.txt";

    /** API GitHub per il release piu' recente. */
    public static final String RELEASES_API_URL =
            "https://api.github.com/repos/SiNaPsEr0x/SpyDetector/releases/latest";

    /**
     * Scarica e applica il database aggiornato delle firme ufficiali.
     * Torna il numero di firme aggiunte/aggiornate, o 0 se nessuna rete.
     */
    public static int updateSignatures(Context ctx) {
        String body = httpGet(SIGNATURES_URL);
        if (body == null || body.isEmpty()) return 0;
        int added = 0;
        for (String line : body.split("\n")) {
            String l = line.trim();
            if (l.isEmpty() || l.startsWith("#")) continue;
            int eq = l.indexOf('=');
            if (eq < 1) continue;
            String pkg = l.substring(0, eq).trim();
            String hash = l.substring(eq + 1).trim();
            if (hash.matches("[0-9a-fA-F]{64}")) {
                ThreatDb.addOfficialSignature(pkg, hash);
                added++;
            }
        }
        return added;
    }

    /**
     * Controlla se esiste una nuova versione su GitHub Releases.
     * Torna l'URL del nuovo APK se trova una versione piu' recente,
     * altrimenti null.
     */
    public static String checkForAppUpdate(Context ctx, String currentVersion) {
        String json = httpGet(RELEASES_API_URL);
        if (json == null || json.isEmpty()) return null;

        String tagName = extractJsonString(json, "tag_name");
        if (tagName == null || tagName.isEmpty()) return null;

        String remoteVersion = tagName.replaceAll("^[^0-9]*", "");
        if (remoteVersion.isEmpty()) return null;

        if (compareVersions(remoteVersion, currentVersion) <= 0) return null;

        return extractApkUrl(json);
    }

    /**
     * Scarica l'APK tramite DownloadManager e propone l'installazione.
     */
    public static void downloadAndProposeInstall(Context ctx, String apkUrl) {
        if (apkUrl == null || apkUrl.isEmpty()) return;
        final Context appCtx = ctx.getApplicationContext();

        String path = apkUrl.substring(apkUrl.lastIndexOf('/') + 1);
        if (path.contains("?")) path = path.substring(0, path.indexOf('?'));
        String fileName = path.endsWith(".apk") ? path : "SpyDetector-update.apk";

        DownloadManager.Request req = new DownloadManager.Request(Uri.parse(apkUrl));
        req.setDestinationUri(Uri.parse("file://" + appCtx.getCacheDir() + "/" + fileName));
        req.setMimeType("application/vnd.android.package-archive");

        DownloadManager dm = (DownloadManager) appCtx.getSystemService(Context.DOWNLOAD_SERVICE);
        dm.enqueue(req);

        // Attendi il completamento e propone l'installazione
        final String fname = fileName;
        new Thread(new Runnable() {
            @Override public void run() {
                long start = System.currentTimeMillis();
                while (System.currentTimeMillis() - start < 300000) {
                    java.io.File f = new java.io.File(appCtx.getCacheDir(), fname);
                    if (f.exists() && f.length() > 10000) break;
                    try { Thread.sleep(2000); } catch (Throwable ignored) {}
                }
                java.io.File apk = new java.io.File(appCtx.getCacheDir(), fname);
                if (!apk.exists() || apk.length() == 0) return;

                // Su Android 7+ (API 24+) file:// non e' consentito:
                // usa il ContentProvider interno
                Uri apkUri = Uri.parse("content://" + appCtx.getPackageName()
                        + ".fileprovider/" + apk.getName());
                Intent install = new Intent(Intent.ACTION_VIEW);
                install.setDataAndType(apkUri, "application/vnd.android.package-archive");
                install.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                install.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                try {
                    appCtx.startActivity(install);
                } catch (Throwable t) {
                    Intent view = new Intent(Intent.ACTION_VIEW);
                    view.setDataAndType(apkUri, "*/*");
                    view.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    try { appCtx.startActivity(view); } catch (Throwable ignored) {}
                }
            }
        }).start();
    }

    // --- HTTP helpers ------------------------------------------------------

    private static String httpGet(String urlStr) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setInstanceFollowRedirects(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setRequestProperty("User-Agent", "SpyDetector/" + Build.VERSION.SDK_INT);

            int code = conn.getResponseCode();
            if (code != 200) return null;

            InputStream is = conn.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(line);
            }
            reader.close();
            is.close();
            return sb.toString();
        } catch (Throwable t) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static String extractJsonString(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon < 0) return null;
        int start = json.indexOf('"', colon + 1);
        if (start < 0) return null;
        int end = json.indexOf('"', start + 1);
        if (end < 0) return null;
        return json.substring(start + 1, end);
    }

    private static String extractApkUrl(String json) {
        int assetsIdx = json.indexOf("\"assets\"");
        if (assetsIdx < 0) return null;
        int urlIdx = json.indexOf("browser_download_url", assetsIdx);
        if (urlIdx < 0) return null;
        int colon = json.indexOf(':', urlIdx);
        int start = json.indexOf('"', colon + 1);
        int end = json.indexOf('"', start + 1);
        if (start < 0 || end < 0) return null;
        String url = json.substring(start + 1, end);
        if (url.endsWith(".apk") && url.contains("release")) return url;
        return url.endsWith(".apk") ? url : null;
    }

    private static int compareVersions(String a, String b) {
        String[] pa = a.split("\\.");
        String[] pb = b.split("\\.");
        int max = Math.max(pa.length, pb.length);
        for (int i = 0; i < max; i++) {
            int va = i < pa.length ? parseIntSafe(pa[i]) : 0;
            int vb = i < pb.length ? parseIntSafe(pb[i]) : 0;
            if (va != vb) return va - vb;
        }
        return 0;
    }

    private static int parseIntSafe(String s) {
        try { return Integer.parseInt(s.trim()); } catch (Throwable t) { return 0; }
    }
}
