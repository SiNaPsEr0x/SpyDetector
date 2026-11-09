package it.spydetector.app.checks;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiManager;
import android.os.Build;

import it.spydetector.app.core.Check;
import it.spydetector.app.core.Finding;
import it.spydetector.app.core.ScanData;
import it.spydetector.app.core.Severity;

import android.net.LinkAddress;
import android.net.LinkProperties;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Rete: proxy trasparente, VPN, reti aperte, IP pubblico locale e interfacce
 * anomale (tun/tap di intercettazione). Nessuna connessione verso Internet:
 * tutto viene letto dalle API locali.
 */
public class NetworkCheck implements Check {

    @Override public String id() { return "NETWORK"; }
    @Override public String category() { return "Rete"; }
    @Override public String label() { return "Rete, VPN e proxy"; }

    @Override
    public List<Finding> run(ScanData data) {
        List<Finding> out = new ArrayList<>();
        String cat = category();
        Context ctx = data.ctx;

        // --- interfacce di rete ---------------------------------------------
        List<String> tun = new ArrayList<>();
        List<String> raw = new ArrayList<>();
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                Network[] networks = cm.getAllNetworks();
                for (Network network : networks) {
                    LinkProperties lp = cm.getLinkProperties(network);
                    if (lp != null) {
                        String name = lp.getInterfaceName();
                        if (name != null) {
                            if (name.startsWith("tun") || name.startsWith("tap") || name.startsWith("ppp")
                                    || name.contains("wg")) {
                                tun.add(name);
                            }
                            for (LinkAddress addr : lp.getLinkAddresses()) {
                                InetAddress a = addr.getAddress();
                                if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                                    raw.add(name + " = " + a.getHostAddress());
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}

        if (!tun.isEmpty()) {
            out.add(new Finding("NET_TUNNEL", cat, "Interfaccia tunnel attiva: " + tun,
                    Severity.ATTENTION,
                    "Trovate interfacce " + tun + ": il traffico sta passando da un tunnel.",
                    "Se non sei tu ad aver attivato una VPN, qualcuno puo' stare instradando il "
                    + "traffico del telefono. Impostazioni > Rete > VPN."));
        }

        // --- VPN -------------------------------------------------------------
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network n = cm.getActiveNetwork();
            NetworkCapabilities nc = cm.getNetworkCapabilities(n);
            boolean vpn = nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            boolean wifi = nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
            boolean cell = nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);

            out.add(new Finding("NET_TYPE", cat, "Connessione attiva",
                    Severity.INFO,
                    cell ? "Rete mobile" : wifi ? "Wi-Fi" : vpn ? "VPN" : "Nessuna/altro",
                    "Informazione di contesto."));

            if (wifi) {
                WifiManager wm = (WifiManager) ctx.getApplicationContext()
                        .getSystemService(Context.WIFI_SERVICE);
                if (wm != null && Build.VERSION.SDK_INT < 29) {
                    @SuppressWarnings("deprecation")
                    int rssi = wm.getConnectionInfo() != null ? wm.getConnectionInfo().getRssi() : 0;
                    boolean weak = rssi != 0 && rssi < -80;
                    if (weak) {
                        out.add(new Finding("NET_WIFI_WEAK", cat, "Segnale Wi-Fi molto debole",
                                Severity.INFO, "RSSI " + rssi + " dBm",
                                "Su reti deboli e' piu' facile agganciarsi a reti false con lo stesso nome."));
                    }
                }
            }

            if (!vpn && !tun.isEmpty()) {
                out.add(new Finding("NET_VPN_CONFLICT", cat, "Tunnel presente ma VPN non dichiarata",
                        Severity.WARNING, String.valueOf(tun),
                        "Un'interfaccia tunnel attiva senza una VPN impostata e' anomala: "
                        + "potrebbe essere un'app che intercetta il traffico."));
            }
        } catch (Throwable ignored) {}

        // --- proxy ------------------------------------------------------------
        try {
            String host = System.getProperty("http.proxyHost");
            String port = System.getProperty("http.proxyPort");
            if (host != null && !host.isEmpty() && !"localhost".equals(host)) {
                out.add(new Finding("NET_PROXY", cat, "Proxy HTTP configurato: " + host + ":" + port,
                        Severity.WARNING,
                        "L'app usa un proxy per il traffico HTTP: un intercettatore puo' leggere i dati.",
                        "Rimuovi il proxy da Impostazioni Wi-Fi > Modifica rete > Avanzate > Proxy."));
            }
        } catch (Throwable ignored) {}

        // --- IP privato -------------------------------------------------------
        if (!raw.isEmpty()) {
            out.add(new Finding("NET_ADDR", cat, "Indirizzi di rete locali",
                    Severity.INFO, join(raw),
                    "Solo informazioni: nessun dato viene inviato fuori dal telefono."));
        }
        return out;
    }

    private static String join(List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < l.size() && i < 6; i++) {
            if (i > 0) sb.append(" | ");
            sb.append(l.get(i));
        }
        return sb.toString();
    }
}
