package app.aegis.scanner;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainActivity extends AppCompatActivity {

    private TextView status, accessTitle, accessCopy, progressText, findingsTitle;
    private Button btnAllow, btnScan, btnDeep, btnStop, btnClose, btnClear;
    private ProgressBar bar;
    private LinearLayout findings, findingsCard;
    private boolean scanning = false;
    private final AtomicBoolean cancel = new AtomicBoolean(false);

    private static final String[] QUICK_EXT = {
        "apk", "xapk", "apks", "apkm", "dex", "exe", "dll", "js", "vbs", "ps1",
        "bat", "cmd", "hta", "jar", "zip", "7z", "rar", "pdf", "doc", "docx",
        "xls", "xlsx", "msi", "iso", "sh", "html"
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        status = findViewById(R.id.status);
        accessTitle = findViewById(R.id.accessTitle);
        accessCopy = findViewById(R.id.accessCopy);
        progressText = findViewById(R.id.progressText);
        findingsTitle = findViewById(R.id.findingsTitle);
        btnAllow = findViewById(R.id.btnAllow);
        btnScan = findViewById(R.id.btnScan);
        btnDeep = findViewById(R.id.btnDeep);
        btnStop = findViewById(R.id.btnStop);
        btnClose = findViewById(R.id.btnClose);
        btnClear = findViewById(R.id.btnClear);
        bar = findViewById(R.id.bar);
        findings = findViewById(R.id.findings);
        findingsCard = findViewById(R.id.findingsCard);
        btnAllow.setOnClickListener(v -> requestAllFiles());
        btnScan.setOnClickListener(v -> startScan(false));
        btnDeep.setOnClickListener(v -> startScan(true));
        btnStop.setOnClickListener(v -> cancel.set(true));
        btnClose.setOnClickListener(v -> finish());
        btnClear.setOnClickListener(v -> clearResults());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() {
                if (scanning) { cancel.set(true); return; }
                if (findingsCard.getVisibility() == View.VISIBLE) { clearResults(); return; }
                finish();
            }
        });
    }

    @Override protected void onResume() { super.onResume(); refreshAccess(); }

    private boolean hasAllFiles() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) return Environment.isExternalStorageManager();
        File root = Environment.getExternalStorageDirectory();
        return root != null && root.canRead();
    }

    private void refreshAccess() {
        boolean ok = hasAllFiles();
        btnAllow.setVisibility(ok ? View.GONE : View.VISIBLE);
        btnScan.setVisibility(ok && !scanning ? View.VISIBLE : View.GONE);
        btnDeep.setVisibility(ok && !scanning ? View.VISIBLE : View.GONE);
        btnStop.setVisibility(scanning ? View.VISIBLE : View.GONE);
        if (ok) {
            accessTitle.setText("Ready to scan");
            accessCopy.setText("Apps + shared storage (Downloads, Documents, DCIM). Other apps private data and boot need root.");
            status.setText("Native Aegis (build 5). Nothing is uploaded.");
        } else {
            accessTitle.setText("Aegis needs All files access");
            accessCopy.setText("Turn Aegis on in All files, swipe back, then scan apps and files.");
            status.setText("Build 5. Close app is at the top.");
        }
    }

    private void requestAllFiles() {
        if (hasAllFiles()) { refreshAccess(); return; }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            }
        }
    }

    private void clearResults() {
        findings.removeAllViews();
        findingsCard.setVisibility(View.GONE);
        bar.setVisibility(View.GONE);
        progressText.setVisibility(View.GONE);
    }

    private void startScan(boolean deep) {
        if (scanning || !hasAllFiles()) return;
        scanning = true;
        cancel.set(false);
        findings.removeAllViews();
        findingsCard.setVisibility(View.GONE);
        bar.setVisibility(View.VISIBLE);
        progressText.setVisibility(View.VISIBLE);
        bar.setProgress(3);
        progressText.setText("Reviewing installed apps…");
        refreshAccess();
        Executors.newSingleThreadExecutor().execute(() -> runScan(deep));
    }

    private void runScan(boolean deep) {
        List<Hit> hits = new ArrayList<>();
        int apps = 0, sideload = 0;
        try {
            PackageManager pm = getPackageManager();
            List<PackageInfo> pkgs = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
            apps = pkgs.size();
            int i = 0;
            for (PackageInfo pkg : pkgs) {
                if (cancel.get()) break;
                i++;
                final int shown = i, total = pkgs.size();
                runOnUiThread(() -> {
                    bar.setProgress(Math.round(shown * 35f / Math.max(total, 1)));
                    progressText.setText("Apps " + shown + " / " + total);
                });
                Hit hit = inspectApp(pm, pkg);
                if (hit != null) {
                    hits.add(hit);
                    if (hit.reason.startsWith("Sideloaded")) sideload++;
                }
            }
        } catch (Exception ignored) {}

        File root = Environment.getExternalStorageDirectory();
        int cap = deep ? 2500 : 800;
        Set<String> ext = new HashSet<>();
        if (!deep) for (String e : QUICK_EXT) ext.add(e);
        List<File> files = listFiles(root, cap, ext);
        int n = files.size();
        for (int i = 0; i < n; i++) {
            if (cancel.get()) break;
            File file = files.get(i);
            final int done = i + 1;
            runOnUiThread(() -> {
                bar.setProgress(35 + Math.round(done * 60f / Math.max(n, 1)));
                progressText.setText("Files " + done + " / " + n);
            });
            Hit hit = inspectFile(file);
            if (hit != null) hits.add(hit);
        }

        boolean bootReadable = new File("/system/bin").canRead() && new File("/data/data").canRead();
        final boolean stopped = cancel.get();
        final int appCount = apps, sideCount = sideload, fileCount = n;
        final boolean boot = bootReadable;
        runOnUiThread(() -> finishScan(appCount, sideCount, fileCount, hits, stopped, boot));
    }

    private Hit inspectApp(PackageManager pm, PackageInfo pkg) {
        if (pkg.applicationInfo == null) return null;
        if ((pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0) return null;
        String label;
        try { label = pm.getApplicationLabel(pkg.applicationInfo).toString(); }
        catch (Exception e) { label = pkg.packageName; }
        String installer = installerOf(pm, pkg.packageName);
        boolean trusted = isTrustedStore(installer);
        String[] perms = pkg.requestedPermissions;
        boolean overlay = hasPerm(perms, "android.permission.SYSTEM_ALERT_WINDOW");
        boolean install = hasPerm(perms, "android.permission.REQUEST_INSTALL_PACKAGES");
        boolean access = hasPerm(perms, "android.permission.BIND_ACCESSIBILITY_SERVICE")
            || hasPerm(perms, "android.permission.BIND_DEVICE_ADMIN");
        if (!trusted && (overlay || install || access)) {
            return new Hit(label, pkg.packageName, "Sideloaded app with install/overlay/admin rights — review");
        }
        if (!trusted) {
            return new Hit(label, pkg.packageName + " · installer: " + (installer == null ? "unknown" : installer), "Sideloaded — not from Play or Samsung");
        }
        if (overlay && install) {
            return new Hit(label, pkg.packageName, "Play/Samsung app requests overlay + package install");
        }
        return null;
    }

    private String installerOf(PackageManager pm, String pkg) {
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                String src = pm.getInstallSourceInfo(pkg).getInstallingPackageName();
                if (src != null) return src;
            }
            return pm.getInstallerPackageName(pkg);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isTrustedStore(String installer) {
        if (installer == null || installer.isEmpty()) return false;
        return installer.equals("com.android.vending")
            || installer.equals("com.google.android.packageinstaller")
            || installer.equals("com.sec.android.app.samsungapps")
            || installer.equals("com.samsung.android.shortcutbackupservice")
            || installer.startsWith("com.samsung.")
            || installer.equals("com.google.android.apps.restore")
            || installer.equals(getPackageName());
    }

    private boolean hasPerm(String[] perms, String want) {
        if (perms == null) return false;
        for (String p : perms) if (want.equals(p)) return true;
        return false;
    }

    private void finishScan(int apps, int sideload, int files, List<Hit> hits, boolean stopped, boolean boot) {
        scanning = false;
        bar.setProgress(100);
        progressText.setText((stopped ? "Stopped" : "Done") + " · " + apps + " apps · " + files + " files");
        findingsCard.setVisibility(View.VISIBLE);
        findingsTitle.setText(hits.isEmpty() ? (stopped ? "Scan stopped" : "Report") : hits.size() + " items to review");

        addNote("Inventory: " + apps + " packages, " + sideload + " sideloaded flags, " + files + " files opened.", false);
        addNote(boot
            ? "Boot and /data were readable. Unusual on a stock S24."
            : "Boot, firmware, and other apps private data are sealed (no root).", false);

        if (hits.isEmpty()) {
            addNote(stopped ? "Stopped early." : "No EICAR, fake APKs, dropper scripts, or high-risk sideloads in what Aegis can read.", false);
        } else {
            for (Hit hit : hits) {
                addHit(hit);
            }
        }
        refreshAccess();
    }

    private void addNote(String text, boolean danger) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(getResources().getColor(danger ? R.color.danger : R.color.ok));
        tv.setPadding(0, 12, 0, 0);
        tv.setTextSize(14);
        findings.addView(tv);
    }

    private void addHit(Hit hit) {
        TextView reason = new TextView(this);
        reason.setText(hit.reason);
        reason.setTextColor(getResources().getColor(R.color.danger));
        reason.setPadding(0, 14, 0, 0);
        reason.setTextSize(14);
        TextView name = new TextView(this);
        name.setText(hit.name);
        name.setTextColor(Color.parseColor("#E8EAED"));
        TextView path = new TextView(this);
        path.setText(hit.path);
        path.setTextColor(Color.parseColor("#5C6370"));
        path.setTextSize(12);
        findings.addView(reason);
        findings.addView(name);
        findings.addView(path);
    }

    private List<File> listFiles(File root, int cap, Set<String> extensions) {
        List<File> out = new ArrayList<>();
        if (root == null || !root.exists()) return out;
        ArrayDeque<File> queue = new ArrayDeque<>();
        queue.add(root);
        while (!queue.isEmpty() && out.size() < cap) {
            if (cancel.get()) break;
            File dir = queue.removeFirst();
            File[] children = dir.listFiles();
            if (children == null) continue;
            for (File child : children) {
                if (out.size() >= cap) break;
                String name = child.getName();
                if (name.startsWith(".") && !name.equals(".nomedia")) continue;
                if (child.isDirectory()) {
                    if (skipDir(name)) continue;
                    queue.addLast(child);
                } else if (child.isFile()) {
                    if (!extensions.isEmpty() && !extensions.contains(extOf(name))) continue;
                    out.add(child);
                }
            }
        }
        return out;
    }

    private Hit inspectFile(File file) {
        byte[] buf = readPrefix(file, 524288);
        if (buf == null) return null;
        String name = file.getName();
        String lower = name.toLowerCase(Locale.US);
        String text = asciiSample(buf);
        if (text.contains("eicar-standard-antivirus-test-file") || text.contains("x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar")) {
            return new Hit(name, file.getAbsolutePath(), "EICAR test signature");
        }
        if (text.contains("powershell -enc") || text.contains("frombase64string") || text.contains("wscript.shell")) {
            return new Hit(name, file.getAbsolutePath(), "Suspicious command string");
        }
        if (buf.length >= 2 && buf[0] == 0x4d && buf[1] == 0x5a && lower.endsWith(".apk")) {
            return new Hit(name, file.getAbsolutePath(), "Windows PE bytes inside an APK name");
        }
        if (lower.endsWith(".apk") && !(buf.length >= 2 && buf[0] == 0x50 && buf[1] == 0x4b)) {
            return new Hit(name, file.getAbsolutePath(), "APK without ZIP magic");
        }
        if (lower.matches(".*\\.(pdf|jpg|png|doc|xls)\\.(exe|apk|js|scr|bat)$")) {
            return new Hit(name, file.getAbsolutePath(), "Double extension — classic dropper name");
        }
        if (lower.matches(".*\\.(js|vbs|ps1|bat|cmd|hta|sh)$")
            && (text.contains("eval(") || text.contains("fromcharcode") || text.contains("downloadstring") || text.contains("/bin/sh"))) {
            return new Hit(name, file.getAbsolutePath(), "Script dropper patterns");
        }
        return null;
    }

    private byte[] readPrefix(File file, int max) {
        try (FileInputStream in = new FileInputStream(file)) {
            int toRead = (int) Math.min(file.length(), Math.max(1, max));
            byte[] buf = new byte[toRead];
            int n = in.read(buf);
            if (n < 0) return new byte[0];
            if (n == buf.length) return buf;
            byte[] cut = new byte[n];
            System.arraycopy(buf, 0, cut, 0, n);
            return cut;
        } catch (Exception e) {
            return null;
        }
    }

    private String asciiSample(byte[] bytes) {
        StringBuilder sb = new StringBuilder(Math.min(bytes.length, 65536));
        int n = Math.min(bytes.length, 65536);
        for (int i = 0; i < n; i++) {
            int c = bytes[i] & 0xff;
            sb.append(c >= 32 && c < 127 ? (char) c : ' ');
        }
        return sb.toString().toLowerCase(Locale.US);
    }

    private boolean skipDir(String name) {
        String n = name.toLowerCase(Locale.US);
        return n.equals("android") || n.equals("cache") || n.equals(".thumbnails")
            || n.equals("lost.dir") || n.equals("lost+found");
    }

    private String extOf(String name) {
        int i = name.lastIndexOf('.');
        if (i < 0 || i == name.length() - 1) return "";
        return name.substring(i + 1).toLowerCase(Locale.US);
    }

    private static class Hit {
        final String name, path, reason;
        Hit(String name, String path, String reason) {
            this.name = name; this.path = path; this.reason = reason;
        }
    }
}
