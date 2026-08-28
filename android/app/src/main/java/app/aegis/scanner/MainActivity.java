package app.aegis.scanner;

import android.content.Intent;
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

public class MainActivity extends AppCompatActivity {

    private TextView status;
    private TextView accessTitle;
    private TextView accessCopy;
    private TextView progressText;
    private TextView findingsTitle;
    private Button btnAllow;
    private Button btnScan;
    private Button btnDeep;
    private ProgressBar bar;
    private LinearLayout findings;
    private LinearLayout findingsCard;
    private boolean scanning = false;

    private static final String[] QUICK_EXT = {
        "apk", "xapk", "apks", "dex", "exe", "dll", "js", "vbs", "ps1", "bat",
        "cmd", "hta", "jar", "zip", "7z", "rar", "pdf", "doc", "xls", "msi", "iso"
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
        bar = findViewById(R.id.bar);
        findings = findViewById(R.id.findings);
        findingsCard = findViewById(R.id.findingsCard);
        btnAllow.setOnClickListener(v -> requestAllFiles());
        btnScan.setOnClickListener(v -> startScan(false));
        btnDeep.setOnClickListener(v -> startScan(true));
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshAccess();
    }

    private boolean hasAllFiles() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager();
        }
        File root = Environment.getExternalStorageDirectory();
        return root != null && root.canRead();
    }

    private void refreshAccess() {
        boolean ok = hasAllFiles();
        btnAllow.setVisibility(ok ? View.GONE : View.VISIBLE);
        btnScan.setVisibility(ok ? View.VISIBLE : View.GONE);
        btnDeep.setVisibility(ok ? View.VISIBLE : View.GONE);
        if (ok) {
            accessTitle.setText("All files access is on");
            accessCopy.setText("Shared storage can be inspected. Other apps private data still requires root.");
            status.setText("Native Aegis (build 3). Files stay on this phone.");
        } else {
            accessTitle.setText("Aegis needs All files access");
            accessCopy.setText("Android will open the All files screen. Turn Aegis on, then return here.");
            status.setText("Build 3 — native screen, no webpage. Grant All files, then scan.");
        }
        btnScan.setEnabled(!scanning);
        btnDeep.setEnabled(!scanning);
    }

    private void requestAllFiles() {
        if (hasAllFiles()) {
            refreshAccess();
            return;
        }
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

    private void startScan(boolean deep) {
        if (scanning || !hasAllFiles()) return;
        scanning = true;
        findings.removeAllViews();
        findingsCard.setVisibility(View.GONE);
        bar.setVisibility(View.VISIBLE);
        progressText.setVisibility(View.VISIBLE);
        bar.setProgress(4);
        progressText.setText("Listing shared storage…");
        refreshAccess();
        Executors.newSingleThreadExecutor().execute(() -> runScan(deep));
    }

    private void runScan(boolean deep) {
        File root = Environment.getExternalStorageDirectory();
        int cap = deep ? 1200 : 400;
        Set<String> ext = new HashSet<>();
        if (!deep) {
            for (String e : QUICK_EXT) ext.add(e);
        }
        List<File> files = listFiles(root, cap, ext);
        List<Hit> hits = new ArrayList<>();
        int n = files.size();
        for (int i = 0; i < n; i++) {
            File file = files.get(i);
            final int done = i + 1;
            runOnUiThread(() -> {
                bar.setProgress(Math.round(done * 100f / Math.max(n, 1)));
                progressText.setText("Inspecting " + done + " / " + n);
            });
            Hit hit = inspect(file);
            if (hit != null) hits.add(hit);
        }
        runOnUiThread(() -> finishScan(n, hits));
    }

    private void finishScan(int n, List<Hit> hits) {
        scanning = false;
        bar.setProgress(100);
        progressText.setText("Done · " + n + " files");
        findingsCard.setVisibility(View.VISIBLE);
        if (hits.isEmpty()) {
            findingsTitle.setText("No matches in allowed storage");
            TextView tv = new TextView(this);
            tv.setText("No EICAR, PE/APK mismatch, or dropper strings in the files Aegis could read.");
            tv.setTextColor(getResources().getColor(R.color.ok));
            tv.setPadding(0, 12, 0, 0);
            findings.addView(tv);
        } else {
            findingsTitle.setText(hits.size() + (hits.size() == 1 ? " finding" : " findings"));
            for (Hit hit : hits) {
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
        }
        refreshAccess();
    }

    private List<File> listFiles(File root, int cap, Set<String> extensions) {
        List<File> out = new ArrayList<>();
        if (root == null || !root.exists()) return out;
        ArrayDeque<File> queue = new ArrayDeque<>();
        queue.add(root);
        while (!queue.isEmpty() && out.size() < cap) {
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

    private Hit inspect(File file) {
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
        if (lower.matches(".*\\.(js|vbs|ps1|bat|cmd|hta)$")
            && (text.contains("eval(") || text.contains("fromcharcode") || text.contains("downloadstring"))) {
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
        final String name;
        final String path;
        final String reason;
        Hit(String name, String path, String reason) {
            this.name = name;
            this.path = path;
            this.reason = reason;
        }
    }
}
