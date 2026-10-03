package app.aegis.scanner;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.text.DateFormat;
import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class MainActivity extends AppCompatActivity {
    private static final int PAGE_HOME = 0;
    private static final int PAGE_SCAN = 1;
    private static final int PAGE_VAULT = 2;
    private static final int PAGE_HISTORY = 3;

    private final AtomicBoolean cancel = new AtomicBoolean(false);
    private boolean scanning;
    private int page = PAGE_HOME;
    private LinearLayout body;
    private Button tabHome, tabScan, tabVault, tabHistory;
    private TextView status;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildShell());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override public void handleOnBackPressed() {
                if (scanning) { cancel.set(true); return; }
                if (page != PAGE_HOME) { show(PAGE_HOME); return; }
                finish();
            }
        });
        show(PAGE_HOME);
    }

    @Override protected void onResume() {
        super.onResume();
        if (!scanning) show(page);
    }

    private View buildShell() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(color(R.color.colorPrimaryDark));
        root.setPadding(dp(16), dp(16), dp(16), dp(8));

        TextView brand = text("AEGIS", 12, color(R.color.muted), false);
        brand.setLetterSpacing(0.08f);
        root.addView(brand);
        TextView title = text("This phone", 26, color(R.color.fg), true);
        title.setPadding(0, dp(4), 0, 0);
        root.addView(title);
        status = text("", 13, color(R.color.muted), false);
        status.setPadding(0, dp(6), 0, dp(10));
        root.addView(status);

        LinearLayout tabs = new LinearLayout(this);
        tabs.setOrientation(LinearLayout.HORIZONTAL);
        tabHome = tab("Home");
        tabScan = tab("Scan");
        tabVault = tab("Vault");
        tabHistory = tab("History");
        tabHome.setOnClickListener(v -> show(PAGE_HOME));
        tabScan.setOnClickListener(v -> show(PAGE_SCAN));
        tabVault.setOnClickListener(v -> show(PAGE_VAULT));
        tabHistory.setOnClickListener(v -> show(PAGE_HISTORY));
        tabs.addView(tabHome, weight());
        tabs.addView(tabScan, weight());
        tabs.addView(tabVault, weight());
        tabs.addView(tabHistory, weight());
        root.addView(tabs);

        ScrollView scroll = new ScrollView(this);
        body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(0, dp(12), 0, dp(24));
        scroll.addView(body);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1f));
        return root;
    }

    private void show(int next) {
        page = next;
        paintTab(tabHome, next == PAGE_HOME);
        paintTab(tabScan, next == PAGE_SCAN);
        paintTab(tabVault, next == PAGE_VAULT);
        paintTab(tabHistory, next == PAGE_HISTORY);
        boolean files = hasAllFiles();
        int alerts = Vault.list(this, "alerts").length();
        int held = Vault.list(this, "quarantine").length();
        status.setText(files
            ? "Build 10. " + held + " in vault. " + alerts + " watch alerts."
            : "Build 10. All files access is off, so file scan and vault restore are limited.");
        body.removeAllViews();
        if (next == PAGE_HOME) renderHome(files, alerts, held);
        else if (next == PAGE_SCAN) renderScan();
        else if (next == PAGE_VAULT) renderVault();
        else renderHistory();
    }

    private void renderHome(boolean files, int alerts, int held) {
        card("Protection", files ? "Shared storage can be scanned." : "Turn on All files access, or Aegis can only see apps.");
        if (!files) body.addView(button("Allow all files", true, v -> requestAllFiles()));
        body.addView(button(Vault.watch(this) ? "Downloads watch is on" : "Watch Downloads", false, v -> toggleWatch()));
        card("What this scan does", "Every scan checks three things: installed apps, shared storage, and boot. Boot means verified boot, Knox, root files, and sideloaded apps that start at startup. The raw boot partition stays sealed without root.");
        body.addView(button("Quick scan", true, v -> startScan(false)));
        body.addView(button("Full shared-storage scan", false, v -> startScan(true)));
        if (alerts > 0) {
            card("Watch alerts", alerts + " new file" + (alerts == 1 ? "" : "s") + " in Downloads.");
            body.addView(button("Clear alerts", false, v -> { Vault.clearAlerts(this); show(PAGE_HOME); }));
        }
        card("Vault", held == 0 ? "Nothing quarantined." : held + " file" + (held == 1 ? "" : "s") + " held on this phone.");
        body.addView(button("Close app", false, v -> finish()));
    }

    private void renderScan() {
        if (!scanning) {
            card("Scan", "Quick and full both check apps, files, and boot. Full walks more of shared storage. Photos and sealed Android data are skipped.");
            body.addView(button("Quick scan", true, v -> startScan(false)));
            body.addView(button("Full scan", false, v -> startScan(true)));
        }
    }

    private void renderVault() {
        JSONArray rows = Vault.list(this, "quarantine");
        if (rows.length() == 0) {
            card("Quarantine is empty", "When a scan flags a file, Quarantine copies it into Aegis private storage and deletes the original. Restore puts it back.");
            return;
        }
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.optJSONObject(i);
            if (row == null) continue;
            String id = row.optString("id");
            card(row.optString("name"), row.optString("reason") + "\n" + row.optString("original"));
            LinearLayout rowBtns = new LinearLayout(this);
            Button restore = button("Restore", true, v -> {
                try {
                    Vault.restore(this, id);
                    toast("Restored");
                } catch (Exception e) {
                    toast(e.getMessage() == null ? "Restore failed" : e.getMessage());
                }
                show(PAGE_VAULT);
            });
            Button delete = button("Delete", false, v -> {
                Vault.deleteForever(this, id);
                show(PAGE_VAULT);
            });
            rowBtns.addView(restore, weight());
            rowBtns.addView(delete, weight());
            body.addView(rowBtns);
        }
    }

    private void renderHistory() {
        JSONArray rows = Vault.list(this, "history");
        if (rows.length() == 0) {
            card("No scans yet", "Finished scans, quarantines, and Downloads-watch hits land here.");
            return;
        }
        DateFormat fmt = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.optJSONObject(i);
            if (row == null) continue;
            card(row.optString("title"), fmt.format(new Date(row.optLong("at"))) + "\n" + row.optString("detail"));
        }
    }

    private void startScan(boolean full) {
        if (scanning) return;
        if (!hasAllFiles()) {
            toast("Allow all files first, or app results will be the only thing Aegis can see.");
        }
        scanning = true;
        cancel.set(false);
        show(PAGE_SCAN);
        ProgressBar bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(100);
        bar.setProgress(2);
        TextView label = text("Starting…", 14, color(R.color.fg), false);
        body.addView(label);
        body.addView(bar);
        body.addView(button("Stop", false, v -> cancel.set(true)));
        Executors.newSingleThreadExecutor().execute(() -> {
            ScanEngine.Result result = ScanEngine.scan(this, full, cancel::get, (pct, text) ->
                runOnUiThread(() -> {
                    bar.setProgress(pct);
                    label.setText(text);
                }));
            boolean stopped = cancel.get();
            Vault.addHistory(this, stopped ? "Scan stopped" : (full ? "Full scan" : "Quick scan"),
                result.apps + " apps, " + result.files + " files, " + result.hits.size() + " findings");
            runOnUiThread(() -> finishScan(result, stopped));
        });
    }

    private void finishScan(ScanEngine.Result result, boolean stopped) {
        scanning = false;
        body.removeAllViews();
        String headline = (stopped ? "Stopped" : "Done") + " · " + result.apps + " apps · " + result.files + " files · boot";
        card(result.hits.isEmpty() ? (stopped ? "Scan stopped" : "Nothing to act on") : result.hits.size() + " findings",
            headline + ". Skipped " + result.skipped + " system, Play, and Samsung apps.");
        if (result.bootSummary != null && !result.bootSummary.isEmpty()) card("Boot", result.bootSummary);
        if (result.hits.isEmpty() && !stopped) {
            card("Clean for this pass", "No spyware-permission sideload, boot tamper, EICAR file, fake APK, ransom note, or script dropper in what this phone lets Aegis read.");
        }
        for (ScanEngine.Finding hit : result.hits) addFinding(hit);
    }

    private void addFinding(ScanEngine.Finding hit) {
        int tone = "critical".equals(hit.severity) || "high".equals(hit.severity) ? color(R.color.danger) : color(R.color.ok);
        TextView reason = text(hit.severity.toUpperCase() + " · " + hit.detail, 14, tone, false);
        reason.setPadding(0, dp(14), 0, 0);
        body.addView(reason);
        body.addView(text(hit.title, 16, color(R.color.fg), true));
        body.addView(text(hit.path, 12, color(R.color.muted), false));
        if ("app".equals(hit.kind)) {
            LinearLayout row = new LinearLayout(this);
            row.addView(button("Uninstall", true, v -> uninstall(hit.path)), weight());
            row.addView(button("App info", false, v -> openApp(hit.path)), weight());
            body.addView(row);
        } else if ("boot".equals(hit.kind)) {
            body.addView(button("Details", false, v -> details(hit)));
        } else {
            LinearLayout row = new LinearLayout(this);
            row.addView(button("Quarantine", true, v -> quarantine(hit)), weight());
            row.addView(button("Details", false, v -> details(hit)), weight());
            body.addView(row);
        }
    }

    private void quarantine(ScanEngine.Finding hit) {
        File file = new File(hit.path);
        if (!file.isFile()) { toast("File is already gone"); return; }
        try {
            Vault.quarantine(this, file, hit.detail);
            toast("Moved to vault");
            show(PAGE_VAULT);
        } catch (Exception e) {
            toast(e.getMessage() == null ? "Quarantine failed" : e.getMessage());
        }
    }

    private void details(ScanEngine.Finding hit) {
        File file = new File(hit.path);
        String extra = file.isFile() ? ("\n\nSize " + file.length() + " bytes") : "\n\nFile is not on disk.";
        new AlertDialog.Builder(this)
            .setTitle(hit.title)
            .setMessage(hit.detail + "\n\n" + hit.path + extra)
            .setPositiveButton("Close", null)
            .show();
    }

    private void uninstall(String pkg) {
        try {
            Intent intent = new Intent(Intent.ACTION_DELETE);
            intent.setData(Uri.parse("package:" + pkg));
            startActivity(intent);
        } catch (Exception e) {
            openApp(pkg);
        }
    }

    private void openApp(String pkg) {
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            intent.setData(Uri.fromParts("package", pkg, null));
            startActivity(intent);
        } catch (Exception e) {
            toast("Can't open app settings");
        }
    }

    private void toggleWatch() {
        if (Vault.watch(this)) {
            Vault.setWatch(this, false);
            stopService(new Intent(this, WatchService.class));
            toast("Downloads watch off");
            show(PAGE_HOME);
            return;
        }
        if (!hasAllFiles()) {
            toast("Allow all files before watching Downloads");
            requestAllFiles();
            return;
        }
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.POST_NOTIFICATIONS}, 41);
            return;
        }
        Vault.setWatch(this, true);
        ContextCompat.startForegroundService(this, new Intent(this, WatchService.class));
        toast("Watching Downloads");
        show(PAGE_HOME);
    }

    @Override public void onRequestPermissionsResult(int code, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(code, permissions, results);
        if (code == 41 && results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) toggleWatch();
        else if (code == 41) toast("Notifications are required for the Downloads watch");
    }

    private void requestAllFiles() {
        if (hasAllFiles()) { show(page); return; }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return;
        String pkg = getPackageName();
        Intent[] attempts = new Intent[] {
            allFiles(Uri.fromParts("package", pkg, null)),
            allFiles(Uri.parse("package:" + pkg)),
            new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
        };
        for (Intent intent : attempts) {
            try {
                startActivity(intent);
                toast("Turn Aegis on, then come back");
                return;
            } catch (Exception ignored) {}
        }
        toast("Settings, Apps, Special access, All files access, Aegis");
    }

    private Intent allFiles(Uri data) {
        Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
        intent.setData(data);
        return intent;
    }

    private boolean hasAllFiles() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) return Environment.isExternalStorageManager();
        File root = Environment.getExternalStorageDirectory();
        return root != null && root.canRead();
    }

    private void card(String title, String copy) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundColor(color(R.color.surface));
        card.setPadding(dp(14), dp(14), dp(14), dp(14));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(10);
        card.setLayoutParams(lp);
        card.addView(text(title, 16, color(R.color.fg), true));
        TextView bodyText = text(copy, 14, color(R.color.muted), false);
        bodyText.setPadding(0, dp(6), 0, 0);
        card.addView(bodyText);
        body.addView(card);
    }

    private Button button(String label, boolean primary, View.OnClickListener click) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setTextColor(primary ? Color.parseColor("#041018") : color(R.color.fg));
        button.setBackgroundColor(primary ? color(R.color.colorPrimary) : color(R.color.surface));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(8);
        lp.leftMargin = dp(4);
        lp.rightMargin = dp(4);
        button.setLayoutParams(lp);
        button.setOnClickListener(click);
        return button;
    }

    private Button tab(String label) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setTextSize(13);
        return button;
    }

    private void paintTab(Button button, boolean on) {
        button.setTextColor(on ? Color.parseColor("#041018") : color(R.color.fg));
        button.setBackgroundColor(on ? color(R.color.colorPrimary) : color(R.color.surface));
    }

    private TextView text(String value, int sp, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT_BOLD);
        return view;
    }

    private LinearLayout.LayoutParams weight() {
        return new LinearLayout.LayoutParams(0, -2, 1f);
    }

    private int color(int id) { return getResources().getColor(id); }
    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }
    private void toast(String msg) { Toast.makeText(this, msg, Toast.LENGTH_LONG).show(); }
}
