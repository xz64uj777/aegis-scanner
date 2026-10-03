package app.aegis.scanner;

import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Environment;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class ScanEngine {
    public static final String[] RISKY_EXT = {
        "apk", "xapk", "apks", "apkm", "dex", "exe", "dll", "js", "vbs", "ps1",
        "bat", "cmd", "hta", "jar", "zip", "7z", "rar", "pdf", "doc", "docx",
        "xls", "xlsx", "msi", "iso", "sh", "html", "scr", "com"
    };

    private ScanEngine() {}

    public static final class Finding {
        public final String kind;
        public final String title;
        public final String path;
        public final String detail;
        public final String severity;
        public Finding(String kind, String title, String path, String detail, String severity) {
            this.kind = kind;
            this.title = title;
            this.path = path;
            this.detail = detail;
            this.severity = severity;
        }
    }

    public static final class Result {
        public int apps;
        public int files;
        public int skipped;
        public String bootSummary = "";
        public final List<Finding> hits = new ArrayList<>();
    }

    public interface Cancel {
        boolean get();
    }

    public interface Progress {
        void onProgress(int percent, String label);
    }

    public static Result scan(Context ctx, boolean full, Cancel cancel, Progress progress) {
        Result result = new Result();
        scanApps(ctx, result, cancel, progress);
        if (cancel.get()) return result;
        progress.onProgress(38, "Boot");
        scanBoot(ctx, result);
        if (cancel.get()) return result;
        List<File> roots = full ? fullRoots() : quickRoots();
        Set<String> ext = new HashSet<>();
        for (String e : RISKY_EXT) ext.add(e);
        int cap = full ? 2500 : 700;
        List<File> files = collect(roots, cap, ext, cancel);
        result.files = files.size();
        int n = files.size();
        for (int i = 0; i < n; i++) {
            if (cancel.get()) break;
            Finding hit = inspectFile(files.get(i));
            if (hit != null) result.hits.add(hit);
            final int done = i + 1;
            progress.onProgress(40 + Math.round(done * 60f / Math.max(n, 1)), "Files " + done + " / " + n);
        }
        return result;
    }

    private static void scanBoot(Context ctx, Result result) {
        String verified = prop("ro.boot.verifiedbootstate");
        String flash = prop("ro.boot.flash.locked");
        String vbmeta = prop("ro.boot.vbmeta.device_state");
        String verity = prop("ro.boot.veritymode");
        String warranty = prop("ro.boot.warranty_bit");
        if (warranty.isEmpty()) warranty = prop("ro.warranty_bit");
        boolean unlocked = "orange".equals(verified) || "unlocked".equalsIgnoreCase(vbmeta) || "0".equals(flash);
        boolean custom = "yellow".equals(verified);
        if (unlocked) {
            result.hits.add(new Finding("boot", "Bootloader unlocked", "ro.boot.verifiedbootstate=" + value(verified),
                "Verified boot is not green. This phone can load a modified boot image.", "critical"));
        } else if (custom) {
            result.hits.add(new Finding("boot", "Custom boot key", "ro.boot.verifiedbootstate=yellow",
                "Boot is signed with a custom key, not the Samsung key.", "high"));
        }
        if ("1".equals(warranty)) {
            result.hits.add(new Finding("boot", "Knox warranty bit tripped", "ro.boot.warranty_bit=1",
                "Samsung has recorded a boot or firmware modification.", "high"));
        }
        if ("disabled".equals(verity) || "eio".equals(verity)) {
            result.hits.add(new Finding("boot", "dm-verity disabled", "ro.boot.veritymode=" + verity,
                "Boot integrity checks are not enforcing.", "high"));
        }
        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) {
            result.hits.add(new Finding("boot", "Test-keys build", "android.os.Build.TAGS",
                "This system image was signed with public test keys.", "high"));
        }
        String[] binaries = {
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/debug_ramdisk/su",
            "/system/bin/magisk", "/sbin/.magisk", "/system/xbin/magisk"
        };
        for (String path : binaries) {
            if (new File(path).exists()) {
                result.hits.add(new Finding("boot", "Root binary", path, "A superuser or Magisk file is on the boot or system path.", "critical"));
            }
        }
        String[] rootPkgs = {
            "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "me.weishu.kernelsu", "com.noshufou.android.su"
        };
        PackageManager pm = ctx.getPackageManager();
        for (String pkg : rootPkgs) {
            try {
                pm.getPackageInfo(pkg, 0);
                if (!already(result, pkg)) {
                    result.hits.add(new Finding("app", pkg, pkg, "Root manager installed. It can change boot and system.", "critical"));
                }
            } catch (Exception ignored) {}
        }
        try {
            List<PackageInfo> pkgs = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
            for (PackageInfo pkg : pkgs) {
                if (pkg.applicationInfo == null) continue;
                if (!has(pkg.requestedPermissions, "android.permission.RECEIVE_BOOT_COMPLETED")) continue;
                int flags = pkg.applicationInfo.flags;
                if ((flags & ApplicationInfo.FLAG_SYSTEM) != 0 || (flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) continue;
                String name = pkg.packageName;
                String installer = installerOf(pm, name);
                if (isVendor(name) || isTrusted(installer) || already(result, name)) continue;
                String label;
                try { label = pm.getApplicationLabel(pkg.applicationInfo).toString(); }
                catch (Exception e) { label = name; }
                result.hits.add(new Finding("app", label, name,
                    "Starts when the phone boots and was not installed from Play or Galaxy Store.", "moderate"));
            }
        } catch (Exception ignored) {}
        int sealed = 0;
        String[] sealedPaths = {"/boot", "/efs", "/data", "/vendor", "/system/bin"};
        for (String path : sealedPaths) {
            File file = new File(path);
            if (!file.exists() || !file.canRead()) sealed++;
        }
        String state = verified.isEmpty() ? "hidden" : verified;
        result.bootSummary = "Verified boot " + state
            + ". Bootloader " + (unlocked ? "unlocked" : "locked or not reported")
            + ". Knox bit " + (warranty.isEmpty() ? "hidden" : warranty)
            + ". " + sealed + " of " + sealedPaths.length + " boot paths are sealed, which is normal without root.";
    }

    private static boolean already(Result result, String path) {
        for (Finding hit : result.hits) if (path.equals(hit.path)) return true;
        return false;
    }

    private static String prop(String key) {
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            Object value = clazz.getMethod("get", String.class, String.class).invoke(null, key, "");
            return value == null ? "" : value.toString().trim().toLowerCase(Locale.US);
        } catch (Exception e) {
            return "";
        }
    }

    private static String value(String raw) {
        return raw == null || raw.isEmpty() ? "hidden" : raw;
    }

    public static Finding inspectFile(File file) {
        if (file == null || !file.isFile()) return null;
        byte[] buf = readPrefix(file, 524288);
        if (buf == null) return null;
        String name = file.getName();
        String lower = name.toLowerCase(Locale.US);
        String text = ascii(buf);
        String path = file.getAbsolutePath();
        if (text.contains("eicar-standard-antivirus-test-file") || text.contains("x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar")) {
            return new Finding("file", name, path, "EICAR test file. Harmless. Confirms detection works.", "high");
        }
        if (text.contains("your files have been encrypted") || text.contains("vssadmin delete shadows")) {
            return new Finding("file", name, path, "Ransomware note or shadow-copy deletion command.", "critical");
        }
        if (text.contains("powershell -enc") || text.contains("frombase64string") || text.contains("invoke-expression")) {
            return new Finding("file", name, path, "Hidden PowerShell. Common dropper pattern.", "high");
        }
        if (text.contains("createremotethread") || text.contains("writeprocessmemory") || text.contains("ntunmapviewofsection")) {
            return new Finding("file", name, path, "Process-injection strings.", "high");
        }
        if (text.contains("wscript.shell") || (lower.endsWith(".js") && text.contains("eval("))) {
            return new Finding("file", name, path, "Script host dropper pattern.", "moderate");
        }
        if (buf.length >= 2 && buf[0] == 0x4d && buf[1] == 0x5a && (lower.endsWith(".apk") || lower.endsWith(".pdf") || lower.endsWith(".jpg"))) {
            return new Finding("file", name, path, "Windows executable bytes inside a non-exe name.", "high");
        }
        if (lower.endsWith(".apk") && !(buf.length >= 2 && buf[0] == 0x50 && buf[1] == 0x4b)) {
            return new Finding("file", name, path, "Named like an APK but it is not a ZIP.", "high");
        }
        if (lower.matches(".*\\.(pdf|jpg|png|doc|xls)\\.(exe|apk|js|scr|bat)$")) {
            return new Finding("file", name, path, "Double extension. Classic dropper name.", "high");
        }
        if (lower.endsWith(".apk")) {
            Finding apk = inspectApk(file);
            if (apk != null) return apk;
        }
        return null;
    }

    private static Finding inspectApk(File file) {
        ZipFile zip = null;
        try {
            zip = new ZipFile(file);
            StringBuilder blob = new StringBuilder();
            ZipEntry manifest = zip.getEntry("AndroidManifest.xml");
            if (manifest != null) blob.append(ascii(readEntry(zip, manifest, 262144)));
            ZipEntry dex = zip.getEntry("classes.dex");
            if (dex != null) blob.append(ascii(readEntry(zip, dex, 262144)));
            String text = blob.toString();
            boolean access = text.contains("bind_accessibility_service");
            boolean sms = text.contains("receive_sms") || text.contains("read_sms");
            boolean install = text.contains("request_install_packages");
            boolean overlay = text.contains("system_alert_window");
            boolean admin = text.contains("bind_device_admin");
            if (access && (sms || install || overlay)) {
                return new Finding("file", file.getName(), file.getAbsolutePath(),
                    "APK asks for accessibility plus SMS, install, or overlay. Banker pattern.", "critical");
            }
            if (admin && install) {
                return new Finding("file", file.getName(), file.getAbsolutePath(),
                    "APK asks for device admin and package install.", "high");
            }
            return null;
        } catch (Exception e) {
            return null;
        } finally {
            try { if (zip != null) zip.close(); } catch (Exception ignored) {}
        }
    }

    private static void scanApps(Context ctx, Result result, Cancel cancel, Progress progress) {
        try {
            PackageManager pm = ctx.getPackageManager();
            int flags = PackageManager.GET_PERMISSIONS | PackageManager.GET_SERVICES | PackageManager.GET_RECEIVERS;
            List<PackageInfo> pkgs = pm.getInstalledPackages(flags);
            result.apps = pkgs.size();
            int i = 0;
            for (PackageInfo pkg : pkgs) {
                if (cancel.get()) return;
                i++;
                progress.onProgress(Math.round(i * 35f / Math.max(pkgs.size(), 1)), "Apps " + i + " / " + pkgs.size());
                if (pkg.applicationInfo == null) continue;
                int appFlags = pkg.applicationInfo.flags;
                if ((appFlags & ApplicationInfo.FLAG_SYSTEM) != 0 || (appFlags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                    result.skipped++;
                    continue;
                }
                String name = pkg.packageName;
                String installer = installerOf(pm, name);
                if (isVendor(name) || isTrusted(installer)) {
                    result.skipped++;
                    continue;
                }
                Finding hit = inspectApp(pm, pkg, installer);
                if (hit == null) result.skipped++;
                else result.hits.add(hit);
            }
        } catch (Exception ignored) {}
    }

    private static Finding inspectApp(PackageManager pm, PackageInfo pkg, String installer) {
        boolean access = false;
        boolean notif = false;
        boolean admin = false;
        if (pkg.services != null) {
            for (ServiceInfo s : pkg.services) {
                if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(s.permission)) access = true;
                if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE".equals(s.permission)) notif = true;
            }
        }
        if (pkg.receivers != null) {
            for (ActivityInfo r : pkg.receivers) {
                if ("android.permission.BIND_DEVICE_ADMIN".equals(r.permission)) admin = true;
            }
        }
        String[] perms = pkg.requestedPermissions;
        boolean sms = has(perms, "android.permission.RECEIVE_SMS") || has(perms, "android.permission.READ_SMS");
        boolean install = has(perms, "android.permission.REQUEST_INSTALL_PACKAGES");
        boolean overlay = has(perms, "android.permission.SYSTEM_ALERT_WINDOW");
        boolean deviceAdmin = admin || has(perms, "android.permission.BIND_DEVICE_ADMIN");
        if (!access && !notif && !deviceAdmin && !sms && !(install && overlay) && !install) return null;
        String label;
        try { label = pm.getApplicationLabel(pkg.applicationInfo).toString(); }
        catch (Exception e) { label = pkg.packageName; }
        String who = installer == null ? "unknown installer" : installer;
        String reason;
        String severity;
        if (access && (sms || install || overlay)) {
            reason = "Sideloaded accessibility app that can read the screen and act on it.";
            severity = "critical";
        } else if (access) {
            reason = "Sideloaded accessibility service. Used by banking malware.";
            severity = "high";
        } else if (sms && (install || overlay)) {
            reason = "Can read texts and install apps or draw over the screen.";
            severity = "critical";
        } else if (sms) {
            reason = "Sideloaded app can read SMS, including login codes.";
            severity = "high";
        } else if (deviceAdmin) {
            reason = "Sideloaded device admin. Hard to remove.";
            severity = "high";
        } else if (notif) {
            reason = "Sideloaded notification listener. Can read incoming alerts.";
            severity = "high";
        } else if (install && overlay) {
            reason = "Can draw over other apps and install packages.";
            severity = "high";
        } else {
            reason = "Not from Play or Galaxy Store, and it can install other apps.";
            severity = "moderate";
        }
        return new Finding("app", label, pkg.packageName, reason + " Installer: " + who + ".", severity);
    }

    private static boolean isVendor(String pkg) {
        return pkg.startsWith("com.samsung.") || pkg.startsWith("com.sec.") || pkg.startsWith("com.google.")
            || pkg.startsWith("com.android.") || pkg.startsWith("android.") || pkg.startsWith("org.chromium.webapk.")
            || pkg.startsWith("com.att.") || pkg.startsWith("com.aura.") || pkg.startsWith("com.monotype.");
    }

    private static boolean isTrusted(String installer) {
        if (installer == null || installer.isEmpty()) return false;
        return installer.equals("com.android.vending")
            || installer.equals("com.sec.android.app.samsungapps")
            || installer.equals("com.samsung.android.shortcutbackupservice")
            || installer.equals("com.google.android.apps.restore");
    }

    private static String installerOf(PackageManager pm, String pkg) {
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

    private static boolean has(String[] perms, String want) {
        if (perms == null) return false;
        for (String p : perms) if (want.equals(p)) return true;
        return false;
    }

    private static List<File> quickRoots() {
        List<File> roots = new ArrayList<>();
        File base = Environment.getExternalStorageDirectory();
        add(roots, Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS));
        add(roots, Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS));
        if (base != null) {
            add(roots, new File(base, "Download"));
            add(roots, new File(base, "Bluetooth"));
            add(roots, new File(base, "Telegram"));
            add(roots, new File(base, "Signal"));
            add(roots, new File(base, "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents"));
            add(roots, new File(base, "Android/media/org.telegram.messenger/Telegram"));
        }
        return roots;
    }

    private static List<File> fullRoots() {
        List<File> roots = new ArrayList<>();
        add(roots, Environment.getExternalStorageDirectory());
        return roots;
    }

    private static void add(List<File> roots, File file) {
        if (file != null && file.isDirectory()) roots.add(file);
    }

    private static List<File> collect(List<File> roots, int cap, Set<String> ext, Cancel cancel) {
        List<File> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        ArrayDeque<File> queue = new ArrayDeque<>();
        for (File root : roots) queue.add(root);
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
                } else if (ext.contains(extOf(name)) && seen.add(child.getAbsolutePath())) {
                    out.add(child);
                }
            }
        }
        return out;
    }

    private static boolean skipDir(String name) {
        String n = name.toLowerCase(Locale.US);
        return n.equals("android") || n.equals("cache") || n.equals(".thumbnails")
            || n.equals("lost.dir") || n.equals("lost+found");
    }

    private static String extOf(String name) {
        int i = name.lastIndexOf('.');
        if (i < 0 || i == name.length() - 1) return "";
        return name.substring(i + 1).toLowerCase(Locale.US);
    }

    private static byte[] readPrefix(File file, int max) {
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

    private static byte[] readEntry(ZipFile zip, ZipEntry entry, int max) {
        try (java.io.InputStream in = zip.getInputStream(entry); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int left = max;
            int n;
            while (left > 0 && (n = in.read(buf, 0, Math.min(buf.length, left))) > 0) {
                out.write(buf, 0, n);
                left -= n;
            }
            return out.toByteArray();
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static String ascii(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(Math.min(bytes.length, 65536));
        int n = Math.min(bytes.length, 65536);
        for (int i = 0; i < n; i++) {
            int c = bytes[i] & 0xff;
            sb.append(c >= 32 && c < 127 ? (char) c : ' ');
        }
        return sb.toString().toLowerCase(Locale.US);
    }
}
