package app.aegis.scanner;

import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.Settings;
import android.util.Base64;

import androidx.activity.result.ActivityResult;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.ActivityCallback;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

@CapacitorPlugin(name = "AegisFs")
public class AegisFsPlugin extends Plugin {

    @PluginMethod
    public void hasAllFiles(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("granted", hasAllFilesAccess());
        call.resolve(ret);
    }

    @PluginMethod
    public void requestAllFiles(PluginCall call) {
        if (hasAllFilesAccess()) {
            JSObject ret = new JSObject();
            ret.put("granted", true);
            call.resolve(ret);
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getContext().getPackageName()));
                startActivityForResult(call, intent, "onAllFilesResult");
            } catch (Exception e) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                startActivityForResult(call, intent, "onAllFilesResult");
            }
        } else {
            JSObject ret = new JSObject();
            ret.put("granted", Environment.getExternalStorageDirectory().canRead());
            call.resolve(ret);
        }
    }

    @ActivityCallback
    private void onAllFilesResult(PluginCall call, ActivityResult result) {
        if (call == null) return;
        JSObject ret = new JSObject();
        ret.put("granted", hasAllFilesAccess());
        call.resolve(ret);
    }

    @PluginMethod
    public void listStorage(PluginCall call) {
        int cap = call.getInt("cap", 800);
        JSArray extArr = call.getArray("extensions");
        Set<String> extensions = new HashSet<>();
        if (extArr != null) {
            try {
                for (int i = 0; i < extArr.length(); i++) {
                    extensions.add(extArr.getString(i).toLowerCase(Locale.US));
                }
            } catch (Exception ignored) {
            }
        }
        File root = Environment.getExternalStorageDirectory();
        JSArray files = new JSArray();
        if (root == null || !root.exists()) {
            JSObject ret = new JSObject();
            ret.put("files", files);
            call.resolve(ret);
            return;
        }
        ArrayDeque<File> queue = new ArrayDeque<>();
        queue.add(root);
        int count = 0;
        while (!queue.isEmpty() && count < cap) {
            File dir = queue.removeFirst();
            File[] children = dir.listFiles();
            if (children == null) continue;
            for (File child : children) {
                if (count >= cap) break;
                String name = child.getName();
                if (name.startsWith(".") && !name.equals(".nomedia")) continue;
                if (child.isDirectory()) {
                    if (skipDir(name)) continue;
                    queue.addLast(child);
                } else if (child.isFile()) {
                    if (!extensions.isEmpty() && !extensions.contains(extOf(name))) continue;
                    JSObject item = new JSObject();
                    item.put("path", child.getAbsolutePath());
                    item.put("size", child.length());
                    files.put(item);
                    count++;
                }
            }
        }
        JSObject ret = new JSObject();
        ret.put("files", files);
        call.resolve(ret);
    }

    @PluginMethod
    public void readPrefix(PluginCall call) {
        String path = call.getString("path");
        int maxBytes = call.getInt("maxBytes", 524288);
        if (path == null) {
            call.reject("path required");
            return;
        }
        File file = new File(path);
        if (!file.exists() || !file.canRead()) {
            call.reject("unreadable");
            return;
        }
        int toRead = (int) Math.min(file.length(), Math.max(1, maxBytes));
        byte[] buf = new byte[toRead];
        try (FileInputStream in = new FileInputStream(file)) {
            int n = in.read(buf);
            if (n < 0) n = 0;
            String b64 = Base64.encodeToString(buf, 0, n, Base64.NO_WRAP);
            JSObject ret = new JSObject();
            ret.put("data", b64);
            call.resolve(ret);
        } catch (Exception e) {
            call.reject(e.getMessage());
        }
    }

    private boolean hasAllFilesAccess() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager();
        }
        File root = Environment.getExternalStorageDirectory();
        return root != null && root.canRead();
    }

    private boolean skipDir(String name) {
        String n = name.toLowerCase(Locale.US);
        return n.equals("android")
            || n.equals("cache")
            || n.equals(".thumbnails")
            || n.equals("lost.dir")
            || n.equals("lost+found");
    }

    private String extOf(String name) {
        int i = name.lastIndexOf('.');
        if (i < 0 || i == name.length() - 1) return "";
        return name.substring(i + 1).toLowerCase(Locale.US);
    }
}
