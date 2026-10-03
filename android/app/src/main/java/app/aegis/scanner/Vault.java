package app.aegis.scanner;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public final class Vault {
    private Vault() {}

    private static android.content.SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences("aegis", Context.MODE_PRIVATE);
    }

    public static JSONArray list(Context ctx, String key) {
        try { return new JSONArray(prefs(ctx).getString(key, "[]")); }
        catch (Exception e) { return new JSONArray(); }
    }

    public static void save(Context ctx, String key, JSONArray array) {
        prefs(ctx).edit().putString(key, array.toString()).apply();
    }

    public static File quarantineFile(Context ctx, String id, String name) {
        File dir = new File(ctx.getFilesDir(), "quarantine");
        dir.mkdirs();
        String safe = name.replaceAll("[^A-Za-z0-9._-]", "_");
        return new File(dir, id + "-" + safe);
    }

    public static JSONObject quarantine(Context ctx, File source, String reason) throws Exception {
        String id = Long.toString(System.currentTimeMillis());
        File dest = quarantineFile(ctx, id, source.getName());
        copy(source, dest);
        if (!source.delete()) {
            dest.delete();
            throw new IllegalStateException("Copied, but Android would not remove the original.");
        }
        JSONObject row = new JSONObject();
        row.put("id", id);
        row.put("name", source.getName());
        row.put("original", source.getAbsolutePath());
        row.put("stored", dest.getAbsolutePath());
        row.put("reason", reason);
        row.put("at", id);
        JSONArray all = list(ctx, "quarantine");
        JSONArray next = new JSONArray();
        next.put(row);
        for (int i = 0; i < all.length() && i < 40; i++) next.put(all.get(i));
        save(ctx, "quarantine", next);
        addHistory(ctx, "Quarantine", source.getName() + " \u2014 " + reason);
        return row;
    }

    public static void restore(Context ctx, String id) throws Exception {
        JSONArray all = list(ctx, "quarantine");
        JSONArray next = new JSONArray();
        JSONObject found = null;
        for (int i = 0; i < all.length(); i++) {
            JSONObject row = all.getJSONObject(i);
            if (id.equals(row.optString("id"))) found = row;
            else next.put(row);
        }
        if (found == null) throw new IllegalStateException("Not in quarantine.");
        File stored = new File(found.getString("stored"));
        File original = new File(found.getString("original"));
        if (original.getParentFile() != null) original.getParentFile().mkdirs();
        copy(stored, original);
        stored.delete();
        save(ctx, "quarantine", next);
        addHistory(ctx, "Restore", original.getName());
    }

    public static void deleteForever(Context ctx, String id) {
        try {
            JSONArray all = list(ctx, "quarantine");
            JSONArray next = new JSONArray();
            for (int i = 0; i < all.length(); i++) {
                JSONObject row = all.getJSONObject(i);
                if (id.equals(row.optString("id"))) new File(row.optString("stored")).delete();
                else next.put(row);
            }
            save(ctx, "quarantine", next);
        } catch (Exception ignored) {}
    }

    public static void addHistory(Context ctx, String title, String detail) {
        try {
            JSONObject row = new JSONObject();
            row.put("at", System.currentTimeMillis());
            row.put("title", title);
            row.put("detail", detail);
            JSONArray all = list(ctx, "history");
            JSONArray next = new JSONArray();
            next.put(row);
            for (int i = 0; i < all.length() && i < 40; i++) next.put(all.get(i));
            save(ctx, "history", next);
        } catch (Exception ignored) {}
    }

    public static void addAlert(Context ctx, String title, String detail) {
        try {
            JSONObject row = new JSONObject();
            row.put("at", System.currentTimeMillis());
            row.put("title", title);
            row.put("detail", detail);
            JSONArray all = list(ctx, "alerts");
            JSONArray next = new JSONArray();
            next.put(row);
            for (int i = 0; i < all.length() && i < 20; i++) next.put(all.get(i));
            save(ctx, "alerts", next);
        } catch (Exception ignored) {}
    }

    public static void clearAlerts(Context ctx) {
        save(ctx, "alerts", new JSONArray());
    }

    public static boolean watch(Context ctx) {
        return prefs(ctx).getBoolean("watch", false);
    }

    public static void setWatch(Context ctx, boolean on) {
        prefs(ctx).edit().putBoolean("watch", on).apply();
    }

    private static void copy(File from, File to) throws Exception {
        if (to.getParentFile() != null) to.getParentFile().mkdirs();
        try (InputStream in = new FileInputStream(from); OutputStream out = new FileOutputStream(to)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
    }
}
