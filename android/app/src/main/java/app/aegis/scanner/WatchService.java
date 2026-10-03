package app.aegis.scanner;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.Environment;
import android.os.FileObserver;
import android.os.IBinder;

import java.io.File;

public class WatchService extends Service {
    public static final String CHANNEL = "aegis-watch";
    private FileObserver observer;

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        Notification note = build("Watching Downloads", "New installers and scripts are checked on this phone.");
        if (Build.VERSION.SDK_INT >= 29) startForeground(41, note, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        else startForeground(41, note);
        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        if (observer != null) observer.stopWatching();
        if (dir != null && dir.isDirectory()) {
            observer = new FileObserver(dir, FileObserver.CLOSE_WRITE | FileObserver.MOVED_TO) {
                @Override public void onEvent(int event, String path) {
                    if (path == null) return;
                    File file = new File(dir, path);
                    ScanEngine.Finding hit = ScanEngine.inspectFile(file);
                    if (hit == null) return;
                    Vault.addAlert(WatchService.this, hit.title, hit.detail + " " + hit.path);
                    Vault.addHistory(WatchService.this, "Downloads watch", hit.title);
                    notifyHit(hit);
                }
            };
            observer.startWatching();
        }
        return START_STICKY;
    }

    private void notifyHit(ScanEngine.Finding hit) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) return;
        nm.notify((int) (System.currentTimeMillis() & 0xffff), build(hit.title, hit.detail));
    }

    private Notification build(String title, String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null) {
            NotificationChannel channel = new NotificationChannel(CHANNEL, "Aegis Downloads watch", NotificationManager.IMPORTANCE_DEFAULT);
            nm.createNotificationChannel(channel);
        }
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pending = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26
            ? new Notification.Builder(this, CHANNEL)
            : new Notification.Builder(this);
        return b.setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build();
    }

    @Override public void onDestroy() {
        if (observer != null) observer.stopWatching();
        super.onDestroy();
    }
}
