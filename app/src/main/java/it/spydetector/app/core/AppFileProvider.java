package it.spydetector.app.core;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * ContentProvider minimo per servire file dalla cache interna, necessario
 * per installare APK su Android 7+ (API 24+) dove file:// URI non e' consentito.
 *
 * Uso: Uri.parse("content://it.spydetector.app.fileprovider/" + fileName)
 */
public class AppFileProvider extends ContentProvider {

    private static final String AUTHORITY = "it.spydetector.app.fileprovider";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        String name = uri.getLastPathSegment();
        if (name == null || name.isEmpty()) {
            throw new FileNotFoundException("Nome file non specificato");
        }
        File file = new File(getContext().getCacheDir(), name);
        if (!file.exists()) {
            throw new FileNotFoundException(name);
        }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public String getType(Uri uri) {
        String name = uri.getLastPathSegment();
        if (name != null && name.endsWith(".apk")) {
            return "application/vnd.android.package-archive";
        }
        return "*/*";
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"_id"});
        cursor.addRow(new Object[]{uri.toString()});
        return cursor;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
