package it.spydetector.app.core;

import java.util.List;

/** Un controllo eseguibile sulla scansione corrente. */
public interface Check {
    String id();
    String category();
    String label();
    List<Finding> run(ScanData data) throws Exception;
}
