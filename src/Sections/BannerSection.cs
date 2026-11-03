using System;
using System.Globalization;
using FolderScan.Core;

namespace FolderScan.Sections {
    // Report title and the list of sections.
    public sealed class BannerSection : IReportSection {
        public void Write(ScanContext c) {
            string bar = new string('=', 60);
            c.L(bar);
            c.L(" folderscan " + ScanContext.Version + " (C# port of " + ScanContext.BaseVersion + ") : structure / content / data structure / linkage / database / semantic dependency report");
            c.L(" Target    : " + c.ScanRoot);
            c.L(" Settings  : " + c.Settings.Describe());
            c.L(" Scan time : " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture));
            c.L(bar);
            c.L(" Sections");
            c.L("  [1]-[8]  folder / file / cab / header / dat dump (same as v2)");
            c.L("  [9]      file index : every file gets No. (used in [10]-[17])");
            c.L("  [10]     content and data structure per file");
            c.L("  [11]     explicit references : file name written inside another file");
            c.L("  [12]     data linkage : same key values (lot No. etc.) in two files");
            c.L("  [13]     same content (SHA256) / same base name");
            c.L("  [14]     relation map per file (summary of [11]-[13])");
            c.L("  [15]     code symbols : def / class / function ... per source file");
            c.L("  [16]     semantic dependencies : import / exec / include / http (url + method) /");
            c.L("           config (reference + key access) / sql / database files+references / file names with context / symbol use");
            c.L("  [17]     integrated relation map : all edges of [11]-[16], roles, entry points,");
            c.L("           isolated files, mermaid graph, [17-6] one row per file pair");
            c.L("  [18]     evidence reconciliation : resolved relations / conflicts / unresolved / architecture roles");
            c.L("  [19]     gap probe : what this scan could not establish + extra evidence per gap (also gaps_*.txt)");
            c.L(" Evidence  : fact / match / candidate / weak / external");
            c.L("             weak = kept for reference, probably not a real dependency");
            c.L("             (nothing is deleted; weak is only excluded from graph and roles)");
            c.L("  Lines between \"#TSV-BEGIN name\" and \"#TSV-END\" are tab separated");
            c.L("  tables for reuse by other tools.");
            c.L("  Lines between \"#MERMAID-BEGIN name\" and \"#MERMAID-END\" are a mermaid graph.");
            c.L(bar);
            c.L();
        }
    }

    // Lists every folder and file of the target ([0/19]).
    public sealed class CollectSection : IReportSection {
        public void Write(ScanContext c) {
            c.Progress("[0/19] Collecting folders and files...");
            c.Fs = FileCollector.Collect(c.ScanRoot);
        }
    }
}
