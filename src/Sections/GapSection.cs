using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using FolderScan.Core;
using FolderScan.Gaps;

namespace FolderScan.Sections {
    // [19] GAP PROBE : what this scan could not establish + extra evidence per gap.
    // Also writes gaps_*.txt, folderscan_history.tsv, folderscan_gaps.tsv and the batch gaps file.
    public sealed class GapSection : IReportSection {
        public void Write(ScanContext c) {
            c.Progress("[19/19] Gap probe...");
            string outDir = c.OutRoot;
            string runId = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

            MetricsHistory mh = new MetricsHistory();
            mh.Collect(c);
            mh.History(c, Path.Combine(outDir, "folderscan_history.tsv"), runId, c.Log);

            GapLedger led = new GapLedger(Path.Combine(outDir, "folderscan_gaps.tsv"));
            led.Read(c.ScanRoot, c.Log);

            GapCollector col = new GapCollector(c, runId);
            col.Collect();
            led.ApplyStatus(col.Gaps);

            GapText text = new GapText(c.Link, c.Settings.SnipLen);
            new GapProbes(c, text).Run(col.Gaps);
            GapExplainer ex = new GapExplainer(c, text);
            ex.Run(col.Gaps);

            var resolved = led.Resolved(col.Seen);
            c.Gaps = col.Gaps; c.GapsResolved = resolved; c.RunId = runId;
            led.Write(c.ScanRoot, runId, col.Gaps, col.Seen, c.Log);

            GapReport rep = new GapReport();
            rep.Build(c, runId, col, ex, resolved, led, mh);

            c.L("==== [19] GAP PROBE (also saved as a separate gaps file) ====");
            foreach (string s in rep.Lines) c.L(s);
            c.L();
            string gapf = Path.Combine(c.RunDir, "gaps.txt");
            if (string.Equals(gapf, c.Report.Path, StringComparison.OrdinalIgnoreCase)) gapf = c.Report.Path + ".gaps.txt";
            try {
                File.WriteAllLines(gapf, rep.Lines, new UTF8Encoding(true));
                c.GapsPath = gapf;
            } catch (Exception e) { c.Log.Info("  [warn] gap file write: " + e.Message); }
            if (!string.IsNullOrEmpty(c.BatchGapsPath)) {
                try { File.AppendAllText(c.BatchGapsPath, string.Join("\r\n", rep.Lines.ToArray()) + "\r\n\r\n", new UTF8Encoding(true)); }
                catch (Exception e) { c.Log.Info("  [warn] batch gaps: " + e.Message); }
            }
        }
    }
}
