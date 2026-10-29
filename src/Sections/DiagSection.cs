using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using FolderScan.Core;
using FolderScan.Diag;

namespace FolderScan.Sections {
    // Self diagnosis (after [19]) : findings ranked by importance, detectors that came up empty,
    // what was not examined, and the change from the previous scan of the same target.
    // Written to <scan folder>\diag.json (for tools / AI) and diag.txt, copied to <output>\latest_diag.json,
    // summary on the console.
    // The scan report itself is not changed.
    public sealed class DiagSection : IReportSection {
        public void Write(ScanContext c) {
            if (c.Settings.Diag != 1) return;
            c.Progress("[diag] Self diagnosis...");
            try { Run(c); } catch (Exception ex) { c.Log.Info("  [warn] self diagnosis failed: " + ex.Message); }
        }

        static void Run(ScanContext c) {
            DiagStore store = new DiagStore(c.OutRoot);
            DiagResult r = new DiagResult();
            r.Prev = store.LoadPrevious(c.ScanRoot, c.Log);
            r.Findings = FindingBuilder.Build(c, r.Prev == null ? null : r.Prev.Findings);
            r.Detectors = DetectorDiag.Run(c, r.Findings);
            r.Coverage = CoverageDiag.Run(c);
            r.Compare();
            c.Diag = r;

            string json = Path.Combine(c.RunDir, "diag.json"), txt = Path.Combine(c.RunDir, "diag.txt");
            int top = Math.Max(1, c.Settings.DiagTop);
            string body = Json.Write(DiagOutput.ToJson(c, r, top));
            File.WriteAllText(json, body, new UTF8Encoding(false));
            // fixed name for handing over : always the newest diagnosis
            string latest = Path.Combine(c.OutRoot, "latest_diag.json");
            try { File.WriteAllText(latest, body, new UTF8Encoding(false)); } catch (Exception ex) { c.Log.Info("  [warn] latest_diag.json: " + ex.Message); }
            string hist = string.Join("\t", new string[] { c.RunId, ScanContext.Version, c.ScanRoot, r.Actionable.ToString(), r.Tracked.ToString(), r.Explained.ToString(), r.Benign.ToString(),
                r.New.Count.ToString(), r.Resolved.Count.ToString(), r.Suspicious.ToString(), r.Coverage.Count.ToString() });
            store.Append(c.RunId, c.ScanRoot, json, hist, c.Log);
            List<string> trend = store.Trend(c.ScanRoot, 5);
            File.WriteAllLines(txt, DiagOutput.Text(c, r, trend, top, true), new UTF8Encoding(true));

            c.Log.Info("");
            foreach (string s in DiagOutput.Text(c, r, trend, top, false)) c.Log.Info(s);
            c.Log.Info(" diag : " + json);
            c.HandOverPath = latest;
        }
    }
}
