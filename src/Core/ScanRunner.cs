using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace FolderScan.Core {
    public sealed class ScanResult {
        public string ReportPath;   // null when no report was created
        public string GapsPath;     // null when no gap file was created
        public string HandOverPath; // latest_diag.json, or null
        public string MapPath;      // latest_map.html, or null
    }

    // One scan of one target folder (":RUNONE" of v5.18).
    // The target is only read. One folder per scan :
    //   <outDir>\YYYYMMDD_HHMMSS_<target name>\scan.txt / gaps.txt / diag.json / diag.txt
    // Ledgers (folderscan_*.tsv) and latest_diag.json stay directly in <outDir>.
    public sealed class ScanRunner {
        readonly Settings settings;
        readonly IConsoleLog log;
        readonly Func<List<IReportSection>> sections;

        public ScanRunner(Settings settings, IConsoleLog log, Func<List<IReportSection>> sections) {
            this.settings = settings; this.log = log; this.sections = sections;
        }

        public ScanResult Run(string target, string outDir, string batchGapsPath) {
            ScanResult res = new ScanResult();
            System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
            List<KeyValuePair<string, double>> timing = new List<KeyValuePair<string, double>>();
            target = (target ?? "").Trim().Trim('"');
            if (target.EndsWith("\\") && !target.EndsWith(":\\")) target = target.Substring(0, target.Length - 1);
            if (!Directory.Exists(target)) {
                log.Info("");
                log.Info("[ERROR] Folder not found or no read permission:");
                log.Info("  " + target);
                return res;
            }
            string ts = UniqueStamp(outDir);
            string runName = ts + "_" + SafeName(RootName(target));
            string outPath = Path.Combine(Path.Combine(outDir, runName), "scan.txt");
            string work = Path.Combine(Path.GetTempPath(), "folderscan_" + ts);
            Directory.CreateDirectory(work);
            log.Info("");
            log.Info("Target : " + target);
            log.Info("Output : " + outPath);
            log.Info("");
            try {
                List<string> cand = new List<string>();
                cand.Add(outPath);
                cand.Add(Path.Combine(Path.Combine(Path.Combine(Path.GetTempPath(), "folderscan"), runName), "scan.txt"));
                using (ReportWriter rw = ReportWriter.Open(cand, log)) {
                    if (rw == null) { log.Info("[FATAL] report file could not be created. scan stopped."); return res; }
                    res.ReportPath = rw.Path;
                    ScanContext ctx = new ScanContext();
                    ctx.Settings = settings;
                    ctx.Log = log;
                    ctx.Report = rw;
                    ctx.OutRoot = Path.GetDirectoryName(Path.GetDirectoryName(rw.Path));
                    ctx.ScanRoot = RootName(target);
                    ctx.WorkDir = work;
                    ctx.BatchGapsPath = batchGapsPath;
                    ctx.DefaultCp = ScanContext.AnsiCodePage();
                    try {
                        foreach (IReportSection s in sections()) {
                            System.Diagnostics.Stopwatch st = System.Diagnostics.Stopwatch.StartNew();
                            s.Write(ctx);
                            timing.Add(new KeyValuePair<string, double>(s.GetType().Name, st.Elapsed.TotalSeconds));
                        }
                    } catch (Exception ex) {
                        Exception e = ex is AggregateException ? ((AggregateException)ex).Flatten().InnerExceptions[0] : ex;
                        rw.L("[FATAL] " + e.Message);
                        log.Info("[FATAL] " + e.Message);
                    }
                    res.GapsPath = ctx.GapsPath;
                    res.HandOverPath = ctx.HandOverPath;
                    res.MapPath = ctx.MapPath;
                }
            } finally {
                try { Directory.Delete(work, true); } catch { }
            }
            log.Info("");
            if (res.ReportPath == null || !File.Exists(res.ReportPath)) {
                log.Info("[ERROR] Report file was not created. See messages above.");
                res.ReportPath = null;
                return res;
            }
            log.Info(string.Format(CultureInfo.InvariantCulture, "Done. ({0:0.0} s)", sw.Elapsed.TotalSeconds));
            log.Info("  Full scan : " + res.ReportPath);
            if (res.GapsPath != null) log.Info("  Gaps      : " + res.GapsPath);
            // where the time went (console only, helps to find slow parts)
            foreach (KeyValuePair<string, double> t in timing)
                if (t.Value >= 0.5) log.Info(string.Format(CultureInfo.InvariantCulture, "  time {0,-22} {1,6:0.0} s", t.Key, t.Value));
            if (res.HandOverPath != null || res.MapPath != null) log.Info("");
            if (res.MapPath != null) log.Info(" >>> System map (open in Edge)                   : " + res.MapPath);
            if (res.HandOverPath != null) {
                log.Info(" >>> To ask for advice, hand over this one file : " + res.HandOverPath);
            }
            return res;
        }

        // Full path without trailing separator ("C:\" -> "C:"), as $SCANROOT of v5.18.
        static string RootName(string target) {
            return new DirectoryInfo(target).FullName.TrimEnd('\\');
        }

        // yyyyMMdd_HHmmss ; waits a second when a scan folder with that time already exists.
        public static string UniqueStamp(string outDir) {
            while (true) {
                string ts = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
                bool used = false;
                try { used = Directory.Exists(outDir) && Directory.GetDirectories(outDir, ts + "_*").Length > 0; } catch { }
                if (!used) return ts;
                Thread.Sleep(1000);
            }
        }

        // last folder name of the target, usable as a file name (max 40 chars)
        static string SafeName(string root) {
            string n = root.TrimEnd('\\', '/');
            int i = Math.Max(n.LastIndexOf('\\'), n.LastIndexOf('/'));
            if (i >= 0) n = n.Substring(i + 1);
            StringBuilder sb = new StringBuilder();
            foreach (char ch in n) sb.Append(Array.IndexOf(Path.GetInvalidFileNameChars(), ch) >= 0 || ch == ':' || ch == ' ' ? '_' : ch);
            string s = sb.ToString().Trim('_', '.');
            if (s.Length == 0) s = "root";
            return s.Length > 40 ? s.Substring(0, 40) : s;
        }
    }
}
