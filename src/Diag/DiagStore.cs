using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FolderScan.Core;

namespace FolderScan.Diag {
    // The diag of the previous scan of the same target, read back from its json.
    public sealed class PrevDiag {
        public string Run = "", JsonPath = "";
        public readonly Dictionary<string, PrevFinding> Findings = new Dictionary<string, PrevFinding>(StringComparer.Ordinal);
        public readonly Dictionary<string, int[]> Detectors = new Dictionary<string, int[]>(StringComparer.OrdinalIgnoreCase);   // name -> found, resolved, unresolved
        public readonly Dictionary<string, int> Coverage = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    }

    // folderscan_diag_index.tsv  : RunTime / Target / json path (to find the previous json)
    // folderscan_diag_history.tsv: counts per run (improvement speed)
    public sealed class DiagStore {
        public const string HistoryHeader = "RunTime\tVersion\tTarget\tActionable\tTracked\tExplained\tBenign\tNew\tResolved\tSuspiciousDetectors\tNotExamined";
        readonly string dir;
        public DiagStore(string dir) { this.dir = dir; }
        string Index { get { return Path.Combine(dir, "folderscan_diag_index.tsv"); } }
        public string History { get { return Path.Combine(dir, "folderscan_diag_history.tsv"); } }

        static bool Same(string a, string b) { return string.Compare(a, b, StringComparison.CurrentCultureIgnoreCase) == 0; }

        public PrevDiag LoadPrevious(string target, IConsoleLog log) {
            PrevDiag p = new PrevDiag();
            if (!File.Exists(Index)) return null;
            try {
                foreach (string ln in File.ReadAllLines(Index, Encoding.UTF8)) {
                    string[] c = ln.Split('\t');
                    if (c.Length < 3 || !Same(c[1], target)) continue;
                    if (string.CompareOrdinal(c[0], p.Run) > 0 && File.Exists(c[2])) { p.Run = c[0]; p.JsonPath = c[2]; }
                }
                if (p.JsonPath.Length == 0) return null;
                object root = Json.Parse(File.ReadAllText(p.JsonPath, Encoding.UTF8));
                foreach (object o in Json.A(root, "findings")) {
                    PrevFinding f = new PrevFinding();
                    f.Id = Json.S(o, "id"); f.Key = Json.S(o, "key"); f.Action = Json.S(o, "action"); f.Category = Json.S(o, "category");
                    f.File = Json.S(o, "file"); f.Subject = Json.S(o, "subject"); f.SeenRuns = Json.I(o, "seenRuns"); f.Score = Json.I(o, "score");
                    p.Findings[f.Id] = f;
                }
                foreach (object o in Json.A(root, "detectors")) p.Detectors[Json.S(o, "name")] = new int[] { Json.I(o, "found"), Json.I(o, "resolved"), Json.I(o, "unresolved") };
                foreach (object o in Json.A(root, "notExamined")) p.Coverage[Json.S(o, "kind")] = Json.I(o, "count");
                return p;
            } catch (Exception ex) { log.Info("  [warn] previous diag read: " + ex.Message); return null; }
        }

        public void Append(string run, string target, string jsonPath, string historyLine, IConsoleLog log) {
            try {
                File.AppendAllText(Index, run + "\t" + target + "\t" + jsonPath + "\r\n", new UTF8Encoding(false));
                StringBuilder sb = new StringBuilder();
                if (!File.Exists(History)) sb.Append(HistoryHeader).Append("\r\n");
                sb.Append(historyLine).Append("\r\n");
                File.AppendAllText(History, sb.ToString(), new UTF8Encoding(false));
            } catch (Exception ex) { log.Info("  [warn] diag history write: " + ex.Message); }
        }

        // actionable count of the last runs of the target (oldest first), for the trend line
        public List<string> Trend(string target, int max) {
            List<string> l = new List<string>();
            if (!File.Exists(History)) return l;
            try {
                foreach (string ln in File.ReadAllLines(History, Encoding.UTF8)) {
                    string[] c = ln.Split('\t');
                    if (c.Length >= 4 && c[0] != "RunTime" && Same(c[2], target)) l.Add(c[3]);
                }
            } catch { }
            if (l.Count > max) l = l.GetRange(l.Count - max, max);
            return l;
        }
    }
}
