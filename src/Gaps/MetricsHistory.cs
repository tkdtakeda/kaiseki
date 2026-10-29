using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Text;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Gaps {
    // Metrics of a scan and folderscan_history.tsv (change from the previous scan of the same target).
    public sealed class MetricsHistory {
        public readonly OrderedDictionary Met = new OrderedDictionary();   // case-sensitive keys, insertion order (as v5.18)
        public string PrevRun = "";
        public readonly List<string[]> Delta = new List<string[]>();
        readonly Hashtable prev = PsHash.New();

        void M(string key, object v) { Met[key] = Convert.ToString(v, CultureInfo.InvariantCulture); }

        // Group-Object <key> | Sort-Object Name : name -> count, sorted by name
        static void Groups<T>(IEnumerable<T> items, Func<T, string> key, Action<string, int> add) {
            Dictionary<string, int> d = new Dictionary<string, int>(StringComparer.CurrentCultureIgnoreCase);
            List<string> order = new List<string>();
            foreach (T it in items) { string kk = key(it) ?? ""; int v; if (!d.TryGetValue(kk, out v)) order.Add(kk); d[kk] = v + 1; }
            FolderScan.Sections.SymbolUseSection.StableSort(order);
            foreach (string kk in order) add(kk, d[kk]);
        }

        public void Collect(ScanContext c) {
            LinkState k = c.Link; DepState d = c.Dep; ReconState rs = c.Recon;
            List<string[]> edges = d.Edges.Items;
            M("files.total", k.Fx.Count);
            Groups(k.Fx, delegate (FileEntry x) { return x.Kind; }, delegate (string n, int v) { M("files.kind." + n, v); });
            Groups(k.Fx, delegate (FileEntry x) { return OriginRules.Of(x); }, delegate (string n, int v) { M("files.origin." + n, v); });
            M("edges.total", edges.Count);
            Groups(edges, delegate (string[] e) { return e[0]; }, delegate (string n, int v) { M("edges.type." + n, v); });
            Groups(edges, delegate (string[] e) { return e[5]; }, delegate (string n, int v) { M("edges.evidence." + n, v); });
            foreach (string s in rs.StatusCount.SortedKeys()) M("resolved." + s, rs.StatusCount[s]);
            M("conflicts.total", rs.Conflicts.Count);
            Groups(rs.Conflicts, delegate (string[] e) { return e[0]; }, delegate (string n, int v) { M("conflicts." + n, v); });
            foreach (string s in rs.FileClassCount.SortedKeys()) M("filesignal." + s, rs.FileClassCount[s]);
            foreach (string s in rs.ExtClassCount.SortedKeys()) M("external." + s, rs.ExtClassCount[s]);
            M("http.calls", d.ClientRows.Count);
            Groups(d.ClientRows, delegate (string[] r) { return r[5] == "(no route found)" ? "noroute" : r[15]; }, delegate (string n, int v) { M("http.result." + n, v); });
            Groups(d.ClientRows, delegate (string[] r) { return r[11]; }, delegate (string n, int v) { M("http.method." + n, v); });
            List<Wrap> hw = new List<Wrap>(); foreach (Wrap w in k.WrapAll) if (w.Http) hw.Add(w);
            M("wrappers.http", hw.Count);
            Groups(hw, delegate (Wrap w) { return w.Depth.ToString(); }, delegate (string n, int v) { M("wrappers.depth." + n, v); });
            int un = 0; foreach (string[] r in rs.ArchRows) if (r[3] == "unclassified") un++;
            M("roles.unclassified", un);
            int tmo = 0; foreach (SemItem sm in k.Sem.Values) if (!string.IsNullOrEmpty(sm.Tmo)) tmo++;
            M("regex.timeout.files", tmo);
            M("elapsed.sec", Math.Round(c.Watch.Elapsed.TotalSeconds, 1));
        }

        // Reads the previous run of the target, computes the delta and appends this run.
        public void History(ScanContext c, string histPath, string runId, IConsoleLog log) {
            string root = c.ScanRoot;
            if (c.Settings.History == 1 && File.Exists(histPath)) {
                try {
                    string[] hl = File.ReadAllLines(histPath, Encoding.UTF8);
                    foreach (string ln in hl) { string[] cc = ln.Split('\t'); if (cc.Length >= 5 && Eq(cc[2], root) && Gt(cc[0], PrevRun)) PrevRun = cc[0]; }
                    if (PrevRun.Length > 0) foreach (string ln in hl) { string[] cc = ln.Split('\t'); if (cc.Length >= 5 && Eq(cc[2], root) && Eq(cc[0], PrevRun)) prev[cc[3]] = cc[4]; }
                } catch (Exception ex) { log.Info("  [warn] history read: " + ex.Message); }
            }
            List<string> allK = new List<string>();
            foreach (object o in Met.Keys) allK.Add((string)o);
            List<string> extra = new List<string>();
            foreach (object o in prev.Keys) if (!Met.Contains(o)) extra.Add((string)o);
            FolderScan.Sections.SymbolUseSection.StableSort(extra);
            allK.AddRange(extra);
            foreach (string k0 in allK) {
                if (k0 == "elapsed.sec") continue;
                string nv = Met.Contains(k0) ? (string)Met[k0] : "0";
                string pv = prev.ContainsKey(k0) ? (string)prev[k0] : "0";
                if (Eq(nv, pv)) continue;
                string dd = "-";
                double a, b;
                if (double.TryParse(nv, NumberStyles.Float, CultureInfo.InvariantCulture, out a) && double.TryParse(pv, NumberStyles.Float, CultureInfo.InvariantCulture, out b)) dd = (a - b).ToString();
                Delta.Add(new string[] { k0, pv, nv, dd });
            }
            if (c.Settings.History == 1) {
                try {
                    StringBuilder sb = new StringBuilder();
                    if (!File.Exists(histPath)) sb.Append("RunTime\tVersion\tTarget\tMetric\tValue\r\n");
                    foreach (object o in Met.Keys) sb.Append(runId + "\t" + ScanContext.Version + "\t" + root + "\t" + o + "\t" + Met[o] + "\r\n");
                    File.AppendAllText(histPath, sb.ToString(), new UTF8Encoding(false));
                } catch (Exception ex) { log.Info("  [warn] history write: " + ex.Message); }
            }
        }

        static bool Eq(string a, string b) { return string.Compare(a, b, StringComparison.CurrentCultureIgnoreCase) == 0; }
        static bool Gt(string a, string b) { return string.Compare(a, b, StringComparison.CurrentCultureIgnoreCase) > 0; }
    }
}
