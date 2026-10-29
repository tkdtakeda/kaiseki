using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using FolderScan.Analysis;
using FolderScan.Core;
using FolderScan.Diag;
using FolderScan.Gaps;

namespace FolderScan.Map {
    // Data of the system map (map.html) : the structure a person needs to repair a system
    // made by someone else - entry points, dependencies, impact, settings, data,
    // resources outside the folder, open questions and clean-up candidates.
    public static class SystemMapBuilder {
        // edges that mean "src needs dst to work" (used for impact and the default graph)
        static readonly HashSet<string> Strong = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "IMPORT", "EXEC", "INCLUDE", "HTTP", "CONFIG", "SQL", "DBREF", "DBFILE", "REF", "PATTERN", "FILEMATCH" };
        static readonly HashSet<string> ConfigExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".json", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".toml", ".xml", ".config", ".properties", ".env" };
        static readonly Regex BackupName = new Regex(@"(\.bak|\.old|\.orig|\.tmp|~)$|[_\-. ](old|bak|backup|copy|org|orig)([_\-. ]|$)|\(\d+\)\.|\u30b3\u30d4\u30fc|(^|[_\-])(19|20)\d{6}([_\-]|\.)", RegexOptions.IgnoreCase);

        static bool IsStrong(string[] e) { return e[2].Length > 0 && Strong.Contains(e[0]) && (e[5] == "fact" || e[5] == "match"); }
        static int Int(string s) { int n; int.TryParse(s, out n); return n; }

        public static JsonObj Build(ScanContext c) {
            LinkState k = c.Link; DepState d = c.Dep;
            List<string[]> E = d.Edges.Items;
            int n = k.Fx.Count;
            // reverse graph over strong edges : who needs file x
            List<int>[] users = new List<int>[n + 1];
            for (int i = 0; i <= n; i++) users[i] = new List<int>();
            foreach (string[] e in E) if (IsStrong(e)) { int s = Int(e[1]), t = Int(e[2]); if (s != t && s > 0 && t > 0 && !users[t].Contains(s)) users[t].Add(s); }
            Dictionary<string, int> findCount = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            List<object> finds = new List<object>();
            if (c.Diag != null) {
                foreach (Finding f in c.Diag.Findings) {
                    if (f.Action == FindingBuilder.Benign) continue;
                    if (f.Action == FindingBuilder.Actionable) { int v; findCount.TryGetValue(f.File, out v); findCount[f.File] = v + 1; }
                    if (finds.Count < 500) finds.Add(new JsonObj().Add("id", f.Id).Add("a", f.Action).Add("sc", f.Score).Add("cls", f.Class).Add("cat", f.Category)
                        .Add("file", f.File).Add("loc", f.Loc).Add("sub", f.Subject).Add("why", string.Join("; ", f.Why.ToArray())).Add("chg", f.Change).Add("seen", f.SeenRuns));
                }
            }
            HashSet<string> explainedCleanup = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Gap g in c.Gaps) if (g.Explained == "superseded-by-sibling" || g.Explained == "template-of") explainedCleanup.Add(g.No + "|" + g.Explained + "|" + g.ExEv);

            List<object> files = new List<object>();
            foreach (FileEntry x in k.Fx) {
                string role; d.Role.TryGetValue(x.No, out role);
                string arch = ""; foreach (string[] r in c.Recon.ArchRows) if (r[0] == x.No.ToString()) { arch = r[3]; break; }
                int ia, oa; d.InAll.TryGetValue(x.No, out ia); d.OutAll.TryGetValue(x.No, out oa);
                int fa, fb; findCount.TryGetValue(x.Display, out fa); findCount.TryGetValue(x.Rel, out fb); int fc = fa + fb;
                files.Add(new JsonObj().Add("n", x.No).Add("p", x.Rel.TrimStart('\\', '/')).Add("src", x.Src).Add("x", x.Ext).Add("l", x.Lang).Add("k", x.Kind)
                    .Add("b", x.File.Length).Add("m", PathUtil.Time(x.File.LastWriteTime)).Add("r", arch).Add("role", role ?? "").Add("o", OriginRules.Of(x)).Add("dp", x.Depth)
                    .Add("e", (role ?? "").IndexOf("entry-candidate", StringComparison.Ordinal) >= 0).Add("in", ia).Add("out", oa)
                    .Add("imp", Impact(users, x.No)).Add("f", fc));
            }
            List<object> edges = new List<object>(), ext = new List<object>();
            foreach (string[] e in E) {
                if (e[2].Length > 0) edges.Add(new JsonObj().Add("s", Int(e[1])).Add("d", Int(e[2])).Add("t", e[0]).Add("v", e[5]).Add("x", e[3]).Add("c", e[4]).Add("o", e[6]));
            }
            foreach (string[] r in c.Recon.Unresolved) if (r[4].Length == 0) ext.Add(new JsonObj().Add("s", Int(r[2])).Add("t", r[1]).Add("val", r[6]).Add("cls", r[9]).Add("v", r[7]));
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Generic == null) continue;
                foreach (string[] g in sm.Generic) ext.Add(new JsonObj().Add("s", x.No).Add("t", "RESOURCE").Add("val", g[1]).Add("cls", g[0]).Add("v", "fact").Add("c", g[3]));
            }
            JsonObj root = new JsonObj();
            root.Add("meta", new JsonObj().Add("target", c.ScanRoot).Add("run", c.RunId).Add("tool", ScanContext.Version).Add("report", c.Report.Path)
                .Add("diag", c.HandOverPath).Add("files", n).Add("edges", E.Count).Add("actionable", c.Diag == null ? 0 : c.Diag.Actionable)
                .Add("omittedText", c.OmittedText.Count).Add("omittedDat", c.OmittedDat.Count));
            root.Add("files", files).Add("edges", edges).Add("ext", ext).Add("findings", finds);
            root.Add("configs", Configs(c)).Add("data", DataItems(c)).Add("cleanup", Cleanup(c, explainedCleanup));
            root.Add("notExamined", NotExamined(c));
            return root;
        }

        // number of files that need x directly or indirectly
        static int Impact(List<int>[] users, int x) {
            HashSet<int> seen = new HashSet<int>(); Queue<int> q = new Queue<int>(); q.Enqueue(x); seen.Add(x);
            while (q.Count > 0) { int v = q.Dequeue(); foreach (int u in users[v]) if (seen.Add(u)) q.Enqueue(u); }
            return seen.Count - 1;
        }

        static List<object> Configs(ScanContext c) {
            LinkState k = c.Link; List<object> l = new List<object>();
            foreach (FileEntry x in k.Fx) {
                if (!ConfigExt.Contains(x.Ext) || x.Kind != "text") continue;
                SemItem sm; k.Sem.TryGetValue(x.No, out sm);
                List<int> by = new List<int>(); List<string> how = new List<string>();
                foreach (string[] e in c.Dep.Edges.Items) {
                    if (e[2] != x.No.ToString() || (e[0] != "CONFIG" && e[0] != "REF" && e[0] != "PATTERN" && e[0] != "FILEMATCH")) continue;
                    int s = Int(e[1]); if (!by.Contains(s)) { by.Add(s); how.Add(e[0]); }
                }
                int keys = sm != null && sm.JK != null ? sm.JK.Count : 0;
                l.Add(new JsonObj().Add("n", x.No).Add("keys", keys).Add("keysRead", x.Ext == ".json").Add("by", by).Add("how", how));
            }
            return l;
        }

        static List<object> DataItems(ScanContext c) {
            LinkState k = c.Link; List<object> l = new List<object>();
            foreach (FileEntry x in k.Fx) {
                bool db = DbRules.Role(x).Length > 0;
                bool data = x.Lang.Length == 0 && !ConfigExt.Contains(x.Ext) && (x.Kind == "binary" || x.Ext == ".csv" || x.Ext == ".tsv" || x.Ext == ".dat" || x.Ext == ".txt");
                if (!db && !data) continue;
                List<int> by = new List<int>();
                foreach (string[] e in c.Dep.Edges.Items) if (e[2] == x.No.ToString() && IsStrong(e)) { int s = Int(e[1]); if (!by.Contains(s)) by.Add(s); }
                l.Add(new JsonObj().Add("n", x.No).Add("kind", db ? DbRules.Role(x) : "data-file").Add("by", by));
            }
            foreach (string[] r in c.Recon.FileClass) {
                // SrcNo, SrcPath, Signal, Class, Evidence, Origin, Loc
                string kind = r[3] == "output-file-candidate" ? "output (written)" : r[3] == "external-file" ? "input (not in folder)" : r[3];
                l.Add(new JsonObj().Add("name", r[2]).Add("kind", kind).Add("by", new int[] { Int(r[0]) }).Add("loc", r[6]));
            }
            return l;
        }

        static List<object> Cleanup(ScanContext c, HashSet<string> explained) {
            LinkState k = c.Link; DepState d = c.Dep; List<object> l = new List<object>();
            HashSet<string> noEdge = new HashSet<string>(d.Iso2);
            foreach (FileEntry x in k.Fx) {
                List<string> why = new List<string>();
                string org = OriginRules.Of(x);
                if (noEdge.Contains(x.No.ToString()) && org != "documentation") why.Add("no relation to any file");
                if (BackupName.IsMatch(x.File.Name)) why.Add("backup / copy / dated name");
                foreach (string s in explained) if (s.StartsWith(x.No + "|")) why.Add(s.Substring(s.IndexOf('|') + 1));
                if (why.Count > 0) l.Add(new JsonObj().Add("n", x.No).Add("why", why));
            }
            foreach (List<FileEntry> g in k.SameContent)
                for (int i = 1; i < g.Count; i++) l.Add(new JsonObj().Add("n", g[i].No).Add("why", new string[] { "same content as " + g[0].Rel.TrimStart('\\', '/') }));
            return l;
        }

        static List<object> NotExamined(ScanContext c) {
            List<object> l = new List<object>();
            if (c.Diag == null) return l;
            foreach (CoverageItem ci in c.Diag.Coverage) l.Add(new JsonObj().Add("kind", ci.Kind).Add("count", ci.Count).Add("detail", ci.Detail).Add("next", ci.Next));
            foreach (DetectorResult r in c.Diag.Detectors) foreach (string s in r.Suspicious) l.Add(new JsonObj().Add("kind", "detector " + r.Name).Add("count", 0).Add("detail", s).Add("next", string.Join(" ", r.Next.ToArray())));
            return l;
        }
    }
}
