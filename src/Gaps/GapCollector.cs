using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Gaps {
    // Collects the gaps G1-G9 (gap collection of v5.18 [19]).
    public sealed class GapCollector {
        static readonly Regex StaticExt = new Regex(@"\.[A-Za-z0-9]{1,5}$", RegexOptions.IgnoreCase);
        static readonly Regex Token = new Regex(@"token=(\S+)");
        static readonly HashSet<string> KnownText = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".txt", ".csv", ".tsv", ".json", ".md", ".log", ".ini", ".cfg", ".xml", ".yml", ".yaml", ".toml", ".rst", ".html", ".htm", ".css", ".svg" };

        readonly ScanContext c;
        readonly string runId;
        public readonly List<Gap> Gaps = new List<Gap>();
        public readonly HashSet<string> Seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);   // $gapSeen (case-insensitive @{})
        public int RouteImplied;

        public GapCollector(ScanContext c, string runId) { this.c = c; this.runId = runId; }

        void Add(string kind, string no, string loc, string subject, string probe, List<string> extra, string note) {
            string pth = "-";
            if (!string.IsNullOrEmpty(no)) { FileEntry q = c.Link.ByNo(no); pth = q == null ? "" : q.Rel; }
            string sub = LinkTool.Clean(subject);
            string key = kind + "|" + pth + "|" + sub;
            if (!Seen.Add(key)) return;
            Gap g = new Gap();
            g.Kind = kind; g.Key = key; g.No = string.IsNullOrEmpty(no) ? null : no; g.Path = pth; g.Loc = loc; g.Subject = sub;
            g.Probe = probe ?? ""; g.Extra = extra; g.Note = note ?? ""; g.First = runId;
            Gaps.Add(g);
        }
        void Add(string kind, string no, string loc, string subject, string probe, List<string> extra) { Add(kind, no, loc, subject, probe, extra, ""); }

        sealed class ImpGroup { public string Root, Mod, Cls, No, Loc; public readonly List<string> Files = new List<string>(); }

        public void Collect() {
            LinkState k = c.Link; DepState d = c.Dep; ReconState rs = c.Recon;
            // G1 scan coverage
            if (c.AllFiles.Count == 0) Add("scan-empty", null, "-", "no file found under the target", "scan", null);
            foreach (ScanError er in c.ScanErrors) Add("scan-access-error", null, "-", string.IsNullOrEmpty(er.Target) ? "?" : er.Target, "scan", null, LinkTool.Clean(er.Message));
            // G2 file read not explained
            foreach (string[] r in rs.FileClass) if (r[3] == "external-file") Add("file-read-unexplained", r[0], r[6], r[2], "ctxdef", null);
            // G3 http
            foreach (string[] r in d.ClientRows) {
                if (r[15] == "candidate") Add("http-ambiguous", r[0], r[4], r[9] + " " + r[2], "httpvar", null, r[5]);
                else if (r[5] == "(no route found)" && OriginRules.Of(k.ByNo(r[0])) == "source-code" && !StaticExt.IsMatch(r[2])) Add("http-no-route", r[0], r[4], r[9] + " " + r[2], "route", null);
                else if (r[11] == "unknown" && r[5] != "(no route found)") RouteImplied++;
            }
            // G4 imports (one gap per module)
            Dictionary<string, ImpGroup> impG = new Dictionary<string, ImpGroup>(StringComparer.CurrentCultureIgnoreCase);
            List<ImpGroup> impOrder = new List<ImpGroup>();
            foreach (string[] e in d.Edges.Items) {
                if (e[0] != "IMPORT" || e[2].Length > 0 || e[6] != "source-code") continue;
                string xc = rs.Ext.Classify(e);
                if (xc != "third-party-or-local-undeclared" && xc != "local-module-missing" && xc != "third-party-no-manifest" && xc != "third-party-known-undeclared") continue;
                string[] pp = e[3].Split(' '); string md = pp.Length >= 2 ? pp[1] : "";
                string root = md.TrimStart('.').Split('.')[0].Split('/')[0];
                string gk = xc == "local-module-missing" ? "rel|" + e[1] + "|" + md : root;
                ImpGroup ig;
                if (!impG.TryGetValue(gk, out ig)) { ig = new ImpGroup(); ig.Root = root; ig.Mod = md; ig.Cls = xc; ig.No = e[1]; ig.Loc = e[4]; impG[gk] = ig; impOrder.Add(ig); }
                string fp = k.ByNo(e[1]).Rel;
                if (!ig.Files.Contains(fp)) ig.Files.Add(fp);
            }
            foreach (ImpGroup ig in impOrder) {
                string nt = ig.Cls + "; files=" + ig.Files.Count + " (" + string.Join(" ; ", ig.Files.GetRange(0, Math.Min(5, ig.Files.Count)).ToArray()) + ")";
                if (ig.Cls == "third-party-known-undeclared") { string pk; ExternalClassifier.PyAlias.TryGetValue(ig.Root.ToLowerInvariant(), out pk); nt = nt + "; package=" + pk; }
                Add("import-unresolved", ig.No, ig.Loc, ig.Cls == "local-module-missing" ? ig.Mod : ig.Root, "mod:" + ig.Root, null, nt);
            }
            // G5 file formats that no parser understood
            Dictionary<string, List<FileEntry>> fmt = new Dictionary<string, List<FileEntry>>(StringComparer.CurrentCultureIgnoreCase);
            List<string> fmtOrder = new List<string>();
            foreach (FileEntry x in k.Fx) {
                if (x.Lang.Length > 0 || (x.Kind != "text" && x.Kind != "binary")) continue;
                string org = OriginRules.Of(x);
                if (org == "documentation" || org == "generated-vendor") continue;
                string key = (x.Ext.Length == 0 ? "(none)" : x.Ext) + " " + x.Kind;
                List<FileEntry> l;
                if (!fmt.TryGetValue(key, out l)) { l = new List<FileEntry>(); fmt[key] = l; fmtOrder.Add(key); }
                l.Add(x);
            }
            foreach (string key in fmtOrder) {
                List<FileEntry> grp = fmt[key]; FileEntry f0 = grp[0];
                if (f0.Kind == "text" && KnownText.Contains(f0.Ext)) continue;
                List<string> nos = new List<string>();
                for (int i = 0; i < grp.Count && i < 2; i++) nos.Add(grp[i].No.ToString());
                Add("format-not-parsed", f0.No.ToString(), "-", "ext " + key, "head", nos, "files=" + grp.Count);
            }
            // G6 production files with no fact/match relation
            foreach (string n in d.Iso1) {
                FileEntry q = k.ByNo(n);
                string org = OriginRules.Of(q);
                if (org != "source-code" && org != "text-data" && org != "binary-string" && org != "other") continue;
                Add("isolated-file", n, "-", q.File.Name, "mention:" + Path.GetFileNameWithoutExtension(q.File.Name), null);
            }
            // G7 role not decided
            foreach (string[] r in rs.ArchRows) if (r[3] == "unclassified") Add("role-unclassified", r[0], "-", k.ByNo(r[0]).File.Name, "headmention", new List<string>(new string[] { r[0] }));
            // G8 file name that fits several files
            foreach (string[] e in d.Edges.Items) {
                if (e[0] != "FILEMATCH" || e[5] != "candidate" || e[6] != "source-code") continue;
                Match tm = Token.Match(e[3]); if (!tm.Success) continue;
                Add("filename-ambiguous", e[1], e[4], tm.Groups[1].Value, "ctx", null);
            }
            // G9 regex timeouts ($sem.Values order)
            foreach (SemItem sm in ExternalClassifier.SemInPsOrder(k)) if (!string.IsNullOrEmpty(sm.Tmo)) Add("regex-timeout", sm.No.ToString(), "-", "some lines not analyzed", "", null, sm.Tmo);
        }
    }
}
