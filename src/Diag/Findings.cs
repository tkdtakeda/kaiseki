using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using FolderScan.Analysis;
using FolderScan.Core;
using FolderScan.Gaps;
namespace FolderScan.Diag {
    public sealed class Finding {
        public string Id, Key, Source, Category, Class, Action, File, Loc, Subject, Detail, Origin, Status = "";
        public string TrackedBy = "";
        public int Score, Affects = 1, SeenRuns = 1;
        public string Change = "new";
        public readonly List<string> Why = new List<string>();
        public readonly List<string> Evidence = new List<string>();
        public string Group = "";
    }
    public static class FindingBuilder {
        public const string Actionable = "actionable", Explained = "explained", Benign = "benign", Tracked = "tracked";
        static readonly Dictionary<string, int> ClassBase = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) {
            { "external-file", 60 }, { "local-module-missing", 60 }, { "missing-asset-or-served-elsewhere", 55 }, { "third-party-or-local-undeclared", 45 },
            { "external-table", 45 }, { "third-party-no-manifest", 40 }, { "external-data-reference", 40 }, { "external-module", 35 }, { "external-other", 35 },
            { "third-party-known-undeclared", 20 }, { "external-program", 15 }, { "configured-data-path", 15 }, { "output-file-candidate", 10 }, { "runtime-work-file", 10 },
            { "runtime-file-candidate", 10 }, { "file-pattern", 10 }, { "ui-example-or-reference", 10 }, { "system-object", 0 },
            { "stdlib", 0 }, { "third-party-declared", 0 }, { "platform-or-library", 0 }, { "lexical-only", 0 }, { "documentation-mention", 0 },
            { "text-mention", 0 }, { "binary-embedded-name", 0 }, { "sql-alias-like", 0 }, { "archive-internal-part", 0 } };
        static readonly Dictionary<string, int> InternalBase = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) {
            { "HTTP", 50 }, { "FILEMATCH", 45 }, { "CONFIG", 35 }, { "PATTERN", 10 }, { "SYM", 5 }, { "KEY", 5 }, { "STEM", 5 } };
        static readonly Dictionary<string, int> GapBase = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) {
            { "scan-access-error", 70 }, { "scan-empty", 70 }, { "file-read-unexplained", 60 }, { "http-no-route", 55 }, { "http-ambiguous", 50 },
            { "import-unresolved", 45 }, { "filename-ambiguous", 40 }, { "regex-timeout", 35 }, { "format-not-parsed", 30 }, { "isolated-file", 25 }, { "role-unclassified", 20 } };
        static readonly Dictionary<string, int> OriginPart = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) {
            { "source-code", 20 }, { "text-data", 10 }, { "other", 5 }, { "test-code", 0 }, { "documentation", -10 }, { "binary-string", -10 }, { "generated-vendor", -10 } };
        static readonly HashSet<string> SqlSystemObjects = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema", "sqlite_sequence", "sqlite_stat1", "sqlite_stat2", "sqlite_stat3", "sqlite_stat4"
        };
        public static string ScoringText() {
            return "score = base(class / gap kind) + origin(source-code +20, text-data +10, other +5, test 0, doc/binary/vendor -10)"
                + " + affects(+5 per extra file with the same problem, max +20) + persistence(+5 per earlier run, max +15); weakly explained gap = half."
                + " action: actionable (base >= 30, or open gap) / explained (base 10-29) / benign (base 0) / tracked (same problem followed by a gap).";
        }
        static string Hash(string s) { using (SHA1 h = SHA1.Create()) { byte[] b = h.ComputeHash(Encoding.UTF8.GetBytes(s)); StringBuilder sb = new StringBuilder(); for (int i = 0; i < 6; i++) sb.Append(b[i].ToString("x2")); return sb.ToString(); } }
        static int Base(Dictionary<string, int> d, string k, int def) { int v; return k != null && d.TryGetValue(k, out v) ? v : def; }
        public static List<Finding> Build(ScanContext c, Dictionary<string, PrevFinding> prev) {
            LinkState k = c.Link; List<Finding> raw = new List<Finding>(); Dictionary<string, string> gapByProblem = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Gap g in c.Gaps) raw.Add(FromGap(c, g, gapByProblem));
            foreach (string[] r in c.Recon.Unresolved) raw.Add(FromUnresolved(k, r, gapByProblem));
            List<Finding> all = Deduplicate(raw);
            Dictionary<string, HashSet<string>> groups = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (Finding f in all) { HashSet<string> h; if (!groups.TryGetValue(f.Group, out h)) { h = new HashSet<string>(StringComparer.OrdinalIgnoreCase); groups[f.Group] = h; } h.Add(f.File); }
            foreach (Finding f in all) {
                f.Affects = groups[f.Group].Count; PrevFinding p;
                if (prev != null && prev.TryGetValue(f.Id, out p)) { f.SeenRuns = p.SeenRuns + 1; f.Change = p.Action == Actionable || p.Action == Tracked ? "persisting" : "reopened"; }
                if (f.Source == "gap") { Gap g = null; foreach (Gap x in c.Gaps) if ("G|" + x.Key == f.Key) { g = x; break; } if (g != null && g.Seen > f.SeenRuns) f.SeenRuns = g.Seen; }
                Score(f);
            }
            all.Sort(delegate (Finding a, Finding b) { int r = Rank(a.Action).CompareTo(Rank(b.Action)); if (r != 0) return r; r = b.Score.CompareTo(a.Score); if (r != 0) return r; return string.CompareOrdinal(a.Key, b.Key); });
            return all;
        }
        static List<Finding> Deduplicate(List<Finding> raw) {
            Dictionary<string, Finding> map = new Dictionary<string, Finding>(StringComparer.Ordinal);
            List<Finding> result = new List<Finding>();
            foreach (Finding f in raw) {
                Finding keep;
                if (!map.TryGetValue(f.Id, out keep)) { map[f.Id] = f; result.Add(f); continue; }
                AddUnique(keep.Evidence, f.Evidence); AddUnique(keep.Why, f.Why);
                if (string.IsNullOrEmpty(keep.Detail) && !string.IsNullOrEmpty(f.Detail)) keep.Detail = f.Detail;
                if (string.IsNullOrEmpty(keep.Loc) && !string.IsNullOrEmpty(f.Loc)) keep.Loc = f.Loc;
                if (Rank(f.Action) < Rank(keep.Action)) keep.Action = f.Action;
            }
            return result;
        }
        static void AddUnique(List<string> dst, List<string> src) { foreach (string s in src) if (!string.IsNullOrEmpty(s) && !dst.Contains(s)) dst.Add(s); }
        static int Rank(string action) { return action == Actionable ? 0 : action == Explained ? 1 : action == Tracked ? 2 : 3; }
        static Finding FromGap(ScanContext c, Gap g, Dictionary<string, string> gapByProblem) {
            Finding f = new Finding(); f.Key = "G|" + g.Key; f.Id = "g" + Hash(f.Key); f.Source = "gap"; f.Category = g.Kind; f.Class = g.Kind;
            f.File = g.Path; f.Loc = g.Loc ?? ""; f.Subject = g.Subject; f.Detail = g.Note; if (!string.IsNullOrEmpty(g.Note)) f.Evidence.Add(g.Note);
            FileEntry q = c.Link.ByNo(g.No ?? ""); f.Origin = q == null ? "-" : OriginRules.Of(q);
            f.Status = g.Explained.Length == 0 ? "open" : (g.Conf == "weak" ? "explained-weak:" : "explained:") + g.Explained;
            f.Action = g.Explained.Length == 0 || g.Conf == "weak" ? Actionable : Explained; f.Group = g.Kind + "|" + g.Subject; f.Why.Add("gap " + g.Kind + " +" + Base(GapBase, g.Kind, 30));
            if (g.Kind == "file-read-unexplained") gapByProblem["file|" + g.No + "|" + g.Subject] = f.Id; if (g.Kind == "import-unresolved") gapByProblem["imp|" + g.Subject] = f.Id; return f;
        }
        static Finding FromUnresolved(LinkState k, string[] r, Dictionary<string, string> gapByProblem) {
            Finding f = new Finding(); bool internalEdge = r[4].Length > 0; f.Source = "unresolved"; f.Category = r[1]; f.Class = internalEdge ? r[0] : r[9];
            f.File = r[3]; f.Subject = internalEdge ? "-> " + r[5] : r[6]; f.Detail = r[6]; f.Origin = r[8]; f.Status = r[0]; if (r.Length > 7 && !string.IsNullOrEmpty(r[7])) f.Evidence.Add(r[7]);
            if (!internalEdge && r[1] == "SQL" && SqlSystemObjects.Contains(CleanSqlObject(r[6]))) { f.Class = "system-object"; f.Status = "platform/system object"; }
            f.Key = "U|" + r[0] + "|" + r[1] + "|" + r[3] + "|" + (internalEdge ? r[5] : r[6]); f.Id = "u" + Hash(f.Key); f.Loc = ""; int b;
            if (internalEdge) { b = r[0] == "internal-weak" ? 0 : Base(InternalBase, r[1], 10); f.Why.Add(r[0] + " " + r[1] + " +" + b); }
            else { b = Base(ClassBase, f.Class, 30); f.Why.Add("class " + f.Class + " +" + b); }
            f.Action = b >= 30 ? Actionable : b >= 10 ? Explained : Benign; f.Group = f.Class + "|" + (internalEdge ? r[1] + "|" + r[5] : Leaf(r[1], r[6]));
            string gid = null; if (r[1] == "EXTFILE" && r[9] == "external-file") { string no = r[2]; gapByProblem.TryGetValue("file|" + no + "|" + LinkTool.Clean(r[6]), out gid); }
            if (r[1] == "IMPORT") { string[] pp = r[6].Split(' '); string md = pp.Length >= 2 ? pp[1] : ""; string root = md.TrimStart('.').Split('.')[0].Split('/')[0]; if (!gapByProblem.TryGetValue("imp|" + root, out gid)) gapByProblem.TryGetValue("imp|" + md, out gid); }
            if (gid != null && f.Action == Actionable) { f.Action = Tracked; f.TrackedBy = gid; f.Why.Add("tracked by gap " + gid); } return f;
        }
        // SQL edge details look like "table <name>" : drop the object-kind word before taking the name.
        static readonly string[] SqlKindWords = { "table ", "view ", "index ", "trigger " };
        static string CleanSqlObject(string s) { string t = LinkTool.Clean(s ?? "").Trim(); foreach (string w in SqlKindWords) if (t.StartsWith(w, StringComparison.OrdinalIgnoreCase)) { t = t.Substring(w.Length).TrimStart(); break; } int p = t.IndexOf(' '); if (p > 0) t = t.Substring(0, p); return t.Trim('`', '"', '\'', '[', ']').ToLowerInvariant(); }
        static string Leaf(string type, string detail) { if (type == "IMPORT") { string[] pp = detail.Split(' '); string md = pp.Length >= 2 ? pp[1] : ""; return md.TrimStart('.').Split('.')[0].Split('/')[0].ToLowerInvariant(); } int i = detail.IndexOf(" [", StringComparison.Ordinal); string tok = i > 0 ? detail.Substring(0, i) : detail; return SemTool.BaseName(tok).ToLowerInvariant(); }
        static void Score(Finding f) { int s = 0; foreach (string w in f.Why) { int p = w.LastIndexOf(" +", StringComparison.Ordinal); int v; if (p >= 0 && int.TryParse(w.Substring(p + 2), out v)) s += v; } if (f.Action == Benign) { f.Score = s; return; } int o = Base(OriginPart, f.Origin, 0); if (o != 0) { s += o; f.Why.Add("origin " + f.Origin + " " + (o > 0 ? "+" : "") + o); } if (f.Affects > 1) { int a = Math.Min(20, 5 * (f.Affects - 1)); s += a; f.Why.Add("affects " + f.Affects + " files +" + a); } if (f.SeenRuns > 1) { int p = Math.Min(15, 5 * (f.SeenRuns - 1)); s += p; f.Why.Add("seen " + f.SeenRuns + " runs +" + p); } if (f.Status.StartsWith("explained-weak")) { s /= 2; f.Why.Add("weakly explained x0.5"); } f.Score = Math.Max(0, s); }
    }
    public sealed class PrevFinding { public string Id, Key, Action, Category, File, Subject; public int SeenRuns, Score; }
}
