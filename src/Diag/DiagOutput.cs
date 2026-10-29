using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using FolderScan.Core;

namespace FolderScan.Diag {
    // Everything the self diagnosis found in one scan.
    public sealed class DiagResult {
        public List<Finding> Findings;
        public List<DetectorResult> Detectors;
        public List<CoverageItem> Coverage;
        public PrevDiag Prev;
        public readonly List<Finding> New = new List<Finding>();
        public readonly List<PrevFinding> Resolved = new List<PrevFinding>();   // gone, or no longer actionable
        public int Persisting;
        public int Actionable, Tracked, Explained, Benign, Suspicious;
        public readonly List<string> Next = new List<string>();

        static bool Open(string action) { return action == FindingBuilder.Actionable || action == FindingBuilder.Tracked; }

        public void Compare() {
            Dictionary<string, Finding> now = new Dictionary<string, Finding>(StringComparer.Ordinal);
            foreach (Finding f in Findings) {
                now[f.Id] = f;
                if (f.Action == FindingBuilder.Actionable) Actionable++; else if (f.Action == FindingBuilder.Tracked) Tracked++;
                else if (f.Action == FindingBuilder.Explained) Explained++; else Benign++;
                if (f.Action == FindingBuilder.Actionable) { if (f.Change == "persisting") Persisting++; else New.Add(f); }
            }
            if (Prev != null) foreach (PrevFinding p in Prev.Findings.Values) {
                if (p.Action != FindingBuilder.Actionable) continue;   // tracked ones are counted on their gap
                Finding f;
                if (!now.TryGetValue(p.Id, out f) || !Open(f.Action)) Resolved.Add(p);
            }
            foreach (DetectorResult d in Detectors) { if (d.Suspicious.Count > 0) Suspicious++; Next.AddRange(d.Next); }
            foreach (CoverageItem c in Coverage) Next.Add(c.Kind + " (" + c.Count + ") : " + c.Next);
        }
    }

    public static class DiagOutput {
        public static JsonObj ToJson(ScanContext c, DiagResult r, int top) {
            JsonObj root = new JsonObj();
            root.Add("schema", "folderscan-diag/1").Add("tool", ScanContext.Version).Add("target", c.ScanRoot).Add("run", c.RunId).Add("report", c.Report.Path).Add("gaps", c.GapsPath);
            root.Add("previous", r.Prev == null ? null : (object)new JsonObj().Add("run", r.Prev.Run).Add("json", r.Prev.JsonPath));
            List<string> topIds = new List<string>();
            foreach (Finding f in r.Findings) { if (f.Action != FindingBuilder.Actionable || topIds.Count >= top) continue; topIds.Add(f.Id); }
            root.Add("summary", new JsonObj().Add("actionable", r.Actionable).Add("tracked", r.Tracked).Add("explained", r.Explained).Add("benign", r.Benign)
                .Add("new", r.New.Count).Add("resolved", r.Resolved.Count).Add("persisting", r.Persisting)
                .Add("suspiciousDetectors", r.Suspicious).Add("notExamined", r.Coverage.Count).Add("top", topIds));
            root.Add("aiNote", AiNote(c));
            root.Add("omitted", Omitted(c));
            List<object> res = new List<object>();
            foreach (PrevFinding p in r.Resolved) res.Add(new JsonObj().Add("id", p.Id).Add("category", p.Category).Add("file", p.File).Add("subject", p.Subject).Add("lastScore", p.Score));
            List<string> news = new List<string>(); foreach (Finding f in r.New) news.Add(f.Id);
            root.Add("changes", new JsonObj().Add("new", news).Add("resolved", res));
            List<object> fs = new List<object>();
            foreach (Finding f in r.Findings) {
                JsonObj o = new JsonObj().Add("id", f.Id).Add("action", f.Action).Add("score", f.Score).Add("source", f.Source).Add("category", f.Category).Add("class", f.Class)
                    .Add("file", f.File).Add("loc", f.Loc).Add("subject", f.Subject).Add("detail", f.Detail).Add("origin", f.Origin).Add("status", f.Status)
                    .Add("affects", f.Affects).Add("seenRuns", f.SeenRuns).Add("change", f.Change).Add("why", f.Why).Add("trackedBy", f.TrackedBy).Add("key", f.Key);
                fs.Add(o);
            }
            List<object> ds = new List<object>();
            foreach (DetectorResult d in r.Detectors) {
                JsonObj o = new JsonObj().Add("name", d.Name).Add("section", d.Section).Add("found", d.Found).Add("resolved", d.Resolved).Add("unresolved", d.Unresolved)
                    .Add("unresolvedRate", d.UnresolvedRate).Add("empty", d.Empty).Add("suspicious", d.Suspicious).Add("next", d.Next);
                int[] pv;
                if (r.Prev != null && r.Prev.Detectors.TryGetValue(d.Name, out pv)) o.Add("delta", new JsonObj().Add("found", d.Found - pv[0]).Add("resolved", d.Resolved - pv[1]).Add("unresolved", d.Unresolved - pv[2]));
                ds.Add(o);
            }
            List<object> cv = new List<object>();
            foreach (CoverageItem ci in r.Coverage) {
                int pc = -1; if (r.Prev != null && !r.Prev.Coverage.TryGetValue(ci.Kind, out pc)) pc = 0;
                JsonObj o = new JsonObj().Add("kind", ci.Kind).Add("count", ci.Count).Add("detail", ci.Detail).Add("next", ci.Next);
                if (pc >= 0) o.Add("delta", ci.Count - pc);
                cv.Add(o);
            }
            root.Add("detectors", ds).Add("notExamined", cv).Add("next", r.Next).Add("scoring", FindingBuilder.ScoringText()).Add("findings", fs);
            return root;
        }

        // Guidance for an AI reading this file : what is left out and how to ask for it.
        static string AiNote(ScanContext c) {
            return "This diagnosis is a summary. scan.txt in the same folder holds every fact, but raw content is left out to keep it small: "
                + (c.Settings.DumpText == 1 ? "" : "the full text of files ([10], DUMPTEXT=0) ")
                + (c.Settings.DumpDat == 1 ? "" : "and the full dump of .dat files ([8], DUMPDAT=0) ")
                + "(see 'omitted'). Line numbers, symbols, imports, references and all analysis results are complete. "
                + "If you need the content of a file to decide something, ask the user to add its path or a wildcard to DUMPFILES in settings.ini "
                + "(e.g. DUMPFILES=app\\server.py;*.ini), rescan, and send scan.txt sections [10] / [8] (or the file itself). "
                + "Ask for DUMPTEXT=1 / DUMPDAT=1 only when every file is needed. Ask for scan.txt when you need facts not in this summary.";
        }

        static JsonObj Omitted(ScanContext c) {
            Settings s = c.Settings;
            JsonObj o = new JsonObj();
            o.Add("text", new JsonObj().Add("section", "[10]").Add("setting", "DUMPTEXT=" + s.DumpText).Add("files", c.OmittedText.Count)
                .Add("examples", c.OmittedText.GetRange(0, Math.Min(20, c.OmittedText.Count)))
                .Add("howToGet", "add paths or wildcards to DUMPFILES (or DUMPTEXT=1 for all) in settings.ini and rescan"));
            o.Add("dat", new JsonObj().Add("section", "[8]").Add("setting", "DUMPDAT=" + s.DumpDat).Add("files", c.OmittedDat.Count)
                .Add("examples", c.OmittedDat.GetRange(0, Math.Min(20, c.OmittedDat.Count)))
                .Add("howToGet", "add paths or wildcards to DUMPFILES (or DUMPDAT=1 for all) in settings.ini and rescan"));
            o.Add("dumpFiles", s.DumpFiles);
            return o;
        }

        static string Short(string s, int n) { s = (s ?? "").Replace('\t', ' '); return s.Length > n ? s.Substring(0, n) + ".." : s; }

        // Human summary : the same text goes to the console (top items) and to diag_*.txt (all items).
        public static List<string> Text(ScanContext c, DiagResult r, List<string> trend, int top, bool full) {
            List<string> o = new List<string>();
            o.Add("==== SELF DIAGNOSIS : what this scan could not establish (folderscan " + ScanContext.Version + ") ====");
            o.Add(" findings : actionable " + r.Actionable + " (new " + r.New.Count + " / persisting " + r.Persisting + ")   resolved since previous " + r.Resolved.Count
                + "   tracked " + r.Tracked + " / explained " + r.Explained + " / benign " + r.Benign);
            o.Add(" previous : " + (r.Prev == null ? "(first diagnosis of this target)" : r.Prev.Run));
            if (trend.Count > 1) o.Add(" trend    : actionable " + string.Join(" -> ", trend.ToArray()) + "  (last " + trend.Count + " runs)");
            o.Add(" [most important open findings]");
            int n = 0;
            foreach (Finding f in r.Findings) {
                if (f.Action != FindingBuilder.Actionable) continue;
                if (!full && n >= top) break;
                n++;
                string tag = f.Change == "persisting" ? "seen " + f.SeenRuns : f.Change;
                o.Add(string.Format(CultureInfo.InvariantCulture, "  {0,3}. {1,3}  {2,-24} {3}{4}  {5}   ({6}{7})", n, f.Score, Short(f.Class, 24), Short(f.File, 60), f.Loc.Length > 0 && f.Loc != "-" ? " " + f.Loc : "", Short(f.Subject, 70), tag, f.Affects > 1 ? ", " + f.Affects + " files" : ""));
                if (full) o.Add("        why: " + string.Join("; ", f.Why.ToArray()) + "   id=" + f.Id);
            }
            if (n == 0) o.Add("  (none)");
            else if (!full && r.Actionable > n) o.Add("  ... " + (r.Actionable - n) + " more in the diag file");
            if (r.Resolved.Count > 0) {
                o.Add(" [resolved since previous scan]");
                int m = 0;
                foreach (PrevFinding p in r.Resolved) { if (!full && m >= top) { o.Add("  ... " + (r.Resolved.Count - m) + " more"); break; } m++; o.Add("  - " + Short(p.Category, 24) + "  " + Short(p.File, 60) + "  " + Short(p.Subject, 70)); }
            }
            o.Add(" [detectors that came up empty or failed]");
            int dn = 0;
            foreach (DetectorResult d in r.Detectors) {
                foreach (string s in d.Suspicious) { o.Add("  - " + d.Name + " " + d.Section + " : " + s); dn++; }
                if (d.Found > 0 && d.Unresolved > 0 && (full || d.UnresolvedRate >= 30)) { o.Add(string.Format(CultureInfo.InvariantCulture, "  - {0} {1} : {2} of {3} not resolved ({4}%)", d.Name, d.Section, d.Unresolved, d.Found, d.UnresolvedRate)); dn++; }
            }
            if (dn == 0) o.Add("  (none)");
            if (c.OmittedText.Count + c.OmittedDat.Count > 0)
                o.Add(" [omitted from scan.txt] full text of " + c.OmittedText.Count + " files (DUMPTEXT=0), dump of " + c.OmittedDat.Count + " .dat files (DUMPDAT=0) : output with DUMPFILES / DUMPTEXT / DUMPDAT in settings.ini");
            o.Add(" [could not examine]");
            if (r.Coverage.Count == 0) o.Add("  (nothing skipped)");
            foreach (CoverageItem ci in r.Coverage) o.Add("  - " + ci.Kind + " : " + ci.Count + (ci.Detail.Length > 0 ? "  (" + Short(ci.Detail, 90) + ")" : ""));
            if (r.Next.Count > 0) {
                o.Add(" [next : to examine more in the next scan]");
                int m = 0;
                foreach (string s in r.Next) { if (!full && m >= top) break; m++; o.Add("  - " + s); }
            }
            return o;
        }
    }
}
