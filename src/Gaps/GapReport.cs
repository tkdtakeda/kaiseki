using System;
using System.Collections.Generic;
using FolderScan.Core;

namespace FolderScan.Gaps {
    // Text of the gap report ([19] and gaps_*.txt).
    public sealed class GapReport {
        public readonly List<string> Lines = new List<string>();
        void G() { Lines.Add(""); }
        void G(string s) { Lines.Add(s); }
        void GT(string name, string[] head, List<string[]> rows) {
            G("#TSV-BEGIN " + name); G(string.Join("\t", head));
            foreach (string[] r in rows) G(string.Join("\t", r));
            G("#TSV-END");
        }

        static bool Weak(Gap g) { return g.Explained.Length > 0 && g.Conf == "weak"; }
        static bool Strong(Gap g) { return g.Explained.Length > 0 && g.Conf != "weak"; }

        public void Build(ScanContext c, string runId, GapCollector col, GapExplainer ex, List<LedgerRow> resolved, GapLedger led, MetricsHistory mh) {
            List<Gap> gaps = col.Gaps;
            int nExp = 0, nWeak = 0, nNew = 0, nPer = 0;
            foreach (Gap g in gaps) {
                if (g.Explained.Length > 0) nExp++;
                if (Weak(g)) nWeak++;
                if (g.Status == "new" || g.Status == "reopened") nNew++;
                if (g.Status == "persisting") nPer++;
            }
            string prevTxt = "(no earlier scan of this target)";
            if (led.PrevRun.Length > 0) prevTxt = led.PrevRun; else if (mh.PrevRun.Length > 0) prevTxt = mh.PrevRun + " (history)";
            string bar = new string('=', 60);
            G(bar);
            G(" folderscan gap report " + ScanContext.Version);
            G(" Target    : " + c.ScanRoot);
            G(" Scan time : " + runId + "   elapsed " + mh.Met["elapsed.sec"] + " s");
            G(" Full scan : " + c.Report.Path);
            G(" Previous  : " + prevTxt);
            G(" Gaps      : " + gaps.Count + "  (new " + nNew + " / persisting " + nPer + " / resolved since previous " + resolved.Count + ")");
            G(" Explained : strong " + (nExp - nWeak) + " / weak " + nWeak + "   Still open : " + (gaps.Count - nExp));
            G("   strong = evidence on the gap line or a traced definition ; weak = nearby / name-only (listed in [G-0b], probed deeper next scan)");
            G(bar);
            G(" gap   = information this scan could not establish");
            G(" probe = extra evidence collected now for the gap");
            G(" A gap seen again next time is probed deeper (context +3 lines, +1 definition hop, more mentions).");
            G(" http calls whose method was taken from the only matching route (not a gap) : " + col.RouteImplied);
            G();
            G("---- [G-0] EXPLAINED BY PROBE EVIDENCE (rule hit count / items) ----");
            List<string[]> x = new List<string[]>();
            foreach (object k in ex.Exr.Keys) { string conf; ex.Exc.TryGetValue((string)k, out conf); x.Add(new string[] { (string)k, conf ?? "", ex.Exr[k].ToString() }); }
            if (x.Count == 0) G("(no gap explained by a rule)");
            GT("explain_rules", new string[] { "Rule", "Confidence", "Hits" }, x);
            List<string[]> xi = new List<string[]>();
            foreach (Gap g in gaps) if (Strong(g)) xi.Add(new string[] { g.Explained, g.Kind, g.Path, g.Loc, g.Subject, g.ExEv });
            GT("explained_gaps", new string[] { "Rule", "Kind", "Path", "Loc", "Subject", "Evidence" }, xi);
            G();
            G("---- [G-0b] WEAKLY EXPLAINED : NEEDS CONFIRMATION (full probe in [G-4], probed deeper next scan) ----");
            List<string[]> wk = new List<string[]>();
            foreach (Gap g in gaps) if (Weak(g)) wk.Add(new string[] { g.Explained, g.Kind, g.Path, g.Loc, g.Subject, g.ExEv });
            if (wk.Count == 0) G("(none)");
            GT("weakly_explained_gaps", new string[] { "Rule", "Kind", "Path", "Loc", "Subject", "Evidence" }, wk);
            G();
            Kinds(gaps, resolved);
            G("---- [G-2] GAP LIST ----");
            List<string[]> lr = new List<string[]>();
            foreach (Gap g in gaps) {
                string st = g.Status;
                if (g.Explained.Length > 0) st = (Weak(g) ? "explained-weak:" : "explained:") + g.Explained;
                lr.Add(new string[] { st, g.Seen.ToString(), g.Kind, g.Path, g.Loc, g.Subject, g.Note, g.Level.ToString() });
            }
            GT("gaps", new string[] { "Status", "SeenCount", "Kind", "Path", "Loc", "Subject", "Note", "ProbeLevel" }, lr);
            G();
            G("---- [G-3] RESOLVED SINCE PREVIOUS SCAN ----");
            List<string[]> vr = new List<string[]>();
            foreach (LedgerRow p in resolved) vr.Add(new string[] { p.Kind, p.Path, p.Subject, p.First, p.Seen.ToString() });
            if (vr.Count == 0) G("(none)");
            GT("gaps_resolved", new string[] { "Kind", "Path", "Subject", "FirstSeen", "SeenCount" }, vr);
            G();
            G("---- [G-4] PROBES (max " + c.Settings.GapMax + " gaps per kind) ----");
            foreach (Gap g in gaps) {
                if (!g.Probed) continue;
                string head = "### [" + g.Kind + "] " + g.Path + " " + g.Loc + "  " + g.Subject;
                if (Strong(g)) { G(head + "   EXPLAINED (strong) by " + g.Explained); G("  evidence : " + g.ExEv); continue; }
                if (Weak(g)) { G(head + "   EXPLAINED (weak) by " + g.Explained + " - needs confirmation   (seen " + g.Seen + ", level " + g.Level + ")"); G("  evidence : " + g.ExEv); foreach (string s in g.Out) G(s); continue; }
                G(head + "   (" + g.Status + ", seen " + g.Seen + ", level " + g.Level + ")");
                if (g.Note.Length > 0) G("  note : " + g.Note);
                foreach (string s in g.Out) G(s);
                if (g.Out.Count == 0) G("  (no probe output)");
            }
            G();
            G("---- [G-5] METRIC CHANGE FROM PREVIOUS SCAN OF THE SAME TARGET ----");
            if (mh.PrevRun.Length == 0) G("(no previous scan of this target in folderscan_history.tsv)");
            else if (mh.Delta.Count == 0) G("(no change)");
            GT("metric_delta", new string[] { "Metric", "Previous", "Now", "Delta" }, mh.Delta);
            G();
        }

        // [G-1] GAPS BY KIND
        void Kinds(List<Gap> gaps, List<LedgerRow> resolved) {
            G("---- [G-1] GAPS BY KIND ----");
            Dictionary<string, List<Gap>> byKind = new Dictionary<string, List<Gap>>(StringComparer.CurrentCultureIgnoreCase);
            List<string> kinds = new List<string>();
            foreach (Gap g in gaps) { List<Gap> l; if (!byKind.TryGetValue(g.Kind, out l)) { l = new List<Gap>(); byKind[g.Kind] = l; kinds.Add(g.Kind); } l.Add(g); }
            FolderScan.Sections.SymbolUseSection.StableSort(kinds);
            List<string[]> rows = new List<string[]>();
            foreach (string kd in kinds) {
                List<Gap> l = byKind[kd];
                int open = 0, nn = 0, probed = 0, st = 0, wk = 0, pv = 0;
                foreach (Gap g in l) { if (g.Explained.Length == 0) open++; if (g.Status != "persisting") nn++; if (g.Probed) probed++; if (Strong(g)) st++; if (Weak(g)) wk++; }
                foreach (LedgerRow p in resolved) if (string.Equals(p.Kind, kd, StringComparison.OrdinalIgnoreCase)) pv++;
                rows.Add(new string[] { kd, open.ToString(), nn.ToString(), (l.Count - nn).ToString(), pv.ToString(), probed.ToString(), st.ToString(), wk.ToString() });
            }
            // kinds that only have resolved gaps (Group-Object order = first appearance)
            Dictionary<string, int> rk = new Dictionary<string, int>(StringComparer.CurrentCultureIgnoreCase);
            List<string> rOrder = new List<string>();
            foreach (LedgerRow p in resolved) { int v; if (!rk.TryGetValue(p.Kind, out v)) rOrder.Add(p.Kind); rk[p.Kind] = v + 1; }
            foreach (string kd in rOrder) if (!byKind.ContainsKey(kd)) rows.Add(new string[] { kd, "0", "0", "0", rk[kd].ToString(), "0", "0", "0" });
            if (rows.Count == 0) G("(no gap)");
            GT("gap_kinds", new string[] { "Kind", "Open", "New", "Persisting", "ResolvedSincePrevious", "Probed", "ExplainedStrong", "ExplainedWeak" }, rows);
            G();
        }
    }
}
