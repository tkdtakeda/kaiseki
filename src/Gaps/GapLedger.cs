using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FolderScan.Core;

namespace FolderScan.Gaps {
    // folderscan_gaps.tsv : gaps of every target over time.
    // Rows of other targets are kept unchanged; rows of this target are rewritten.
    public sealed class GapLedger {
        const string Header = "Target\tGapKey\tKind\tFirstSeen\tLastSeen\tSeenCount\tStatus\tPath\tSubject";
        readonly string path;
        readonly List<string> other = new List<string>();
        public readonly Hashtable Mine = PsHash.New();   // gap key -> LedgerRow ; iteration order = v5.18
        public string PrevRun = "";

        public GapLedger(string path) { this.path = path; }

        static bool IsOpenStatus(string s) { return Eq(s, "open") || Eq(s, "explained") || Eq(s, "explained-weak"); }
        static bool Eq(string a, string b) { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }

        public void Read(string root, IConsoleLog log) {
            if (!File.Exists(path)) return;
            try {
                foreach (string ln in File.ReadAllLines(path, Encoding.UTF8)) {
                    string[] c = ln.Split('\t');
                    if (c.Length < 9 || Eq(c[0], "Target")) continue;
                    if (string.Compare(c[0], root, StringComparison.CurrentCultureIgnoreCase) == 0) {
                        LedgerRow r = new LedgerRow(); r.Kind = c[2]; r.First = c[3]; r.Last = c[4]; r.Seen = int.Parse(c[5]); r.Status = c[6]; r.Path = c[7]; r.Subject = c[8];
                        Mine[c[1]] = r;
                        if (string.Compare(c[4], PrevRun, StringComparison.CurrentCultureIgnoreCase) > 0) PrevRun = c[4];
                    } else other.Add(ln);
                }
            } catch (Exception ex) { log.Info("  [warn] gap ledger read: " + ex.Message); }
        }

        // status of this scan's gaps from the previous scans
        public void ApplyStatus(List<Gap> gaps) {
            foreach (Gap g in gaps) {
                LedgerRow p = (LedgerRow)Mine[g.Key];
                if (p == null) continue;
                g.First = p.First; g.Seen = p.Seen + 1;
                if (IsOpenStatus(p.Status)) { g.Status = "persisting"; g.Level = Math.Min(3, p.Seen); } else g.Status = "reopened";
            }
        }

        // gaps open last time that were not found again
        public List<LedgerRow> Resolved(HashSet<string> seenKeys) {
            List<LedgerRow> l = new List<LedgerRow>();
            foreach (object k in Mine.Keys) { LedgerRow p = (LedgerRow)Mine[k]; if (IsOpenStatus(p.Status) && !seenKeys.Contains((string)k)) l.Add(p); }
            return l;
        }

        public void Write(string root, string runId, List<Gap> gaps, HashSet<string> seenKeys, IConsoleLog log) {
            try {
                StringBuilder sb = new StringBuilder();
                sb.Append(Header).Append("\r\n");
                foreach (string ln in other) sb.Append(ln).Append("\r\n");
                foreach (Gap g in gaps) {
                    string st = "open";
                    if (g.Explained.Length > 0) st = g.Conf == "weak" ? "explained-weak" : "explained";
                    sb.Append(string.Join("\t", new string[] { root, g.Key, g.Kind, g.First, runId, g.Seen.ToString(), st, g.Path, g.Subject })).Append("\r\n");
                }
                foreach (object k in Mine.Keys) {
                    if (seenKeys.Contains((string)k)) continue;
                    LedgerRow p = (LedgerRow)Mine[k]; string lst = p.Last, st0 = p.Status;
                    if (IsOpenStatus(st0)) { lst = runId; st0 = "resolved"; }
                    sb.Append(string.Join("\t", new string[] { root, (string)k, p.Kind, p.First, lst, p.Seen.ToString(), st0, p.Path, p.Subject })).Append("\r\n");
                }
                File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
            } catch (Exception ex) { log.Info("  [warn] gap ledger write: " + ex.Message); }
        }
    }
}
