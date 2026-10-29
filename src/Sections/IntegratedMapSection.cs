using System;
using System.Collections.Generic;
using System.Text;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [17] INTEGRATED RELATION MAP : all edges of [11]-[16], roles, entry points,
    // relation map per file, mermaid graph, file pair summary.
    public sealed class IntegratedMapSection : IReportSection {
        static readonly Dictionary<string, int> EvRank = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) { { "fact", 0 }, { "match", 1 }, { "candidate", 2 }, { "weak", 3 }, { "external", 4 } };

        static bool HiddenOrigin(string o) { return o == "binary-string" || o == "documentation" || o == "generated-vendor"; }
        static int Int(string s) { int n; int.TryParse(s, out n); return n; }

        public void Write(ScanContext c) {
            LinkState k = c.Link;
            DepState d = c.Dep;
            EdgeList E = d.Edges;
            c.Progress("[17/19] Integrated relation map...");
            AddLinkEdges(k, E);
            c.L("==== [17] INTEGRATED RELATION MAP (all edges of [11]-[16]) ====");
            c.L(" Edge types : REF (file name written) / IMPORT (module import) / EXEC (script launch) /");
            c.L("              INCLUDE (template, script src, css, static file) / HTTP (client url + method -> server route) /");
            c.L("              CONFIG (json file used by code) / SQL (table use) / PATTERN (wildcard file name) /");
            c.L("              FILEMATCH (normalized/suffix filename match) /");
            c.L("              EXTFILE (file name not in folder) / SYM (symbol name use) / KEY (shared key value) /");
            c.L("              SAME (identical content) / STEM (same base name)");
            c.L(" Evidence   : fact / match / candidate / weak / external (confidence; see [16])");
            c.L(" Origin     : source-code / text-data / documentation / binary-string / generated-vendor / other");
            c.L();
            c.L("---- [17-1] ALL EDGES (raw : every detected edge, nothing removed) ----");
            List<string[]> rows = new List<string[]>();
            foreach (string[] e in E.Items) {
                bool hasDst = e[2].Length > 0;
                rows.Add(new string[] { e[0], e[1], k.FP(e[1]), hasDst ? e[2] : "-", hasDst ? k.FP(e[2]) : "(external)", e[3], e[4], e[5], e[6] });
            }
            c.Report.Tsv("edges", new string[] { "Type", "SrcNo", "SrcPath", "DstNo", "DstPath", "Detail", "Loc", "Evidence", "Origin" }, rows);
            c.L();
            Roles(c);
            Entries(c);
            PerFile(c);
            Mermaid(c);
            Pairs(c);
        }

        // REF / KEY / SAME / STEM edges from [11]-[13]
        static void AddLinkEdges(LinkState k, EdgeList E) {
            foreach (string[] r in k.Refs) foreach (string t in r[2].Split(',')) E.Add("REF", r[0], t, "token=" + r[1] + " hits=" + r[3], r[4], "fact");
            foreach (string[] p in k.Pairs) E.Add("KEY", p[0], p[1], "shared=" + p[2] + " e.g. " + p[3], "", "candidate");
            foreach (List<FileEntry> g in k.SameContent)
                for (int i = 0; i < g.Count; i++) for (int j = i + 1; j < g.Count; j++)
                    E.Add("SAME", g[i].No.ToString(), g[j].No.ToString(), "sha256=" + g[0].Sha.Substring(0, 16) + "..", "", "fact");
            foreach (KeyValuePair<string, List<FileEntry>> g in k.SameBase) {
                if (SameFileSection.DistinctExt(g.Value) < 2) continue;
                List<FileEntry> gl = g.Value;
                for (int i = 0; i < gl.Count; i++) for (int j = i + 1; j < gl.Count; j++)
                    if (!string.Equals(gl[i].File.Extension, gl[j].File.Extension, StringComparison.OrdinalIgnoreCase))
                        E.Add("STEM", gl[i].No.ToString(), gl[j].No.ToString(), "base=" + g.Key, "", "candidate");
            }
        }

        static void Inc(Dictionary<int, Dictionary<string, int>> h, int no, string t) {
            Dictionary<string, int> m;
            if (!h.TryGetValue(no, out m)) { m = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase); h[no] = m; }
            int v; m.TryGetValue(t, out v); m[t] = v + 1;
        }

        static void Bump(Dictionary<int, int> h, int no) { int v; h.TryGetValue(no, out v); h[no] = v + 1; }

        // [17-2] ROLE PER FILE (weak edges and binary/doc/vendor origins are not used)
        static void Roles(ScanContext c) {
            LinkState k = c.Link; DepState d = c.Dep;
            foreach (string[] e in d.Edges.Items) {
                Bump(d.OutAll, Int(e[1]));
                if (e[2].Length > 0) Bump(d.InAll, Int(e[2]));
                if (e[5] == "weak" || HiddenOrigin(e[6])) continue;
                Inc(d.OutT, Int(e[1]), e[0]); if (e[2].Length > 0) Inc(d.InT, Int(e[2]), e[0]);
            }
            foreach (FileEntry x in k.Fx) {
                SemItem sm; k.Sem.TryGetValue(x.No, out sm);
                List<string> ro = new List<string>();
                bool runner = (x.Lang == "bat" || x.Lang == "ps") && !d.HasT(d.InT, x.No, "EXEC");
                if (runner || (sm != null && sm.Main)) ro.Add("entry-candidate");
                if (sm != null && sm.Rt != null && sm.Rt.Count > 0) ro.Add("http-server");
                if (d.HasT(d.OutT, x.No, "HTTP")) ro.Add("http-client");
                if (d.HasT(d.InT, x.No, "IMPORT")) ro.Add("module/library");
                if (d.HasT(d.InT, x.No, "EXEC")) ro.Add("launched-script");
                if (d.HasT(d.InT, x.No, "INCLUDE")) ro.Add("template/static-asset");
                if (d.HasT(d.InT, x.No, "CONFIG")) ro.Add("config/settings");
                if (sm != null && sm.Sql != null && HasDef(sm.Sql)) ro.Add("db-schema");
                if (d.HasT(d.OutT, x.No, "SQL")) ro.Add("db-user");
                if (d.HasT(d.OutT, x.No, "EXTFILE")) ro.Add("uses-outside-files");
                string ext = x.Ext;
                if (x.Lang.Length == 0 && (ext == ".md" || ext == ".txt" || ext == ".rst")) ro.Add("document");
                if (x.Lang.Length == 0 && x.Kind == "binary") ro.Add("data(binary)");
                if (ro.Count == 0) ro.Add("unclassified");
                d.Role[x.No] = string.Join(",", ro.ToArray());
            }
            c.L("---- [17-2] ROLE PER FILE (inferred from non-weak edges and semantic items) ----");
            List<string[]> rows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                int ia, oa; d.InAll.TryGetValue(x.No, out ia); d.OutAll.TryGetValue(x.No, out oa);
                rows.Add(new string[] { x.No.ToString(), x.Display, x.Lang.Length > 0 ? x.Lang : "-", d.Role[x.No], ia.ToString(), oa.ToString() });
            }
            c.Report.Tsv("roles", new string[] { "No", "Path", "Lang", "Role", "InEdges", "OutEdges" }, rows);
            c.L();
        }

        static bool HasDef(List<string[]> sql) { foreach (string[] r in sql) if (r[0] == "DEF") return true; return false; }

        // [17-3] ENTRY POINTS / ISOLATED FILES
        static void Entries(ScanContext c) {
            LinkState k = c.Link; DepState d = c.Dep;
            c.L("---- [17-3] ENTRY POINTS / ISOLATED FILES ----");
            List<string> ent = new List<string>();
            foreach (FileEntry x in k.Fx) if (d.Role[x.No].IndexOf("entry-candidate", StringComparison.OrdinalIgnoreCase) >= 0) ent.Add("No." + x.No + "  " + x.Display);
            c.L("[entry point candidates] (bat/ps not launched by other files, or main guard found)");
            if (ent.Count == 0) c.L("  (none)"); else foreach (string s in ent) c.L("  " + s);
            HashSet<int> strong = new HashSet<int>(), any = new HashSet<int>();
            foreach (string[] e in d.Edges.Items) {
                if ((e[5] == "fact" || e[5] == "match") && !HiddenOrigin(e[6])) { strong.Add(Int(e[1])); if (e[2].Length > 0) strong.Add(Int(e[2])); }
                any.Add(Int(e[1])); if (e[2].Length > 0) any.Add(Int(e[2]));
            }
            foreach (FileEntry x in k.Fx) { if (!strong.Contains(x.No)) d.Iso1.Add(x.No.ToString()); if (!any.Contains(x.No)) d.Iso2.Add(x.No.ToString()); }
            c.L("[no fact/match edge] No. " + string.Join(",", d.Iso1.ToArray()));
            c.L("[no edge at all]     No. " + string.Join(",", d.Iso2.ToArray()));
            c.L();
        }

        // [17-4] RELATION MAP PER FILE (all edge types)
        static void PerFile(ScanContext c) {
            LinkState k = c.Link; DepState d = c.Dep;
            c.L("---- [17-4] RELATION MAP PER FILE (all edge types) ----");
            c.L("  -> TYPE  this file depends on / points to the other file");
            c.L("  <- TYPE  the other file depends on / points to this file");
            c.L();
            Dictionary<int, List<string>> byF = new Dictionary<int, List<string>>();
            foreach (string[] e in d.Edges.Items) {
                string lc = e[4].Length > 0 ? " @" + e[4] : "";
                string tail = "   [" + e[3] + lc + "] (" + e[5] + ", origin=" + e[6] + ")";
                if (e[2].Length > 0) {
                    Add(byF, Int(e[1]), "  -> " + e[0].PadRight(8) + "No." + e[2] + "  " + k.FP(e[2]) + tail);
                    Add(byF, Int(e[2]), "  <- " + e[0].PadRight(8) + "No." + e[1] + "  " + k.FP(e[1]) + tail);
                } else Add(byF, Int(e[1]), "  -> " + e[0].PadRight(8) + "(external)" + tail);
            }
            foreach (FileEntry x in k.Fx) {
                c.L("[No." + x.No + "] " + x.Src + " " + x.Rel + "  (" + x.Kind + ", " + (x.Lang.Length > 0 ? x.Lang : "-") + ", " + x.File.Length + " bytes)  role=" + d.Role[x.No]);
                List<string> l;
                if (byF.TryGetValue(x.No, out l)) { List<string> s = new List<string>(l); SymbolUseSection.StableSort(s); foreach (string t in s) c.L(t); }
                else c.L("  (no edge)");
                c.L();
            }
        }

        static void Add(Dictionary<int, List<string>> h, int n, string s) {
            List<string> l; if (!h.TryGetValue(n, out l)) { l = new List<string>(); h[n] = l; }
            l.Add(s);
        }

        // [17-5] DEPENDENCY GRAPH (mermaid)
        static void Mermaid(ScanContext c) {
            LinkState k = c.Link; DepState d = c.Dep; Settings s = c.Settings;
            c.L("---- [17-5] DEPENDENCY GRAPH (mermaid) ----");
            c.L(" solid arrow = fact / match, dotted arrow = candidate, ext_* node = outside of the scanned folder");
            c.L(" KEY edges drawn : " + s.MermaidKey + "   SYM edges drawn : " + s.MermaidSym + "   weak edges drawn : " + s.MermaidWeak + "   (binary-string / documentation / generated-vendor origins are hidden; all raw edges are in [17-1])");
            c.L("#MERMAID-BEGIN dependency_graph");
            c.L("graph LR");
            foreach (FileEntry x in k.Fx) c.L("  F" + x.No + "[\"" + x.Rel.TrimStart('\\').Replace("\"", "'").Replace('\\', '/') + "\"]");
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string> xid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            int xn = 0;
            foreach (string[] e in d.Edges.Items) {
                if (HiddenOrigin(e[6])) continue;
                if (e[0] == "KEY" && s.MermaidKey != 1) continue;
                if (e[0] == "SYM" && s.MermaidSym != 1) continue;
                if (e[5] == "weak" && s.MermaidWeak != 1) continue;
                string dst;
                if (e[2].Length > 0) dst = "F" + e[2];
                else {
                    if (e[0] != "EXEC" && e[0] != "INCLUDE" && e[0] != "EXTFILE" && e[0] != "SQL") continue;
                    string xk = e[0] + "|" + e[3];
                    if (!xid.TryGetValue(xk, out dst)) {
                        xn++; dst = "ext_" + xn; xid[xk] = dst;
                        string xl = e[3].Replace("\"", "'").Replace('\\', '/');
                        if (xl.Length > 60) xl = xl.Substring(0, 60) + "..";
                        c.L("  " + dst + "([\"" + xl + "\"])");
                    }
                }
                if (!seen.Add("F" + e[1] + "|" + dst + "|" + e[0])) continue;
                string arrow = e[5] == "candidate" || e[5] == "weak" ? "-.->" : "-->";
                c.L("  F" + e[1] + " " + arrow + "|" + e[0] + "| " + dst);
            }
            c.L("#MERMAID-END");
            c.L();
        }

        sealed class Pair {
            public string S, D, Best = "weak";
            public readonly Dictionary<string, int> T = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public readonly Dictionary<string, int> Ev = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            public readonly Dictionary<string, int> O = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        }

        static int Rank(string ev) { int r; return ev != null && EvRank.TryGetValue(ev, out r) ? r : 0; }

        static void Inc(Dictionary<string, int> h, string key) { int v; h.TryGetValue(key, out v); h[key] = v + 1; }

        // [17-6] FILE PAIR SUMMARY
        static void Pairs(ScanContext c) {
            LinkState k = c.Link; DepState d = c.Dep;
            c.L("---- [17-6] FILE PAIR SUMMARY (one row per Src -> Dst, all edge types merged for reading) ----");
            c.L(" Types    = edge types with count, e.g. IMPORT x1 SYM x1 (same relation found by several methods)");
            c.L(" Best     = strongest evidence among them (fact > match > candidate > weak)");
            c.L(" Evidence = count per confidence. Origins = count per source of evidence. Raw edges are not changed, see [17-1].");
            Dictionary<string, Pair> pr = new Dictionary<string, Pair>(StringComparer.OrdinalIgnoreCase);
            List<Pair> order = new List<Pair>();
            foreach (string[] e in d.Edges.Items) {
                if (e[2].Length == 0) continue;
                string pk = e[1] + "|" + e[2];
                Pair o;
                if (!pr.TryGetValue(pk, out o)) { o = new Pair(); o.S = e[1]; o.D = e[2]; pr[pk] = o; order.Add(o); }
                Inc(o.T, e[0]); Inc(o.Ev, e[5]); Inc(o.O, e[6]);
                if (Rank(e[5]) < Rank(o.Best)) o.Best = e[5];
            }
            List<KeyValuePair<int, Pair>> sorted = new List<KeyValuePair<int, Pair>>();
            for (int i = 0; i < order.Count; i++) sorted.Add(new KeyValuePair<int, Pair>(i, order[i]));
            sorted.Sort(delegate (KeyValuePair<int, Pair> a, KeyValuePair<int, Pair> b) {
                int r = Rank(a.Value.Best).CompareTo(Rank(b.Value.Best)); if (r != 0) return r;
                r = Int(a.Value.S).CompareTo(Int(b.Value.S)); if (r != 0) return r;
                r = Int(a.Value.D).CompareTo(Int(b.Value.D)); if (r != 0) return r;
                return a.Key.CompareTo(b.Key);
            });
            List<string[]> rows = new List<string[]>();
            foreach (KeyValuePair<int, Pair> kv in sorted) {
                Pair o = kv.Value;
                rows.Add(new string[] { o.S, k.FP(o.S), o.D, k.FP(o.D), Join(o.T, " x", false), o.Best, Join(o.Ev, "=", true), Join(o.O, "=", false) });
            }
            if (rows.Count == 0) c.L("(no file pair)");
            c.Report.Tsv("pair_summary", new string[] { "SrcNo", "SrcPath", "DstNo", "DstPath", "Types", "Best", "Evidence", "Origins" }, rows);
            c.L();
        }

        // keys sorted by name (or by evidence rank) as "key<sep>count" joined by spaces
        static string Join(Dictionary<string, int> h, string sep, bool byRank) {
            List<string> keys = new List<string>(h.Keys);
            if (byRank) keys.Sort(delegate (string a, string b) { return Rank(a).CompareTo(Rank(b)); });
            else SymbolUseSection.StableSort(keys);
            StringBuilder sb = new StringBuilder();
            foreach (string key in keys) { if (sb.Length > 0) sb.Append(' '); sb.Append(key).Append(sep).Append(h[key]); }
            return sb.ToString();
        }
    }
}
