using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using FolderScan.Core;

namespace FolderScan.Analysis {
    // Result of [10] for one file. Built in parallel, written to the report in file order.
    public sealed class ContentResult {
        public FileEntry X;
        public readonly StringWriter Pre = new StringWriter();   // text before the content listing
        public List<Unit> Units;                                 // content listing (null = none)
        public readonly StringWriter Post = new StringWriter();  // text after the content listing
        public HashSet<string> Keys;                             // null = file not analyzed
        public readonly List<string[]> Refs = new List<string[]>();
        public SemItem Sem;
        public readonly List<Wrap> Wrappers = new List<Wrap>();
        public bool Omitted;                                     // content listing left out (DUMPTEXT=0)
    }

    // Content and data structure of one file (the loop body of [10] in v5.18).
    // Uses only read-only shared data, so files can be analyzed at the same time.
    public sealed class ContentAnalyzer {
        readonly Settings s;
        readonly Dictionary<string, DatInfo> datA;
        readonly Dictionary<string, string> names;
        readonly List<FileEntry> dbX;

        public ContentAnalyzer(Settings s, Dictionary<string, DatInfo> datA, Dictionary<string, string> names, List<FileEntry> dbX) {
            this.s = s; this.datA = datA; this.names = names; this.dbX = dbX;
        }

        static string N(double d) { return d.ToString(CultureInfo.InvariantCulture); }

        public ContentResult Analyze(FileEntry x) {
            ContentResult r = new ContentResult(); r.X = x;
            TextWriter o = r.Pre;
            string ext = x.Ext; string extK = ext.Length == 0 ? "(none)" : ext;
            string bar = new string('#', 78);
            o.WriteLine(bar);
            o.WriteLine("# FILE No." + x.No + "  " + x.Src + "  " + x.Rel);
            o.WriteLine(bar);
            o.WriteLine("Kind      : " + x.Kind + "   Bytes : " + x.File.Length);
            if (x.Kind == "text") o.WriteLine("Encoding  : " + SemTool.CpName(x.Cp) + " (codepage " + x.Cp + ")   Lang : " + (x.Lang.Length > 0 ? x.Lang : "-"));
            if (x.Kind != "text" && x.Kind != "binary") { o.WriteLine("(content not analyzed)"); o.WriteLine(); return r; }
            bool isText = x.Kind == "text";
            List<Unit> u;
            try { u = LinkTool.Units(x.File.FullName, isText, x.Cp, s.LinkMaxBytes, s.MinStr); }
            catch (Exception ex) { o.WriteLine("read error: " + ex.Message); o.WriteLine(); return r; }
            if (s.LinkMaxBytes > 0) o.WriteLine("ReadLimit : first " + s.LinkMaxMb + " MB only");
            bool dump = s.WantDump(s.DumpText == 1, x.Rel, x.File.Name);
            const string omit = "   (content omitted : DUMPTEXT=0 ; set DUMPTEXT=1 or add this file to DUMPFILES in settings.ini)";
            if (isText) {
                if (ext == ".dat") o.WriteLine("[TEXT] " + u.Count + " lines : see [8]");
                else if (dump) { o.WriteLine("[TEXT] " + u.Count + " lines"); r.Units = u; }
                else { o.WriteLine("[TEXT] " + u.Count + " lines" + omit); r.Omitted = u.Count > 0; }
            } else {
                o.WriteLine("[STRINGS] " + u.Count + " runs (>= " + s.MinStr + " chars, Loc = byte offset)" + (dump ? "" : omit));
                if (dump) r.Units = u; else r.Omitted = u.Count > 0;
            }
            TextWriter p = r.Post;
            p.WriteLine();
            HashSet<string> keys = LinkTool.Keys(u, s.KeyMax);
            Structure(x, u, isText, extK, keys, p);
            r.Keys = keys;
            p.WriteLine("[KEYS] " + keys.Count + " candidate key values");
            References(x, u, isText, r);
            p.WriteLine("[REFS] " + r.Refs.Count + " file names found in this file (see [11])");
            Semantic(x, u, isText, r, p);
            r.Sem.DbHits = DbRules.Scan(x, u, dbX);
            r.Sem.Generic = GenericScanner.Scan(u, null);
            x.Depth = isText && x.Lang.Length > 0 ? "structure" : "generic";
            p.WriteLine();
            return r;
        }

        void Structure(FileEntry x, List<Unit> u, bool isText, string extK, HashSet<string> keys, TextWriter p) {
            RecSet rs = null;
            if (isText) {
                TableInfo tbl = LinkTool.Delim(u, s.ProfRec);
                if (!string.IsNullOrEmpty(tbl.Info)) {
                    p.WriteLine("[TABLE] " + tbl.Info);
                    ReportWriter.WriteTsv(p, "table_" + x.No, new string[] { "Col", "Header", "Numeric%", "Distinct", "Examples" }, tbl.Cols);
                    p.WriteLine();
                } else {
                    rs = LinkTool.LineRecs(u, x.Cp, s.ProfRec);
                    if (rs.Recs.Count >= 2) p.WriteLine("[FIELDS] fixed-width lines : length=" + rs.Len + " bytes  same length=" + N(Math.Round(rs.Ratio, 1)) + "%  profiled=" + rs.Recs.Count + " / lines=" + rs.Total);
                    else rs = null;
                }
            } else if (ContainsIgnoreCase(s.RecExt, extK)) {
                DatInfo a;
                if (!datA.TryGetValue(x.File.FullName, out a)) { try { a = DatTool.Analyze(x.File.FullName, s.RecSample, s.RecLag); } catch { a = null; } }
                if (a != null && a.BestLen >= 4 && a.BestScore >= s.RecMin) {
                    rs = LinkTool.FixedRecs(x.File.FullName, a.BestLen, s.ProfRec);
                    if (rs.Recs.Count >= 2) {
                        string div = x.File.Length % a.BestLen == 0 ? "yes" : "no";
                        p.WriteLine("[FIELDS] fixed-length records : length=" + a.BestLen + " bytes  similarity=" + N(Math.Round(a.BestScore, 1)) + "%  size divisible=" + div + "  profiled=" + rs.Recs.Count + " / records=" + rs.Total);
                    } else rs = null;
                } else if (a != null) {
                    p.WriteLine("[FIELDS] no fixed-length record detected (best=" + a.BestLen + " bytes, " + N(Math.Round(a.BestScore, 1)) + "% < " + N(s.RecMin) + "%)");
                }
            }
            if (rs != null) {
                List<Field> fl = LinkTool.Profile(rs.Recs, x.Cp);
                ReportWriter.WriteTsv(p, "fields_" + x.No, new string[] { "Start", "Len", "Class", "Distinct", "Examples" }, LinkTool.FieldRows(fl));
                LinkTool.FieldKeys(rs.Recs, fl, x.Cp, keys, s.KeyMax);
                p.WriteLine();
            }
        }

        void References(FileEntry x, List<Unit> u, bool isText, ContentResult r) {
            string basis = isText ? "text" : "binstr";
            string self = x.No.ToString();
            foreach (string[] e in LinkTool.Refs(u, names, x.File.Name.ToLowerInvariant())) {
                List<string> tn = new List<string>();
                foreach (string t in e[1].Split(',')) if (t.Length > 0 && t != self) tn.Add(t);
                if (tn.Count == 0) continue;
                r.Refs.Add(new string[] { self, e[0], string.Join(",", tn.ToArray()), e[2], e[3], basis, e[4] });
            }
        }

        void Semantic(FileEntry x, List<Unit> u, bool isText, ContentResult r, TextWriter p) {
            string lang = x.Lang;
            SemItem sm = new SemItem(); sm.No = x.No; sm.Lang = lang; sm.Text = isText;
            SemTool.TimeoutLocs.Clear();
            try {
                sm.Ext = SemTool.FileTokens(u, lang);
                sm.Sql = SemTool.Sql(u, lang, !isText);
                if (isText && lang.Length > 0) {
                    sm.Sym = SemTool.Symbols(u, lang);
                    sm.Imp = SemTool.Imports(u, lang);
                    sm.Rt = SemTool.Routes(u, lang);
                    if (lang == "json") sm.JK = SemTool.JsonKeys(u);
                    else {
                        sm.Lit = SemTool.Literals(u);
                        sm.Acc = SemTool.KeyAccess(u);
                        sm.Idn = SemTool.Idents(u);
                        sm.Raw = SemTool.ClientRaw(u, lang);
                        sm.Main = SemTool.HasMain(u, lang);
                        r.Wrappers.AddRange(SemTool.Wrappers(u, lang, x.No.ToString()));
                    }
                }
            } catch (Exception ex) { p.WriteLine("[SEM] analysis error: " + ex.Message); }
            if (SemTool.TimeoutLocs.Count > 0) {
                sm.Tmo = string.Join(" ", SemTool.TimeoutLocs.ToArray());
                p.WriteLine("[SEM] regex timeout (these units were not analyzed by some rules, content itself is above): " + sm.Tmo);
            }
            r.Sem = sm;
            p.WriteLine("[SEM] symbols=" + Cnt(sm.Sym) + " imports=" + Cnt(sm.Imp) + " routes=" + Cnt(sm.Rt) + " client-url-sites=" + Cnt(sm.Raw) +
                " json-keys=" + Cnt(sm.JK) + " key-access=" + (sm.Acc == null ? 0 : sm.Acc.Count) + " sql=" + Cnt(sm.Sql) + " file-tokens=" + Cnt(sm.Ext) +
                " functions=" + r.Wrappers.Count + " main=" + sm.Main);
        }

        static int Cnt(List<string[]> l) { return l == null ? 0 : l.Count; }

        static bool ContainsIgnoreCase(List<string> l, string v) {
            foreach (string t in l) if (string.Equals(t, v, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
}
