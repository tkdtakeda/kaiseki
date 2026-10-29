using System;
using System.Collections.Generic;
using FolderScan.Analysis;
using FolderScan.Core;
using FolderScan.Gaps;

namespace FolderScan.Diag {
    // Result of one detector in this scan.
    //   (a) unresolved : found but the target could not be identified
    //   (b) suspicious : another detector says something should have been found here
    //   (c) not examined : timeouts / read errors / limits (see CoverageDiag)
    public sealed class DetectorResult {
        public string Name, Section;
        public int Found, Resolved, Unresolved;
        public readonly List<string> Suspicious = new List<string>();
        public readonly List<string> Next = new List<string>();
        public double UnresolvedRate { get { return Found == 0 ? 0 : Math.Round(100.0 * Unresolved / Found, 1); } }
        public bool Empty { get { return Found == 0; } }
    }

    public static class DetectorDiag {
        static readonly HashSet<string> CodeLangs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "py", "js", "cs", "java", "rs", "vb", "ps", "bat" };

        static int Count(List<string[]> edges, string type, bool? withDst) {
            int n = 0;
            foreach (string[] e in edges) if (e[0] == type && (withDst == null || (e[2].Length > 0) == withDst.Value)) n++;
            return n;
        }

        public static List<DetectorResult> Run(ScanContext c, List<Finding> findings) {
            LinkState k = c.Link; DepState d = c.Dep;
            List<string[]> E = d.Edges.Items;
            List<DetectorResult> l = new List<DetectorResult>();
            Dictionary<string, int> actionableByType = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (Finding f in findings) if (f.Source == "unresolved" && (f.Action == FindingBuilder.Actionable || f.Action == FindingBuilder.Tracked)) { int v; actionableByType.TryGetValue(f.Category, out v); actionableByType[f.Category] = v + 1; }

            int srcFiles = 0, sqlRefs = 0, sqlDefs = 0;
            List<string> silent = new List<string>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm; k.Sem.TryGetValue(x.No, out sm);
                if (CodeLangs.Contains(x.Lang) && x.Kind == "text") {
                    srcFiles++;
                    bool nothing = sm == null || (Cnt(sm.Sym) == 0 && Cnt(sm.Imp) == 0 && Cnt(sm.Rt) == 0 && Cnt(sm.Raw) == 0);
                    if (nothing && x.File.Length > 1024) silent.Add(x.Rel);
                }
                if (sm != null && sm.Sql != null) foreach (string[] r in sm.Sql) { if (r[0] == "REF") sqlRefs++; else sqlDefs++; }
            }

            // IMPORT
            DetectorResult imp = New(l, "IMPORT", "[16-1]");
            imp.Found = Count(E, "IMPORT", null); imp.Resolved = Count(E, "IMPORT", true); imp.Unresolved = Get(actionableByType, "IMPORT");
            if (imp.Found > 0 && imp.UnresolvedRate >= 30) imp.Next.Add("many imports are not resolved : add requirements.txt / package.json to the scanned folder, or check module paths");
            // ROUTE / HTTP
            DetectorResult rt = New(l, "ROUTE", "[16-2]");
            rt.Found = d.Routes.Count; rt.Resolved = d.Routes.Count;
            DetectorResult http = New(l, "HTTP", "[16-3]");
            int match = 0, cand = 0, noroute = 0;
            foreach (string[] r in d.ClientRows) { if (r[5] == "(no route found)") noroute++; else if (r[15] == "candidate") cand++; else match++; }
            http.Found = d.ClientRows.Count; http.Resolved = match; http.Unresolved = cand + noroute;
            if (http.Found > 0 && rt.Found == 0) {
                rt.Suspicious.Add(http.Found + " client calls but no server route : the server framework may not be supported, or the server is outside the folder");
                rt.Next.Add("check which framework serves the api (look at [19] http-no-route probes) and add a route rule for it");
            }
            if (noroute > 0 && rt.Found > 0) http.Suspicious.Add(noroute + " client urls match no route although " + rt.Found + " routes exist : url prefix / blueprint not resolved?");
            // SQL
            DetectorResult sql = New(l, "SQL", "[16-5]");
            sql.Found = sqlRefs; sql.Resolved = Count(E, "SQL", true); sql.Unresolved = Get(actionableByType, "SQL");
            if (sqlDefs > 0 && sqlRefs == 0) sql.Suspicious.Add(sqlDefs + " table definitions but no table use found : queries may be built dynamically or use an ORM");
            // DB
            DetectorResult db = New(l, "DATABASE", "[16-5a/b]");
            db.Found = k.DbX.Count; db.Resolved = Count(E, "DBREF", true) + Count(E, "DBFILE", true);
            if (k.DbX.Count > 0 && Count(E, "DBREF", true) == 0) db.Suspicious.Add(k.DbX.Count + " database files but no file refers to them by name : connection string may come from settings outside the folder");
            // CONFIG
            DetectorResult cfg = New(l, "CONFIG", "[16-4]");
            int jsonWithKeys = 0, jsonLinked = 0;
            HashSet<string> cfgDst = new HashSet<string>();
            foreach (string[] e in E) if (e[0] == "CONFIG") cfgDst.Add(e[2]);
            foreach (FileEntry x in k.Fx) { SemItem sm; if (k.Sem.TryGetValue(x.No, out sm) && Cnt(sm.JK) > 0) { jsonWithKeys++; if (cfgDst.Contains(x.No.ToString())) jsonLinked++; } }
            cfg.Found = jsonWithKeys; cfg.Resolved = jsonLinked; cfg.Unresolved = jsonWithKeys - jsonLinked;
            if (cfg.Unresolved > 0) cfg.Next.Add(cfg.Unresolved + " json files are not linked to code : keys may be read in a generic loop, or the file is used by another tool");
            // FILE tokens
            DetectorResult ft = New(l, "FILETOKEN", "[16-6]");
            int tok = 0; foreach (SemItem sm in k.Sem.Values) tok += Cnt(sm.Ext);
            ft.Found = tok; ft.Unresolved = Get(actionableByType, "EXTFILE"); ft.Resolved = Count(E, "FILEMATCH", true) + Count(E, "PATTERN", true);
            // REF / KEY / SYM
            DetectorResult rf = New(l, "REF", "[11]"); rf.Found = k.Refs.Count; rf.Resolved = k.Refs.Count;
            DetectorResult ky = New(l, "KEY", "[12]"); ky.Found = k.Pairs.Count; ky.Resolved = k.Pairs.Count;
            DetectorResult sy = New(l, "SYM", "[16-7]"); sy.Found = Count(E, "SYM", true); sy.Resolved = sy.Found;
            // GENERIC (layer 1, any format)
            DetectorResult gen = New(l, "GENERIC", "[16-8]");
            int gfiles = 0; foreach (SemItem sm in k.Sem.Values) if (sm.Generic != null) { gen.Found += sm.Generic.Count; if (sm.Generic.Count > 0) gfiles++; }
            gen.Resolved = gen.Found;
            if (gen.Found > 0) gen.Next.Add(gen.Found + " outside resources in " + gfiles + " files ([16-8]) : check that these servers / shares / paths exist on the machine where the system runs");
            // semantic extraction per source file
            DetectorResult sem = New(l, "SEMANTIC", "[10]");
            sem.Found = srcFiles; sem.Resolved = srcFiles - silent.Count; sem.Unresolved = silent.Count;
            if (silent.Count > 0) {
                sem.Suspicious.Add(silent.Count + " source files (> 1 KB) gave no symbol / import / route / url : e.g. " + string.Join(" ; ", silent.GetRange(0, Math.Min(3, silent.Count)).ToArray()));
                sem.Next.Add("open one of these files : syntax not covered by the regex rules (dialect, generated code, unusual layout)");
            }
            return l;
        }

        static DetectorResult New(List<DetectorResult> l, string name, string sec) { DetectorResult r = new DetectorResult(); r.Name = name; r.Section = sec; l.Add(r); return r; }
        static int Cnt(List<string[]> l) { return l == null ? 0 : l.Count; }
        static int Get(Dictionary<string, int> d, string k) { int v; return d.TryGetValue(k, out v) ? v : 0; }
    }
}
