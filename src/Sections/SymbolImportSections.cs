using System;
using System.Collections.Generic;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [15] CODE SYMBOLS
    public sealed class SymbolSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            c.Dep.Edges = new EdgeList(k);
            c.Progress("[15/19] Code symbols...");
            c.L("==== [15] CODE SYMBOLS (definitions found in source code) ====");
            c.L(" Lang is decided by extension (py js html css bat ps cs vb java rs sql json).");
            c.L(" Kind : def / method/inner-def / class / const / var (py), function / class / top-var (js),");
            c.L("        label (bat), psfunction (ps), type:* / method (cs, java), sub / function (vb),");
            c.L("        fn / struct / enum / trait / mod (rs), sql:table / sql:view ... (sql)");
            c.L(" Main=True : entry guard found (python __main__ / rust fn main / C# static Main / java main)");
            List<string[]> rows = new List<string[]>(), rowsC = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm)) continue;
                int n = 0;
                if (sm.Sym != null) foreach (string[] r in sm.Sym) { n++; rows.Add(new string[] { x.No.ToString(), x.Display, sm.Lang, r[0], r[1], r[2] }); }
                if (sm.Lang.Length > 0 && sm.Lang != "json" && sm.Text) rowsC.Add(new string[] { x.No.ToString(), x.Display, sm.Lang, n.ToString(), sm.Main.ToString() });
            }
            if (rows.Count == 0) c.L("(no symbol found)");
            c.Report.Tsv("symbols", new string[] { "No", "Path", "Lang", "Kind", "Name", "Loc" }, rows);
            c.L();
            c.L("[symbols per source file]");
            c.Report.Tsv("symbol_count", new string[] { "No", "Path", "Lang", "Symbols", "Main" }, rowsC);
            c.L();
        }
    }

    // [16] header + [16-1] IMPORT / EXEC / INCLUDE
    public sealed class ImportSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            EdgeList E = c.Dep.Edges;
            ModuleResolver mr = new ModuleResolver(k);
            c.Progress("[16/19] Semantic dependencies...");
            c.L("==== [16] SEMANTIC DEPENDENCIES ====");
            c.L(" Evidence : fact      = written explicitly in the source (import, script src, exec, template ...)");
            c.L("            match     = resolved by a rule (http route + method, sql table name, file reference + key use)");
            c.L("            candidate = heuristic (config key name, symbol name, http path without method). Check before concluding.");
            c.L("            weak      = kept for reference, probably not a dependency (object.property, generic key name only)");
            c.L("            external  = target is not in the scanned folder (library, missing file, outside data ...)");
            c.L();
            c.L("---- [16-1] IMPORT / EXEC / INCLUDE (module, script, template, static file) ----");
            c.L(" Resolve : internal = file in scanned folder / ambiguous = several files / external = not in folder");
            List<string[]> rows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Imp == null || sm.Imp.Count == 0) continue;
                string self = x.No.ToString();
                foreach (string[] r in sm.Imp) {
                    string kind = r[0], mod = r[1];
                    string et = "IMPORT";
                    if (kind == "exec" || kind == "dot-source") et = "EXEC";
                    else if (kind == "template" || kind == "src/href" || kind == "static-file" || kind == "css-url") et = "INCLUDE";
                    List<string> tn;
                    if (sm.Lang == "py" && kind == "from" && mod.StartsWith(".")) tn = ModuleResolver.Unique(mr.ResolveRelPy(self, mod, r[2]));
                    else {
                        tn = ModuleResolver.Unique(mr.ResolveMod(sm.Lang, kind, mod, self));
                        if (sm.Lang == "py" && kind == "from" && !string.IsNullOrEmpty(r[2])) {
                            string[] sp = mod.Split('.'); string pkgLast = sp[sp.Length - 1];
                            List<string> subHit = new List<string>();
                            foreach (string nm0 in r[2].Split(',')) {
                                string n1 = ModuleResolver.StripAlias(nm0);
                                if (n1.Length == 0 || n1 == "*") continue;
                                foreach (FileEntry y in k.Fx)
                                    if (y.No != x.No && string.Equals(y.File.Name, n1 + ".py", StringComparison.OrdinalIgnoreCase)
                                        && string.Equals(y.File.Directory.Name, pkgLast, StringComparison.OrdinalIgnoreCase)) subHit.Add(y.No.ToString());
                            }
                            if (subHit.Count > 0) tn = ModuleResolver.Unique(subHit);
                        }
                    }
                    string det = kind + " " + mod; if (!string.IsNullOrEmpty(r[2])) det = det + " : " + r[2];
                    string res, tno, tp;
                    if (tn.Count == 0) {
                        res = "external"; tno = "-"; tp = "-";
                        E.Add(et, self, "", det, r[3], "external");
                    } else {
                        res = tn.Count > 1 ? "ambiguous" : "internal";
                        foreach (string t in tn) E.Add(et, self, t, det, r[3], "fact");
                        tno = string.Join(",", tn.ToArray());
                        List<string> ps = new List<string>(); foreach (string t in tn) ps.Add(k.FP(t));
                        tp = string.Join(" ; ", ps.ToArray());
                    }
                    rows.Add(new string[] { self, x.Display, sm.Lang, kind, LinkTool.Clean(mod), LinkTool.Clean(r[2]), r[3], res, tno, tp });
                }
            }
            if (rows.Count == 0) c.L("(no import / exec / include found)");
            c.Report.Tsv("imports", new string[] { "No", "Path", "Lang", "Kind", "Module", "Names", "Loc", "Resolve", "TargetNo", "TargetPath" }, rows);
            c.L();
        }
    }

    // [16-2] HTTP ROUTES (server side)
    public sealed class RouteSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            c.L("---- [16-2] HTTP ROUTES / COMMANDS (server side : flask, fastapi, express, actix, tauri) ----");
            List<string[]> rows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Rt == null || sm.Rt.Count == 0) continue;
                foreach (string[] r in sm.Rt) {
                    RouteInfo ri = new RouteInfo(); ri.No = x.No; ri.Method = r[0]; ri.Path = r[1]; ri.Handler = r[2]; ri.Loc = r[3];
                    c.Dep.Routes.Add(ri);
                    rows.Add(new string[] { x.No.ToString(), x.Display, r[0], r[1], r[2], r[3] });
                }
            }
            if (rows.Count == 0) c.L("(no route found)");
            c.Report.Tsv("http_routes", new string[] { "No", "Path", "Method", "Route", "Handler", "Loc" }, rows);
            c.L();
        }
    }
}
