using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [16-6] FILE NAMES WRITTEN IN FILES (incl. files NOT in the scanned folder)
    public sealed class FileTokenSection : IReportSection {
        static readonly Regex Wild = new Regex(@"[\*\?]");

        public void Write(ScanContext c) {
            LinkState k = c.Link;
            EdgeList E = c.Dep.Edges;
            ModuleResolver mr = new ModuleResolver(k);

            c.L("---- [16-6] FILE NAMES WRITTEN IN FILES (incl. files NOT in the scanned folder) ----");
            c.L(" Status  : internal(see [11]) = exists in folder / pattern-matched = wildcard name matched files");
            c.L("           external = not in the scanned folder (input data, missing file, runtime output ...)");
            c.L("           external-pattern = wildcard name with no match in folder / self = own file name");
            c.L("           internal-normalized = one unique file ends with the token; ambiguous-normalized = several do");
            c.L("           attr-like = only seen as object.property in code (e.g. request.json, it.cab) : kept, evidence weak");
            c.L("           suppressed = token kept in report, but not promoted to unresolved EXTFILE evidence");
            c.L(" Context : write-io = string on a line with file write/output api");
            c.L("           io = string on a line with other file api / path join (open, Path, glob, BASE / \"x\", send_file ...) ");
            c.L("           quoted = string literal / text = non-code file / plain = unquoted in code");
            c.L("           doc = python docstring / comment / attr = object.property (probably not a file)");

            List<string[]> rows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Ext == null || sm.Ext.Count == 0) continue;

                string self = x.No.ToString();
                string basis = sm.Text ? "text" : "binstr";

                foreach (string[] r in sm.Ext) {
                    string tok = r[0], leaf = SemTool.BaseName(tok), ctxS = r[3], best = r[4];
                    if (string.IsNullOrEmpty(leaf)) continue;

                    string ev0 = best == "attr" ? "weak" : "external";
                    List<string> mm;
                    string st;

                    if (Wild.IsMatch(leaf)) {
                        mm = new List<string>();
                        foreach (FileEntry y in k.Fx)
                            if (y.No != x.No && ModuleResolver.Like(y.File.Name, leaf)) mm.Add(y.No.ToString());

                        if (mm.Count > 0) {
                            st = "pattern-matched";
                            foreach (string t in mm)
                                E.Add("PATTERN", self, t, "pattern " + tok + " [" + best + "]", r[2], "match");
                        } else {
                            st = "external-pattern";
                            E.Add("EXTFILE", self, "", "pattern " + tok + " [" + best + "]", r[2], ev0);
                        }
                    } else {
                        mm = mr.NameIds(leaf, self);
                        if (mm.Count > 0) {
                            st = "internal(see [11])";
                        } else if (string.Equals(leaf, x.File.Name, StringComparison.OrdinalIgnoreCase)) {
                            st = "self";
                        } else {
                            List<string> sm2 = ModuleResolver.Unique(mr.SuffixNameIds(leaf, self));
                            if (sm2.Count == 1) {
                                mm = sm2;
                                st = "internal-normalized(unique-suffix)";
                                E.Add("FILEMATCH", self, sm2[0], "token=" + tok + " method=unique-suffix [" + best + "]", r[2], "match");
                            } else if (sm2.Count > 1) {
                                mm = sm2;
                                st = "ambiguous-normalized(suffix)";
                                foreach (string t in sm2)
                                    E.Add("FILEMATCH", self, t, "token=" + tok + " method=ambiguous-suffix [" + best + "]", r[2], "candidate");
                            } else {
                                string provenanceReason;
                                bool promote = TokenProvenance.ShouldCreateExternalEdge(x, tok, leaf, ctxS, best, out provenanceReason);
                                if (promote) {
                                    st = best == "attr" ? "attr-like" : "external";
                                    E.Add("EXTFILE", self, "", tok + " [" + best + "]", r[2], ev0);
                                } else {
                                    st = "suppressed(" + provenanceReason + ")";
                                }
                            }
                        }
                    }

                    rows.Add(new string[] {
                        self, x.Display, LinkTool.Clean(tok), r[1], r[2], basis, st,
                        mm.Count > 0 ? string.Join(",", mm.ToArray()) : "-", ctxS, best
                    });
                }
            }

            if (rows.Count == 0) c.L("(no file name found)");
            c.Report.Tsv("file_tokens", new string[] {
                "No", "Path", "Token", "Hits", "FirstLoc", "Basis", "Status", "MatchedNo", "Context", "BestContext"
            }, rows);
            c.L();
        }
    }

    // [16-7] SYMBOL USE ACROSS FILES
    public sealed class SymbolUseSection : IReportSection {
        static readonly Dictionary<string, string> Fam = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "py", "py" }, { "js", "js" }, { "html", "js" }, { "cs", "net" }, { "vb", "net" },
            { "java", "java" }, { "rs", "rs" }, { "ps", "ps" }, { "bat", "bat" }, { "sql", "sql" }
        };

        static readonly HashSet<string> Stop = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "main", "init", "self", "this", "data", "name", "path", "value", "values", "items", "keys", "load", "save", "open", "close",
            "status", "start", "stop", "test", "list", "dict", "text", "file", "files", "type", "info", "error", "result", "args",
            "kwargs", "true", "false", "none", "null", "return", "function", "const", "async", "await", "class", "import", "from",
            "index", "count", "item", "node", "size", "time", "date", "line", "temp", "json", "html", "string", "object"
        };

        static readonly HashSet<string> SkipKind = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "label", "var", "top-var", "method/inner-def"
        };

        public void Write(ScanContext c) {
            LinkState k = c.Link;
            EdgeList E = c.Dep.Edges;
            int symMin = c.Settings.SymMin;

            c.L("---- [16-7] SYMBOL USE ACROSS FILES (name defined in one file appears in another file of the same language family, name length >= " + symMin + ") ----");
            c.L(" Candidate : same name may be a different thing. Combine with [16-1] import to confirm.");

            Hashtable defs = PsHash.New(); // "family|name" -> List<string> of file Nos ; iteration order = v5.18
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Sym == null || sm.Sym.Count == 0 || !Fam.ContainsKey(sm.Lang)) continue;
                foreach (string[] r in sm.Sym) {
                    if (SkipKind.Contains(r[0])) continue;
                    string nm = r[1];
                    if (nm.Length < symMin || Stop.Contains(nm.ToLowerInvariant())) continue;
                    string dk = Fam[sm.Lang] + "|" + nm;
                    List<string> l = (List<string>)defs[dk];
                    if (l == null) { l = new List<string>(); defs[dk] = l; }
                    if (!l.Contains(x.No.ToString())) l.Add(x.No.ToString());
                }
            }

            List<string[]> rows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Idn == null || !Fam.ContainsKey(sm.Lang)) continue;
                string f0 = Fam[sm.Lang], self = x.No.ToString();
                Hashtable use = PsHash.New();

                foreach (object o in defs.Keys) {
                    string dk = (string)o;
                    string[] pp = dk.Split('|');
                    if (!string.Equals(pp[0], f0, StringComparison.OrdinalIgnoreCase)) continue;
                    List<string> dl = (List<string>)defs[dk];
                    if (dl.Contains(self)) continue;
                    if (!sm.Idn.Contains(pp[1])) continue;

                    foreach (string d in dl) {
                        List<string> ul = (List<string>)use[d];
                        if (ul == null) { ul = new List<string>(); use[d] = ul; }
                        ul.Add(pp[1]);
                    }
                }

                foreach (object o in use.Keys) {
                    string d = (string)o;
                    List<string> ns = new List<string>((List<string>)use[d]);
                    StableSort(ns);
                    string ex = string.Join(" ", ns.GetRange(0, Math.Min(10, ns.Count)).ToArray());
                    rows.Add(new string[] { self, x.Display, d, k.FP(d), ns.Count.ToString(), string.Join(" ", ns.ToArray()) });
                    E.Add("SYM", self, d, "names=" + ns.Count + " e.g. " + ex, "", "candidate");
                }
            }

            if (rows.Count == 0) c.L("(no cross-file symbol use found)");
            c.Report.Tsv("symbol_use", new string[] { "UserNo", "UserPath", "DefNo", "DefPath", "Names", "NameList" }, rows);
            c.L();
        }

        // Sort-Object on strings (culture aware, case-insensitive, stable)
        public static void StableSort(List<string> l) {
            List<KeyValuePair<int, string>> t = new List<KeyValuePair<int, string>>();
            for (int i = 0; i < l.Count; i++) t.Add(new KeyValuePair<int, string>(i, l[i]));
            t.Sort(delegate (KeyValuePair<int, string> a, KeyValuePair<int, string> b) {
                int r = PathUtil.SortCmp.Compare(a.Value, b.Value);
                return r != 0 ? r : a.Key.CompareTo(b.Key);
            });
            for (int i = 0; i < l.Count; i++) l[i] = t[i].Value;
        }
    }
}
