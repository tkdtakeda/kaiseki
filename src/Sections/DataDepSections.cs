using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [16-4] CONFIG / JSON KEY USE
    public sealed class ConfigKeySection : IReportSection {
        sealed class User { public List<string> Keys = new List<string>(); public int SpecA; public int SpecL; }

        public void Write(ScanContext c) {
            LinkState k = c.Link;
            EdgeList E = c.Dep.Edges;
            c.L("---- [16-4] CONFIG / JSON KEY USE ----");
            c.L(" UsedByNo  = source files that contain the key as a quoted string (same as v4, kept)");
            c.L(" AccessNo  = source files that access the key : x[\"key\"] / .get(\"key\") / getattr(x, \"key\") ...");
            c.L(" Generic   = key name in GENERICKEYS (common word, low evidence)");
            c.L(" Edge evidence per (code file, json file) :");
            c.L("   match     = code file writes the json file name ([11]) and uses its keys");
            c.L("   candidate = no file name, but specific keys are accessed (1+) or written (2+)");
            c.L("   weak      = only generic keys or a single specific literal (kept, probably coincidence)");
            List<string[]> rows = new List<string[]>();
            List<SemItem> codeX = new List<SemItem>();
            foreach (FileEntry x in k.Fx) { SemItem s0; if (k.Sem.TryGetValue(x.No, out s0) && s0.Lit != null) codeX.Add(s0); }
            HashSet<string> generic = new HashSet<string>(c.Settings.GenericKeys, StringComparer.OrdinalIgnoreCase);
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.JK == null || sm.JK.Count == 0) continue;
                Hashtable byUser = PsHash.New();   // iteration order = v5.18
                foreach (string[] r in sm.JK) {
                    string key = r[0];
                    bool gen = generic.Contains(key.ToLowerInvariant());
                    List<string> users = new List<string>(), accs = new List<string>();
                    foreach (SemItem sc in codeX) {
                        if (sc.No == x.No) continue;
                        bool isL = sc.Lit.Contains(key);
                        bool isA = sc.Acc != null && sc.Acc.Contains(key);
                        if (isL) users.Add(sc.No.ToString());
                        if (isA) accs.Add(sc.No.ToString());
                        if (isL || isA) {
                            User bu = (User)byUser[sc.No];
                            if (bu == null) { bu = new User(); byUser[sc.No] = bu; }
                            bu.Keys.Add(key);
                            if (!gen) { if (isA) bu.SpecA++; else if (isL) bu.SpecL++; }
                        }
                    }
                    rows.Add(new string[] { x.No.ToString(), x.Display, key, r[1], r[2], users.Count > 0 ? string.Join(",", users.ToArray()) : "(not found in code)", accs.Count > 0 ? string.Join(",", accs.ToArray()) : "-", gen ? "yes" : "no" });
                }
                foreach (object kk in byUser.Keys) {
                    User bu = (User)byUser[kk];
                    string ex = string.Join(" ", bu.Keys.GetRange(0, Math.Min(8, bu.Keys.Count)).ToArray());
                    string ev, why;
                    if (k.RefPair.Contains(kk + "|" + x.No)) { ev = "match"; why = "file name written"; }
                    else if (bu.SpecA >= 1 || bu.SpecL >= 2) { ev = "candidate"; why = "specific keys"; }
                    else { ev = "weak"; why = "generic or single key only"; }
                    E.Add("CONFIG", kk.ToString(), x.No.ToString(), "keys=" + bu.Keys.Count + " specific-access=" + bu.SpecA + " specific-literal=" + bu.SpecL + " (" + why + ") e.g. " + ex, "", ev);
                }
            }
            if (rows.Count == 0) c.L("(no json key found)");
            c.Report.Tsv("config_keys", new string[] { "JsonNo", "JsonPath", "Key", "Count", "FirstLoc", "UsedByNo", "AccessNo", "Generic" }, rows);
            c.L();
        }
    }

    // [16-5] SQL OBJECTS
    public sealed class SqlSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            EdgeList E = c.Dep.Edges;
            c.L("---- [16-5] SQL OBJECTS (CREATE TABLE/VIEW/INDEX/TRIGGER = DEF, FROM/JOIN/INTO/UPDATE = REF) ----");
            c.L(" DEF is also taken from ASCII strings of binary files (e.g. sqlite_master of SQLite db).");
            c.L(" REF in non-sql source is taken only when the keyword is UPPER case (to avoid normal sentences).");
            c.L(" Resolved = file that defines the table, or file whose base name equals the table name.");
            Dictionary<string, List<string>> tblDef = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Sql == null) continue;
                foreach (string[] r in sm.Sql) {
                    if (r[0] != "DEF") continue;
                    string tk = r[2].ToLowerInvariant();
                    List<string> l;
                    if (!tblDef.TryGetValue(tk, out l)) { l = new List<string>(); tblDef[tk] = l; }
                    if (!l.Contains(x.No.ToString())) l.Add(x.No.ToString());
                }
            }
            List<string[]> rows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Sql == null || sm.Sql.Count == 0) continue;
                string self = x.No.ToString();
                foreach (string[] r in sm.Sql) {
                    string res = "-";
                    if (r[0] == "REF") {
                        List<string> tn = new List<string>();
                        List<string> defs;
                        if (tblDef.TryGetValue(r[2].ToLowerInvariant(), out defs)) foreach (string t in defs) if (!string.Equals(t, self, StringComparison.OrdinalIgnoreCase)) tn.Add(t);
                        foreach (FileEntry y in k.Fx)
                            if (y.No != x.No && string.Equals(Path.GetFileNameWithoutExtension(y.File.Name), r[2], StringComparison.OrdinalIgnoreCase)) tn.Add(y.No.ToString());
                        tn = ModuleResolver.Unique(tn);
                        if (tn.Count > 0) {
                            res = string.Join(",", tn.ToArray());
                            foreach (string t in tn) E.Add("SQL", self, t, r[1] + " " + r[2], r[3], "match");
                        } else if (r[2].Length <= 1) {
                            res = "(alias-like; not resolved)";
                            E.Add("SQL", self, "", "alias-like " + r[1] + " " + r[2], r[3], "weak");
                        } else {
                            res = "(not in folder)";
                            E.Add("SQL", self, "", "table " + r[2], r[3], "external");
                        }
                    }
                    rows.Add(new string[] { self, x.Display, r[0], r[1], r[2], r[3], res });
                }
            }
            if (rows.Count == 0) c.L("(no sql object found)");
            c.Report.Tsv("sql_objects", new string[] { "No", "Path", "Kind", "Type", "Name", "Loc", "Resolved" }, rows);
            c.L();
        }
    }

    // [16-5a] DATABASE FILES / PAIRS   [16-5b] DATABASE REFERENCES
    public sealed class DatabaseSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            EdgeList E = c.Dep.Edges;
            c.L("---- [16-5a] DATABASE FILES / PAIRS ----");
            c.L(" DBType : sqlserver-data / sqlserver-log / sqlite / access / generic-db");
            c.L(" Pair   : MDF and *_log.LDF with the same folder/base are paired. Pairing proves file-set structure, not table usage.");
            Dictionary<string, List<FileEntry>> dbMap = new Dictionary<string, List<FileEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (FileEntry d0 in k.DbX) {
                string key = DbRules.Key(d0);
                List<FileEntry> l;
                if (!dbMap.TryGetValue(key, out l)) { l = new List<FileEntry>(); dbMap[key] = l; }
                l.Add(d0);
            }
            List<string[]> dbRows = new List<string[]>();
            HashSet<string> pairSeen = new HashSet<string>();
            foreach (FileEntry d0 in k.DbX) {
                string role = DbRules.Role(d0), pairNo = "-", pairPath = "-", status = "standalone", ev = "extension";
                if (role == "sqlserver-data" || role == "sqlserver-log") {
                    string want = role == "sqlserver-data" ? ".ldf" : ".mdf";
                    FileEntry mate = null;
                    foreach (FileEntry m in dbMap[DbRules.Key(d0)]) if (m.No != d0.No && m.Ext == want) { mate = m; break; }
                    if (mate != null) {
                        pairNo = mate.No.ToString(); pairPath = mate.Display; status = "paired"; ev = "same-folder-base+extension";
                        string pks = Math.Min(d0.No, mate.No) + "|" + Math.Max(d0.No, mate.No);
                        if (pairSeen.Add(pks)) E.Add("DBFILE", d0.No.ToString(), mate.No.ToString(), "database-pair " + role + " <-> " + DbRules.Role(mate), "", "fact");
                    } else status = "pair-missing";
                }
                dbRows.Add(new string[] { d0.No.ToString(), d0.Display, role, pairNo, pairPath, d0.File.Length.ToString(), status, ev });
            }
            if (dbRows.Count == 0) c.L("(no database file found)");
            c.Report.Tsv("database_files", new string[] { "No", "Path", "DBType", "PairNo", "PairPath", "Bytes", "Status", "Evidence" }, dbRows);
            c.L();

            c.L("---- [16-5b] DATABASE REFERENCES / CONNECTION INDICATORS ----");
            c.L(" Values after connection keys are intentionally not emitted. Indicator/file-name evidence only.");
            List<string[]> refRows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                // hits were collected in [10] while the content was read (same units as v5.18)
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.DbHits == null) continue;
                foreach (DbHit h in sm.DbHits) {
                    if (!h.IsFile) refRows.Add(new string[] { x.No.ToString(), x.Display, h.Loc, "indicator", h.Value, "candidate", "value-masked" });
                    else {
                        refRows.Add(new string[] { x.No.ToString(), x.Display, h.Loc, "db-file", h.Value, "fact", "No." + h.DbNo });
                        E.Add("DBREF", x.No.ToString(), h.DbNo.ToString(), "database file " + h.Value, h.Loc, "fact");
                    }
                }
            }
            if (refRows.Count == 0) c.L("(no database reference / connection indicator found)");
            c.Report.Tsv("database_references", new string[] { "No", "Path", "Loc", "Kind", "IndicatorOrFile", "Evidence", "TargetOrNote" }, refRows);
            c.L();
        }
    }
}
