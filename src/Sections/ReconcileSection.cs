using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [18] EVIDENCE RECONCILIATION (derived; raw evidence remains in [17-1])
    public sealed class ReconcileSection : IReportSection {
        static readonly Regex HttpUrl = new Regex(@"^[^ ]+ ([^ ]+) =>");
        static readonly Regex TokHead = new Regex(@"^(.+?) \[");
        // database file extensions (v5.18 had '^\\.' here, which never matched; fixed in v6.0)
        static readonly Regex DbExt = new Regex(@"^\.(sqlite|sqlite3|db|mdb|accdb)$", RegexOptions.IgnoreCase);
        static readonly HashSet<string> ManifestFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.toml", "cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts" };

        sealed class Rec {
            public string S, D; public int Score, N;
            public readonly Hashtable Types = PsHash.New(), Ev = PsHash.New(), Org = PsHash.New(), CoreTypes = PsHash.New(), CoreFam = PsHash.New(), CandFam = PsHash.New();
        }

        static void Inc(Hashtable h, string k) { object v = h[k]; h[k] = (v == null ? 0 : (int)v) + 1; }

        public void Write(ScanContext c) {
            ReconState rs = c.Recon;
            rs.Ext = new ExternalClassifier(c.Link);
            c.Progress("[18/19] Evidence reconciliation...");
            c.L("==== [18] EVIDENCE RECONCILIATION (derived; raw evidence remains in [17-1]) ====");
            c.L(" Production evidence = source-code/text-data facts and matches. test-code is retained but does not by itself prove runtime production flow.");
            c.L(" Resolution status uses cross-detector agreement and normalized filenames; no raw edge is deleted or rewritten.");
            c.L();
            Resolved(c);
            Conflicts(c);
            Unresolved(c);
            Architecture(c);
        }

        static List<string> SortedKeys(Hashtable h) {
            List<string> l = new List<string>(); foreach (object o in h.Keys) l.Add((string)o);
            SymbolUseSection.StableSort(l);
            return l;
        }

        // [18-1]
        static void Resolved(ScanContext c) {
            LinkState k = c.Link; ReconState rs = c.Recon;
            Dictionary<string, Rec> rec = new Dictionary<string, Rec>(StringComparer.OrdinalIgnoreCase);
            List<Rec> order = new List<Rec>();
            foreach (string[] e in c.Dep.Edges.Items) {
                if (e[2].Length == 0) continue;
                string pk = e[1] + "|" + e[2];
                Rec o;
                if (!rec.TryGetValue(pk, out o)) { o = new Rec(); o.S = e[1]; o.D = e[2]; rec[pk] = o; order.Add(o); }
                o.N++;
                Inc(o.Types, e[0]); Inc(o.Ev, e[5]); Inc(o.Org, e[6]);
                o.Score += ExternalClassifier.Weight(e);
                bool core = ExternalClassifier.IsCoreOrigin(e[6]);
                if (core && (e[5] == "fact" || e[5] == "match")) { Inc(o.CoreTypes, e[0]); Inc(o.CoreFam, ExternalClassifier.Family(e[0])); }
                else if (core && e[5] == "candidate") Inc(o.CandFam, ExternalClassifier.Family(e[0]));
            }
            c.L("---- [18-1] RESOLVED INTERNAL RELATIONS ----");
            c.L(" Families : name (REF FILEMATCH PATTERN) / code (IMPORT EXEC INCLUDE) / protocol (HTTP) / data (CONFIG SQL) /");
            c.L("            content (SAME) / symbol (SYM) / value (KEY) / stem (STEM)");
            c.L(" confirmed    = strong (fact/match) production evidence from 2+ independent families");
            c.L(" corroborated = strong evidence from 1 family + candidate evidence from another family");
            c.L(" supported    = strong evidence from 1 family only (e.g. REF + FILEMATCH = same family)");
            c.L(" candidate    = only heuristic / weak / test evidence");
            foreach (Rec o in order) {
                List<string> cfm = SortedKeys(o.CoreFam);
                List<string> xfm = new List<string>();
                foreach (string f in SortedKeys(o.CandFam)) if (!o.CoreFam.ContainsKey(f)) xfm.Add(f);
                string status = "candidate";
                if (cfm.Count >= 2) status = "confirmed";
                else if (cfm.Count == 1 && xfm.Count >= 1) status = "corroborated";
                else if (cfm.Count == 1) status = "supported";
                rs.Resolved.Add(new string[] { o.S, k.FP(o.S), o.D, k.FP(o.D), status, o.Score.ToString(), string.Join(" ", SortedKeys(o.CoreTypes).ToArray()),
                    Counts(o.Types, " x"), Counts(o.Org, "="), string.Join(" ", cfm.ToArray()), string.Join(" ", xfm.ToArray()) });
                rs.StatusCount.Inc(status);
            }
            c.Report.Tsv("resolved_relations", new string[] { "SrcNo", "SrcPath", "DstNo", "DstPath", "Status", "Score", "StrongDetectorTypes", "AllTypes", "Origins", "StrongFamilies", "CorroboratingFamilies" }, rs.Resolved);
            c.L();
            c.L("[status count]");
            c.Report.Tsv("resolved_status_count", new string[] { "Status", "Pairs" }, rs.StatusCount.Rows());
            c.L();
        }

        static string Counts(Hashtable h, string sep) {
            List<string> o = new List<string>();
            foreach (string key in SortedKeys(h)) o.Add(key + sep + h[key]);
            return string.Join(" ", o.ToArray());
        }

        // [18-2]
        static void Conflicts(ScanContext c) {
            LinkState k = c.Link; ReconState rs = c.Recon; List<string[]> edges = c.Dep.Edges.Items;
            c.L("---- [18-2] CONTRADICTIONS / COMPETING TARGETS ----");
            c.L(" conflict = same client url has multiple selected server targets, a file token fits several internal files,");
            c.L("            or a read-io file token is explained neither by an internal file nor by its context.");
            c.L(" comment / doc / attr / write-output / program / config / UI / runtime names are not conflicts;");
            c.L(" they are retained in file_signal_classification.");
            Hashtable hc = PsHash.New();   // iteration order = v5.18
            foreach (string[] e in edges) {
                if (e[0] != "HTTP" || e[2].Length == 0) continue;
                Match m = HttpUrl.Match(e[3]); if (!m.Success) continue;
                string key = e[1] + "|" + m.Groups[1].Value;
                List<string> l = (List<string>)hc[key];
                if (l == null) { l = new List<string>(); hc[key] = l; }
                if (!l.Contains(e[2])) l.Add(e[2]);
            }
            foreach (object o in hc.Keys) {
                List<string> l = (List<string>)hc[o];
                if (l.Count <= 1) continue;
                string[] pp = ((string)o).Split(new char[] { '|' }, 2);
                rs.Conflicts.Add(new string[] { "HTTP-AMBIGUOUS", pp[0], k.FP(pp[0]), pp[1], string.Join(",", l.ToArray()), "multiple selected server targets", "candidate" });
            }
            Dictionary<int, List<string[]>> refsBySrc = new Dictionary<int, List<string[]>>();
            foreach (string[] e in edges) {
                if (e[0] != "REF" || e[2].Length == 0) continue;
                int s = Int(e[1]); List<string[]> l;
                if (!refsBySrc.TryGetValue(s, out l)) { l = new List<string[]>(); refsBySrc[s] = l; }
                l.Add(e);
            }
            foreach (string[] e in edges) {
                if (e[0] != "EXTFILE" || e[2].Length > 0 || e[6] != "source-code") continue;
                Match tm = TokHead.Match(e[3]); if (!tm.Success) continue;
                string tok = SemTool.BaseName(tm.Groups[1].Value);
                List<string> expl = new List<string>();
                List<string[]> refs;
                if (refsBySrc.TryGetValue(Int(e[1]), out refs))
                    foreach (string[] re in refs) { FileEntry t = k.ByNo(re[2]); if (t != null && t.File.Name.ToLowerInvariant().EndsWith(tok.ToLowerInvariant())) expl.Add(re[2]); }
                expl = ModuleResolver.Unique(expl);
                if (expl.Count == 1) rs.FileRecon.Add(new string[] { e[1], k.FP(e[1]), tok, expl[0], k.FP(expl[0]), "explained-by-internal-REF", "not-a-conflict" });
                else if (expl.Count > 1) rs.Conflicts.Add(new string[] { "FILE-AMBIGUOUS", e[1], k.FP(e[1]), tok, string.Join(",", expl.ToArray()), "external token fits multiple internal REF targets", "candidate" });
                else {
                    string fcl = rs.Ext.Classify(e);
                    rs.FileClass.Add(new string[] { e[1], k.FP(e[1]), e[3], fcl, e[5], e[6], e[4] });
                    rs.FileClassCount.Inc(fcl);
                    if (fcl == "external-file") rs.Conflicts.Add(new string[] { "FILE-SIGNAL", e[1], k.FP(e[1]), e[3], "-", "read-io token not explained by internal file", "external" });
                }
            }
            if (rs.Conflicts.Count == 0) c.L("(none detected)");
            c.Report.Tsv("conflicts", new string[] { "Kind", "SrcNo", "SrcPath", "Subject", "TargetNo", "Reason", "Evidence" }, rs.Conflicts);
            c.L();
            c.L("[file signals explained by stronger internal REF evidence]");
            if (rs.FileRecon.Count == 0) c.L("(none)");
            c.Report.Tsv("file_signal_reconciliation", new string[] { "SrcNo", "SrcPath", "Token", "TargetNo", "TargetPath", "Resolution", "Status" }, rs.FileRecon);
            c.L();
            c.L("[file signals not explained by internal files : semantic class (all kept; only external-file is a conflict)]");
            if (rs.FileClass.Count == 0) c.L("(none)");
            c.Report.Tsv("file_signal_classification", new string[] { "SrcNo", "SrcPath", "Signal", "Class", "Evidence", "Origin", "Loc" }, rs.FileClass);
            c.L();
            c.L("[file signal class count]");
            c.Report.Tsv("file_signal_class_count", new string[] { "Class", "Signals" }, rs.FileClassCount.Rows());
            c.L();
        }

        static int Int(string s) { int n; int.TryParse(s, out n); return n; }

        // [18-3]
        static void Unresolved(ScanContext c) {
            LinkState k = c.Link; ReconState rs = c.Recon;
            c.L("---- [18-3] UNRESOLVED / EXTERNAL / AMBIGUOUS ----");
            foreach (string[] e in c.Dep.Edges.Items) {
                string reason = "";
                if (e[2].Length == 0) { if (e[5] == "external") reason = "external-target"; else if (e[5] == "weak") reason = "weak-external-signal"; }
                else if (e[5] == "candidate" || e[5] == "weak") reason = "internal-" + e[5];
                if (e[0] == "SQL" && e[5] == "weak" && e[2].Length == 0) reason = "sql-alias-like";
                if (reason.Length == 0) continue;
                string dp = "-", xc = "-";
                if (e[2].Length > 0) dp = k.FP(e[2]); else xc = rs.Ext.Classify(e);
                rs.Unresolved.Add(new string[] { reason, e[0], e[1], k.FP(e[1]), e[2], dp, e[3], e[5], e[6], xc });
                if (xc != "-") rs.ExtClassCount.Inc(xc);
            }
            if (rs.Unresolved.Count == 0) c.L("(none)");
            c.L(" ExternalClass : stdlib / third-party-declared / third-party-or-local-undeclared / local-module-missing /");
            c.L("                 platform-or-library / external-file / external-data-reference / configured-data-path /");
            c.L("                 output-file-candidate / runtime-file-candidate / runtime-work-file / archive-internal-part /");
            c.L("                 external-program / file-pattern /");
            c.L("                 ui-example-or-reference / documentation-mention / lexical-only / text-mention /");
            c.L("                 binary-embedded-name / external-table / sql-alias-like");
            c.L(" third-party-declared = root module name equals a package in requirements*.txt / pyproject.toml / package.json");
            c.L("                        (distribution and import names can differ; undeclared does not prove missing)");
            c.Report.Tsv("unresolved", new string[] { "Reason", "Type", "SrcNo", "SrcPath", "DstNo", "DstPath", "Detail", "Evidence", "Origin", "ExternalClass" }, rs.Unresolved);
            c.L();
            c.L("[external class count]");
            c.Report.Tsv("external_class_count", new string[] { "ExternalClass", "Edges" }, rs.ExtClassCount.Rows());
            c.L();
            c.L("[declared packages found in dependency manifests]");
            if (rs.Ext.DeclDeps.Count == 0) c.L("(none)");
            List<string[]> dd = new List<string[]>();
            foreach (string key in SortedKeys(rs.Ext.DeclDeps)) dd.Add(new string[] { key, (string)rs.Ext.DeclDeps[key] });
            c.Report.Tsv("declared_packages", new string[] { "NormalizedName", "Manifest" }, dd);
            c.L();
        }

        // [18-4]
        static void Architecture(ScanContext c) {
            LinkState k = c.Link; DepState d = c.Dep; ReconState rs = c.Recon;
            c.L("---- [18-4] ARCHITECTURE ROLES (derived from reconciled evidence) ----");
            c.L(" test-code/docs/vendor/binary evidence is preserved but does not promote production architecture roles.");
            foreach (FileEntry x in k.Fx) {
                SemItem sm; k.Sem.TryGetValue(x.No, out sm);
                List<string> rr = new List<string>(), why = new List<string>();
                string org = OriginRules.Of(x);
                if (org == "test-code") { rr.Add("test"); why.Add("origin=test-code"); }
                else if (org == "documentation") { rr.Add("documentation"); why.Add("origin=documentation"); }
                else if (org == "generated-vendor") { rr.Add("generated/vendor"); why.Add("origin=generated-vendor"); }
                else if (org == "binary-string") {
                    rr.Add("binary-artifact"); why.Add("origin=binary-string");
                    if (DbExt.IsMatch(x.Ext)) { rr.Add("datastore"); why.Add("database extension"); }   // real database files are binary
                }
                else {
                    if ((x.Lang == "bat" || x.Lang == "ps") && !d.HasT(d.InT, x.No, "EXEC")) { rr.Add("launcher"); why.Add("entry script"); }
                    if (sm != null && sm.Main) { rr.Add("application-entry"); why.Add("main"); }
                    if (sm != null && sm.Rt != null && sm.Rt.Count > 0) { rr.Add("web-api/server"); why.Add("server routes"); }
                    if (d.HasT(d.OutT, x.No, "HTTP")) { rr.Add("frontend/http-client"); why.Add("outgoing HTTP"); }
                    if (d.HasT(d.InT, x.No, "INCLUDE") && x.Lang == "html") { rr.Add("frontend-view"); why.Add("included HTML"); }
                    else if (d.HasT(d.InT, x.No, "INCLUDE")) { rr.Add("frontend/static-asset"); why.Add("included asset"); }
                    if (d.HasT(d.InT, x.No, "IMPORT")) { rr.Add("module/library"); why.Add("imported"); }
                    if (d.HasT(d.InT, x.No, "REF") && !d.HasT(d.InT, x.No, "IMPORT") && !d.HasT(d.InT, x.No, "INCLUDE")) { rr.Add("reference-source"); why.Add("referenced by production source"); }
                    if (ManifestFiles.Contains(x.File.Name)) { rr.Add("dependency-manifest"); why.Add("known manifest filename"); }
                    if (d.HasT(d.InT, x.No, "CONFIG")) { rr.Add("configuration"); why.Add("config edge"); }
                    if (sm != null && sm.Sql != null && HasDef(sm.Sql)) { rr.Add("datastore/schema"); why.Add("SQL definitions"); }
                    if (DbExt.IsMatch(x.Ext)) { rr.Add("datastore"); why.Add("database extension"); }
                }
                if (rr.Count == 0) rr.Add("unclassified");
                rs.ArchRows.Add(new string[] { x.No.ToString(), x.Display, org, string.Join(",", ModuleResolver.Unique(rr).ToArray()), string.Join("; ", ModuleResolver.Unique(why).ToArray()) });
            }
            c.Report.Tsv("architecture_roles", new string[] { "No", "Path", "Origin", "Roles", "EvidenceBasis" }, rs.ArchRows);
            c.L();
        }

        static bool HasDef(List<string[]> sql) { foreach (string[] r in sql) if (r[0] == "DEF") return true; return false; }
    }
}
