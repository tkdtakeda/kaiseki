using System;
using System.Collections.Generic;
using System.IO;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [11] EXPLICIT REFERENCES
    public sealed class ReferenceSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            c.Progress("[11/19] References...");
            c.L("==== [11] EXPLICIT REFERENCES (file name of another file is written in the source file) ====");
            c.L(" Basis text=found in text line / binstr=found in ASCII string of binary");
            c.L(" TargetNo with \",\" = same file name exists in several places (ambiguous)");
            List<string[]> rows = new List<string[]>();
            foreach (string[] r in k.Refs) {
                List<string> tp = new List<string>();
                foreach (string t in r[2].Split(',')) tp.Add(k.FP(t));
                rows.Add(new string[] { r[0], k.FP(r[0]), r[1], r[2], string.Join(" ; ", tp.ToArray()), r[3], r[4], r[5], r[6] });
            }
            if (rows.Count == 0) c.L("(no reference found)");
            c.Report.Tsv("references", new string[] { "SrcNo", "SrcPath", "Token", "TargetNo", "TargetPath", "Hits", "FirstLoc", "Basis", "Context" }, rows);
            c.L();
            foreach (string[] r in k.Refs) foreach (string t in r[2].Split(',')) k.RefPair.Add(r[0] + "|" + t);
        }
    }

    // [12] DATA LINKAGE (shared key values)
    public sealed class KeyLinkSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            c.Progress("[12/19] Data linkage (shared key values)...");
            c.L("==== [12] DATA LINKAGE (same candidate key values found in two files) ====");
            c.L(" Key = token of 6-32 chars containing a digit (lot No., order No., date, code ...)");
            c.L(" Keys found in more than " + c.Settings.KeyMaxFiles + " files are ignored for pairs (too common).");
            c.L(" This is a candidate. Check the examples before concluding a linkage.");
            c.L("Distinct keys : " + k.Keys.KeyCount);
            k.Pairs = k.Keys.Pairs(c.Settings.KeyMaxFiles, 5);
            List<string[]> rows = new List<string[]>();
            foreach (string[] p in k.Pairs) rows.Add(new string[] { p[0], k.FP(p[0]), p[1], k.FP(p[1]), p[2], p[3] });
            if (rows.Count == 0) c.L("(no shared key found)");
            c.Report.Tsv("key_pairs", new string[] { "NoA", "PathA", "NoB", "PathB", "SharedKeys", "Examples" }, rows);
            c.L();
            c.L("[keys shared by most files : top 50]");
            c.Report.Tsv("key_common", new string[] { "Key", "Files", "FileNo" }, k.Keys.Common(50));
            c.L();
        }
    }

    // [13] SAME CONTENT (SHA256) / SAME BASE NAME
    public sealed class SameFileSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            c.Progress("[13/19] Same content / same base name...");
            c.L("==== [13] SAME CONTENT (SHA256) / SAME BASE NAME ====");
            List<string[]> rows = new List<string[]>();
            List<FileEntry> hashed = new List<FileEntry>();
            foreach (FileEntry x in k.Fx) if (x.Sha != "-") hashed.Add(x);
            int gi = 0;
            foreach (KeyValuePair<string, List<FileEntry>> g in GroupInOrder(hashed, delegate (FileEntry x) { return x.Sha; })) {
                if (g.Value.Count < 2) continue;
                k.SameContent.Add(g.Value);
                gi++;
                foreach (FileEntry x in g.Value) rows.Add(new string[] { "S" + gi, x.No.ToString(), x.Display, g.Key });
            }
            if (c.Settings.HashAll != 1) c.L("(HASHALL=0 : not checked)");
            else if (rows.Count == 0) c.L("(no same content)");
            c.Report.Tsv("same_content", new string[] { "Group", "No", "Path", "SHA256" }, rows);
            c.L();

            List<string[]> rows2 = new List<string[]>();
            gi = 0;
            foreach (KeyValuePair<string, List<FileEntry>> g in GroupInOrder(k.Fx, BaseKey)) {
                if (g.Value.Count < 2 || g.Value.Count > 20) continue;
                k.SameBase.Add(g);
                if (DistinctExt(g.Value) < 2) continue;
                gi++;
                foreach (FileEntry x in g.Value) rows2.Add(new string[] { "B" + gi, x.No.ToString(), x.Display, g.Key });
            }
            c.L("[same base name, different extension (inferred pair such as data.dat / data.idx)]");
            if (rows2.Count == 0) c.L("(none)");
            c.Report.Tsv("same_basename", new string[] { "Group", "No", "Path", "BaseName" }, rows2);
            c.L();
        }

        public static string BaseKey(FileEntry x) { return Path.GetFileNameWithoutExtension(x.File.Name).ToLowerInvariant(); }

        public static int DistinctExt(List<FileEntry> l) {
            HashSet<string> h = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (FileEntry x in l) h.Add(x.Ext);
            return h.Count;
        }

        // Group-Object : groups in order of first appearance, case-insensitive key
        public static List<KeyValuePair<string, List<FileEntry>>> GroupInOrder(List<FileEntry> l, Func<FileEntry, string> key) {
            Dictionary<string, List<FileEntry>> d = new Dictionary<string, List<FileEntry>>(StringComparer.OrdinalIgnoreCase);
            List<KeyValuePair<string, List<FileEntry>>> r = new List<KeyValuePair<string, List<FileEntry>>>();
            foreach (FileEntry x in l) {
                string kk = key(x);
                List<FileEntry> g;
                if (!d.TryGetValue(kk, out g)) { g = new List<FileEntry>(); d[kk] = g; r.Add(new KeyValuePair<string, List<FileEntry>>(kk, g)); }
                g.Add(x);
            }
            return r;
        }
    }

    // [14] RELATION MAP PER FILE (summary of [11]-[13])
    public sealed class RelationMapSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            c.Progress("[14/19] Relation map...");
            c.L("==== [14] RELATION MAP PER FILE ====");
            c.L("  -> REF   this file writes the name of the other file (fact)");
            c.L("  <- REF   the other file writes the name of this file (fact)");
            c.L("  ?        same file name exists in several places (ambiguous)");
            c.L("  <> KEY   same key values in both files (candidate data linkage)");
            c.L("            top " + c.Settings.KeyTop + " per file, all pairs in [12]");
            c.L("  == SAME  identical content (SHA256)");
            c.L("  ~~ STEM  same base name, different extension (inferred)");
            c.L("  (import / exec / http / config / sql / symbol edges are in [16] and [17])");
            c.L();
            Dictionary<int, List<string>> adj = new Dictionary<int, List<string>>();
            foreach (string[] r in k.Refs) {
                string[] tn = r[2].Split(',');
                string amb = tn.Length > 1 ? "?" : "";
                foreach (string t in tn) {
                    Add(adj, Int(r[0]), "  -> REF" + amb + "  No." + t + "  " + k.FP(t) + "   [" + r[5] + " " + r[4] + ", hits=" + r[3] + "]");
                    Add(adj, Int(t), "  <- REF" + amb + "  No." + r[0] + "  " + k.FP(r[0]) + "   [" + r[5] + " " + r[4] + "]");
                }
            }
            Dictionary<int, int> kc = new Dictionary<int, int>();
            int top = c.Settings.KeyTop;
            foreach (string[] p in k.Pairs) {
                int a = Int(p[0]), b = Int(p[1]);
                if (Bump(kc, a, top)) Add(adj, a, "  <> KEY   No." + b + "  " + k.FP(b) + "   [shared=" + p[2] + "  e.g. " + p[3] + "]");
                if (Bump(kc, b, top)) Add(adj, b, "  <> KEY   No." + a + "  " + k.FP(a) + "   [shared=" + p[2] + "  e.g. " + p[3] + "]");
            }
            foreach (List<FileEntry> g in k.SameContent)
                foreach (FileEntry x in g) foreach (FileEntry y in g) if (x.No != y.No) Add(adj, x.No, "  == SAME  No." + y.No + "  " + y.Display);
            foreach (KeyValuePair<string, List<FileEntry>> g in k.SameBase) {
                if (SameFileSection.DistinctExt(g.Value) < 2) continue;
                foreach (FileEntry x in g.Value) foreach (FileEntry y in g.Value)
                    if (x.No != y.No && !string.Equals(x.File.Extension, y.File.Extension, StringComparison.OrdinalIgnoreCase)) Add(adj, x.No, "  ~~ STEM  No." + y.No + "  " + y.Display);
            }
            List<string> iso = new List<string>();
            foreach (FileEntry x in k.Fx) {
                List<string> l;
                if (adj.TryGetValue(x.No, out l)) {
                    c.L("[No." + x.No + "] " + x.Src + " " + x.Rel + "  (" + x.Kind + ", " + x.File.Length + " bytes)");
                    foreach (string s in l) c.L(s);
                    c.L();
                } else iso.Add(x.No.ToString());
            }
            c.L("[no relation found] No. " + string.Join(",", iso.ToArray()));
            c.L(" (files listed here may still have import / exec / http / config / sql edges, see [17])");
            c.L();
        }

        static int Int(string s) { int n; int.TryParse(s, out n); return n; }

        static void Add(Dictionary<int, List<string>> d, int n, string s) {
            List<string> l;
            if (!d.TryGetValue(n, out l)) { l = new List<string>(); d[n] = l; }
            l.Add(s);
        }

        static bool Bump(Dictionary<int, int> kc, int n, int top) {
            int v; kc.TryGetValue(n, out v);
            if (v >= top) return false;
            kc[n] = v + 1;
            return true;
        }
    }
}
