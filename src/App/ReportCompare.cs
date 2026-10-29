using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace FolderScan.App {
    // Migration check : compares two reports section by section
    // (old = v5.18 bat, new = this tool) and writes a readable result.
    //   folderscan.exe --compare <old scan_*.txt> <new scan_*.txt> [result.txt]
    // A section starts at a line "==== [n] ..." or "---- [n-m] ...".
    // Ignored : scan time line, trailing spaces.
    public static class ReportCompare {
        const int ShowMax = 5;

        public static int Run(string oldPath, string newPath, string outPath) {
            // drag and drop order is not fixed : the report made by this tool is "new"
            if (IsNewTool(oldPath) && !IsNewTool(newPath)) { string t = oldPath; oldPath = newPath; newPath = t; }
            if (string.IsNullOrEmpty(outPath)) outPath = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(newPath)), "compare_" + Path.GetFileNameWithoutExtension(newPath) + ".txt");
            List<KeyValuePair<string, List<string>>> a = Split(Read(oldPath));
            List<KeyValuePair<string, List<string>>> b = Split(Read(newPath));
            Dictionary<string, List<string>> bm = new Dictionary<string, List<string>>();
            foreach (KeyValuePair<string, List<string>> s in b) if (!bm.ContainsKey(s.Key)) bm[s.Key] = s.Value;
            HashSet<string> seen = new HashSet<string>();
            StringBuilder o = new StringBuilder();
            o.AppendLine("folderscan report compare");
            o.AppendLine(" old : " + oldPath);
            o.AppendLine(" new : " + newPath);
            o.AppendLine();
            int same = 0, diff = 0, missing = 0, added = 0;
            StringBuilder detail = new StringBuilder();
            foreach (KeyValuePair<string, List<string>> s in a) {
                if (!seen.Add(s.Key)) continue;
                List<string> nb;
                if (!bm.TryGetValue(s.Key, out nb)) { missing++; o.AppendLine("MISSING  " + s.Key + "  (" + s.Value.Count + " lines in old)"); continue; }
                string d = Diff(s.Value, nb);
                if (d == null) { same++; o.AppendLine("SAME     " + s.Key); }
                else { diff++; o.AppendLine("DIFF     " + s.Key); detail.AppendLine("######## " + s.Key).Append(d).AppendLine(); }
            }
            foreach (KeyValuePair<string, List<string>> s in b) {
                if (seen.Contains(s.Key)) continue;
                seen.Add(s.Key); added++;
                o.AppendLine("NEW      " + s.Key + "  (" + s.Value.Count + " lines in new)");
            }
            o.AppendLine();
            o.AppendLine("same=" + same + "  diff=" + diff + "  missing-in-new=" + missing + "  only-in-new=" + added);
            o.AppendLine();
            o.Append(detail);
            string text = o.ToString();
            if (!string.IsNullOrEmpty(outPath)) {
                File.WriteAllText(outPath, text, new UTF8Encoding(true));
                Console.WriteLine("compare result : " + outPath);
            }
            Console.WriteLine("same=" + same + "  diff=" + diff + "  missing-in-new=" + missing + "  only-in-new=" + added);
            return diff + missing == 0 ? 0 : 1;
        }

        static bool IsNewTool(string p) {
            using (StreamReader r = new StreamReader(p, Encoding.UTF8)) {
                for (int i = 0; i < 5; i++) { string s = r.ReadLine(); if (s == null) break; if (s.Contains("(C# port of")) return true; }
            }
            return false;
        }

        static List<string> Read(string p) {
            List<string> l = new List<string>();
            foreach (string s in File.ReadAllLines(p, Encoding.UTF8)) {
                if (s.StartsWith(" Scan time : ")) continue;
                l.Add(s.TrimEnd());
            }
            return l;
        }

        static bool IsHead(string s) {
            return (s.StartsWith("==== [") || s.StartsWith("---- [")) && s.IndexOf(']') > 0;
        }

        // key = "[n]" + title ; the banner before the first section is "(banner)"
        static List<KeyValuePair<string, List<string>>> Split(List<string> lines) {
            List<KeyValuePair<string, List<string>>> r = new List<KeyValuePair<string, List<string>>>();
            string key = "(banner)"; List<string> cur = new List<string>();
            foreach (string s in lines) {
                if (IsHead(s)) {
                    r.Add(new KeyValuePair<string, List<string>>(key, cur));
                    key = s.Substring(5, s.IndexOf(']') - 4);
                    cur = new List<string>();
                }
                cur.Add(s);
            }
            r.Add(new KeyValuePair<string, List<string>>(key, cur));
            return r;
        }

        // null = same ; otherwise counts and the first differing lines
        static string Diff(List<string> a, List<string> b) {
            int n = Math.Max(a.Count, b.Count), shown = 0, cnt = 0;
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < n; i++) {
                string x = i < a.Count ? a[i] : null, y = i < b.Count ? b[i] : null;
                if (x == y) continue;
                cnt++;
                if (shown < ShowMax) {
                    shown++;
                    sb.AppendLine("  line " + (i + 1) + " of section");
                    sb.AppendLine("    old: " + (x ?? "(none)"));
                    sb.AppendLine("    new: " + (y ?? "(none)"));
                }
            }
            if (cnt == 0) return null;
            return "  lines old=" + a.Count + " new=" + b.Count + "  differing lines=" + cnt + " (first " + shown + " shown)\r\n" + sb.ToString();
        }
    }
}
