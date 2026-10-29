using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace FolderScan.Analysis {
    // Layer 1 of the analysis : language independent. Every text line / binary string is
    // searched for resources outside the scanned folder (url, unc / absolute path,
    // registry key, environment variable, ip address). Works on any file format.
    public static class GenericScanner {
        sealed class Rule { public string Kind; public Regex Rx; public int Group; }
        static readonly List<Rule> Rules = new List<Rule>();
        static readonly Regex Secret = new Regex(@"(?i)((?:password|passwd|pwd|pass|secret|token|apikey|api_key)\s*[:=]\s*)[^;&\s""']+|(//[^/:@\s""']+:)[^@/\s""']+@");
        static readonly TimeSpan T = TimeSpan.FromSeconds(1);

        static void Add(string kind, string rx, int group) {
            Rule r = new Rule(); r.Kind = kind; r.Rx = new Regex(rx, RegexOptions.CultureInvariant, T); r.Group = group; Rules.Add(r);
        }

        static GenericScanner() {
            Add("url", @"\b((?:https?|ftp|file)://[^\s""'<>()\[\]{}|\\^`]+)", 1);
            Add("unc-path", @"(?<![\\\w])(\\\\[A-Za-z0-9_.$\-]+\\[^\s""'<>|*?;,]+)", 1);
            Add("absolute-path", @"(?<![\w/\\])([A-Za-z]:\\[^\s""'<>|*?;,]*[^\s""'<>|*?;,.\\])", 1);
            Add("registry", @"\b((?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR)\\[^\s""'<>|;,]+)", 1);
            Add("env-var", @"(?:%([A-Za-z_][A-Za-z0-9_]{1,40})%|\$env:([A-Za-z_][A-Za-z0-9_]{1,40})|environ(?:\.get\(|\[)\s*[""']([A-Za-z_][A-Za-z0-9_]{1,40})|getenv\(\s*[""']([A-Za-z_][A-Za-z0-9_]{1,40})|Environment\.GetEnvironmentVariable\(\s*""([A-Za-z_][A-Za-z0-9_]{1,40}))", -1);
            Add("ip-address", @"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])", 1);
        }

        // kind, value, hits, firstLoc
        public static List<string[]> Scan(List<Unit> u, List<string> timeouts) {
            Dictionary<string, string[]> d = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            List<string> order = new List<string>();
            foreach (Unit x in u) {
                foreach (Rule r in Rules) {
                    MatchCollection mc;
                    try { mc = r.Rx.Matches(x.Text); if (mc.Count == 0) continue; }
                    catch (RegexMatchTimeoutException) { if (timeouts != null && timeouts.Count < 200) timeouts.Add(x.Loc); continue; }
                    foreach (Match m in mc) {
                        string v = Value(r, m);
                        if (v.Length == 0 || Noise(r.Kind, v, x.Text, m.Index)) continue;
                        v = Mask(v);
                        if (v.Length > 200) v = v.Substring(0, 200) + "..";
                        string key = r.Kind + "|" + v;
                        string[] e;
                        if (!d.TryGetValue(key, out e)) { e = new string[] { r.Kind, v, "0", x.Loc }; d[key] = e; order.Add(key); }
                        e[2] = (int.Parse(e[2]) + 1).ToString();
                    }
                }
            }
            List<string[]> o = new List<string[]>();
            foreach (string k in order) o.Add(d[k]);
            return o;
        }

        static string Value(Rule r, Match m) {
            if (r.Group >= 0) return m.Groups[r.Group].Value.TrimEnd('.', ',', ')', ';', ':');
            for (int g = 1; g < m.Groups.Count; g++) if (m.Groups[g].Success) return m.Groups[g].Value;
            return "";
        }

        // version numbers look like ip addresses ; "C:\" alone is not a resource
        static bool Noise(string kind, string v, string line, int at) {
            if (kind == "ip-address") {
                if (v.StartsWith("0.") || v == "255.255.255.255") return true;
                int s = Math.Max(0, at - 12);
                string before = line.Substring(s, at - s).ToLowerInvariant();
                if (before.Contains("version") || before.Contains("ver") || before.EndsWith("v")) return true;
            }
            if (kind == "absolute-path" && v.Length <= 3) return true;
            return false;
        }

        public static string Mask(string v) { return Secret.Replace(v, delegate (Match m) { return m.Groups[1].Success ? m.Groups[1].Value + "***" : m.Groups[2].Value + "***@"; }); }
    }
}
