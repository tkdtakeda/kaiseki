using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using FolderScan.Core;

namespace FolderScan.Analysis {
    // Finds the files of the scanned folder that a module / file name points to
    // (functions NameIds / SuffixNameIds / ResolveRelPy / ResolveMod of v5.18).
    public sealed class ModuleResolver {
        static readonly Regex AsAlias = new Regex(@"\s+as\s+.*$", RegexOptions.IgnoreCase);
        static readonly Regex HasExt = new Regex(@"\.[A-Za-z0-9]+$");
        static readonly Regex SuffixExt = new Regex(@"\.[A-Za-z0-9]{1,8}$");
        static readonly Dictionary<string, string[]> Exts = new Dictionary<string, string[]>();
        static ModuleResolver() {
            Exts["js"] = new string[] { ".js", ".ts", ".mjs", ".jsx", ".tsx", ".vue" };
            Exts["html"] = new string[] { ".js", ".ts", ".mjs", ".css", ".html" };
            Exts["css"] = new string[] { ".css" };
            Exts["rs"] = new string[] { ".rs" };
            Exts["cs"] = new string[] { ".cs" };
            Exts["java"] = new string[] { ".java", ".kt" };
            Exts["ps"] = new string[] { ".ps1", ".psm1", ".psd1" };
            Exts["vb"] = new string[] { ".bas", ".cls", ".vb" };
            Exts["bat"] = new string[] { ".bat", ".cmd", ".ps1", ".py", ".exe" };
            Exts["py"] = new string[] { ".py", ".pyw" };
        }

        readonly LinkState k;
        readonly Dictionary<string, string> initDir = new Dictionary<string, string>();          // folder name -> __init__.py Nos
        readonly Dictionary<string, string> byFull = new Dictionary<string, string>();           // lower full path -> No

        public ModuleResolver(LinkState k) {
            this.k = k;
            foreach (FileEntry x in k.Fx) {
                if (string.Equals(x.File.Name, "__init__.py", StringComparison.OrdinalIgnoreCase)) {
                    string dn = x.File.Directory.Name.ToLowerInvariant();
                    string v;
                    initDir[dn] = initDir.TryGetValue(dn, out v) ? v + "," + x.No : x.No.ToString();
                }
                byFull[x.File.FullName.ToLowerInvariant()] = x.No.ToString();
            }
        }

        static bool NotSelf(string v, string self) { return v.Length > 0 && !string.Equals(v, self, StringComparison.OrdinalIgnoreCase); }

        public static string StripAlias(string nm) { return AsAlias.Replace(nm, "").Trim(); }

        // Files whose name equals n (lower case match), without self.
        public List<string> NameIds(string n, string self) {
            List<string> o = new List<string>();
            string k2 = (n ?? "").ToLowerInvariant();
            string v;
            if (k2.Length > 0 && k.Names.TryGetValue(k2, out v)) foreach (string t in v.Split(',')) if (NotSelf(t, self)) o.Add(t);
            return o;
        }

        // Files whose name ends with leaf (prefix of at most 24 chars), leaf >= 8 chars with an extension.
        public List<string> SuffixNameIds(string leaf, string self) {
            List<string> o = new List<string>();
            if (string.IsNullOrEmpty(leaf) || leaf.Length < 8 || !SuffixExt.IsMatch(leaf)) return o;
            string ll = leaf.ToLowerInvariant();
            foreach (FileEntry x in k.Fx) {
                if (x.No.ToString() == self) continue;
                int d = x.File.Name.Length - leaf.Length;
                if (d > 0 && d <= 24 && x.File.Name.ToLowerInvariant().EndsWith(ll)) o.Add(x.No.ToString());
            }
            return o;
        }

        // python "from .x import y" : resolved by folder position
        public List<string> ResolveRelPy(string self, string mod, string names) {
            List<string> o = new List<string>();
            FileEntry q = k.ByNo(self);
            int dots = 0; while (dots < mod.Length && mod[dots] == '.') dots++;
            string bas = q.File.DirectoryName;
            for (int i = 1; i < dots; i++) { bas = Path.GetDirectoryName(bas); if (string.IsNullOrEmpty(bas)) return o; }
            string rest = mod.Substring(dots);
            if (rest.Length > 0) bas = Path.Combine(bas, rest.Replace('.', Path.DirectorySeparatorChar));
            List<string> cands = new List<string>();
            string[] parts = (names ?? "").Split(',');
            if (rest.Length > 0) {
                List<string> sub = new List<string>();
                foreach (string nm0 in parts) {
                    string n1 = StripAlias(nm0);
                    if (n1.Length == 0 || n1 == "*") continue;
                    string c1 = Path.Combine(bas, n1 + ".py"), c2 = Path.Combine(Path.Combine(bas, n1), "__init__.py");
                    if (byFull.ContainsKey(c1.ToLowerInvariant())) sub.Add(c1); else if (byFull.ContainsKey(c2.ToLowerInvariant())) sub.Add(c2);
                }
                if (sub.Count > 0) cands = sub; else { cands.Add(bas + ".py"); cands.Add(Path.Combine(bas, "__init__.py")); }
            } else {
                foreach (string nm0 in parts) {
                    string n1 = StripAlias(nm0);
                    if (n1.Length == 0 || n1 == "*") continue;
                    cands.Add(Path.Combine(bas, n1 + ".py")); cands.Add(Path.Combine(Path.Combine(bas, n1), "__init__.py"));
                }
                if (cands.Count > 0) {
                    bool hit = false;
                    foreach (string c in cands) if (byFull.ContainsKey(c.ToLowerInvariant())) { hit = true; break; }
                    if (!hit) { cands = new List<string>(); cands.Add(Path.Combine(bas, "__init__.py")); }
                }
            }
            foreach (string c in cands) {
                string v;
                if (byFull.TryGetValue(c.ToLowerInvariant(), out v) && !string.Equals(v, self, StringComparison.OrdinalIgnoreCase)) o.Add(v);
            }
            return o;
        }

        public List<string> ResolveMod(string lang, string kind, string mod, string self) {
            List<string> r = new List<string>();
            string m0 = (mod ?? "").Trim();
            if (m0.Length == 0) return r;
            if (lang == "py" && (kind == "import" || kind == "from")) {
                string b0 = m0.TrimStart('.');
                if (b0.Length == 0) return r;
                string[] sp = b0.Split('.'); string last = sp[sp.Length - 1];
                r.AddRange(NameIds(last + ".py", self));
                r.AddRange(NameIds(last + ".pyw", self));
                string v;
                if (initDir.TryGetValue(last.ToLowerInvariant(), out v)) foreach (string t in v.Split(',')) if (!string.Equals(t, self, StringComparison.OrdinalIgnoreCase)) r.Add(t);
                return r;
            }
            string bn = SemTool.BaseName(m0);
            if (string.IsNullOrEmpty(bn)) return r;
            r.AddRange(NameIds(bn, self));
            if (r.Count > 0) return r;
            string[] ex;
            if (!HasExt.IsMatch(bn) && Exts.TryGetValue(lang ?? "", out ex)) {
                foreach (string e0 in ex) r.AddRange(NameIds(bn + e0, self));
                if (r.Count == 0 && lang == "js" && (m0.StartsWith(".") || m0.StartsWith("/"))) {
                    foreach (FileEntry x in k.Fx)
                        if (string.Equals(Path.GetFileNameWithoutExtension(x.File.Name), "index", StringComparison.OrdinalIgnoreCase)
                            && string.Equals(x.File.Directory.Name, bn, StringComparison.OrdinalIgnoreCase) && x.No.ToString() != self) r.Add(x.No.ToString());
                }
            }
            return r;
        }

        // Select-Object -Unique (case-sensitive, first occurrence) after dropping empty items
        public static List<string> Unique(IEnumerable<string> l) {
            List<string> o = new List<string>(); HashSet<string> h = new HashSet<string>(StringComparer.Ordinal);
            foreach (string s in l) if (!string.IsNullOrEmpty(s) && h.Add(s)) o.Add(s);
            return o;
        }

        // PowerShell -like (wildcards * ? [..], case-insensitive). Invalid pattern = no match.
        public static bool Like(string text, string pattern) {
            Regex r;
            try { r = new Regex(WildcardToRegex(pattern), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline); }
            catch (ArgumentException) { return false; }
            return r.IsMatch(text);
        }

        static string WildcardToRegex(string p) {
            StringBuilder sb = new StringBuilder("^");
            for (int i = 0; i < p.Length; i++) {
                char ch = p[i];
                if (ch == '`' && i + 1 < p.Length) { sb.Append(Regex.Escape(p[++i].ToString())); continue; }
                if (ch == '*') sb.Append(".*");
                else if (ch == '?') sb.Append('.');
                else if (ch == '[') {
                    int j = p.IndexOf(']', i + 1);
                    if (j < 0) throw new ArgumentException("bad wildcard");
                    sb.Append('[').Append(p.Substring(i + 1, j - i - 1).Replace("\\", "\\\\")).Append(']');
                    i = j;
                } else sb.Append(Regex.Escape(ch.ToString()));
            }
            return sb.Append('$').ToString();
        }
    }
}
