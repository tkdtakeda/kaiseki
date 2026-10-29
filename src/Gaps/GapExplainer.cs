using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Gaps {
    // EXPLAIN pass (v5.14 -) : probe evidence -> rule -> gap status "explained".
    // strong = evidence on the gap line or a traced definition ; weak = nearby / name-only.
    public sealed class GapExplainer {
        const RegexOptions I = RegexOptions.IgnoreCase;
        static readonly HashSet<string> WeakRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "shared-property-url", "dynamic-route-indirect", "basename-mentioned", "data-table", "documentation-or-template", "runtime-path-nearby", "url-in-variable", "bundled-package" };
        static readonly Dictionary<string, string> Bundle = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            { "werkzeug", "flask" }, { "jinja2", "flask" }, { "itsdangerous", "flask" }, { "click", "flask" }, { "markupsafe", "flask" }, { "blinker", "flask" }, { "starlette", "fastapi" }, { "pydantic", "fastapi" }, { "anyio", "httpx" } };
        static readonly Regex FlaskImport = new Regex(@"(^|\s)flask(\s|\.|$)", I);
        static readonly Regex Install = new Regex(@"(?i)(?:pip3?|python\s+-m\s+pip|py\s+-m\s+pip)\s+install\s+([^\r\n&|;""'<>]+)");
        static readonly Regex VersionTail = new Regex(@"[<>=!~\[].*$", I);
        static readonly Regex Spaces = new Regex(@"\s+");
        static readonly Regex Template = new Regex(@"^(.+?)\.(sample|example|template|dist|default|orig)(\.[A-Za-z0-9]+)?$", I);
        static readonly Regex MentionLine = new Regex(@"^\s+mention (?!:)", I);
        static readonly Regex ImportMention = new Regex(@" L\d+:\s*(from|import)\s", I);
        static readonly Regex CommentStart = new Regex(@"^(//|#|/\*|\*|<!--|' |rem\s|::|;)", I);
        static readonly Regex CtxStrip = new Regex(@"\s*\[[a-z\-]+\]\s*$", I);
        static readonly Regex ProbeLine = new Regex(@"^\s+(def \S+|call \S+|>|) ?L\d+: (.*)$");
        static readonly Regex RuntimeKw = new Regex(@"(?i)LOCALAPPDATA|\bAPPDATA\b|%TEMP%|\bTEMP\b|gettempdir|mkdtemp|tempfile|\.mkdir\s*\(|makedirs|\bruntime\b|_RUNTIME\b|local_root|cache_dir|tmp_dir|work_dir|\buuid", I);
        static readonly Regex RuntimeSkip = new Regex(@"(?i)^\s*(from|import)\s|\blog(ger|ging)?\.\w+\s*\(|\bprint\s*\(|\bconsole\.\w+\s*\(", I);
        static readonly Regex UseMethod = new Regex(@"^\s+use L\d+: .*\[method=([A-Z]+)\]");
        static readonly Regex RoutingFile = new Regex(@"^\s+routing (.+?) L\d+:");
        static readonly Regex LiteralFile = new Regex(@"^\s+url literal (.+?) L\d+:");
        static readonly Regex SampleExt = new Regex(@"\.sample$|\.example", I);
        static readonly Regex HeadSection = new Regex(@"^\s+head L\d+: \[[^\]]+\]\s*$", I);
        static readonly Regex HeadKeyValue = new Regex(@"^\s+head L\d+: [A-Za-z_][\w\.]*\s*=", I);

        readonly ScanContext c;
        readonly GapText t;
        public readonly OrderedDictionary Exr = new OrderedDictionary(StringComparer.CurrentCultureIgnoreCase);   // rule -> hits ([ordered]@{})
        public readonly Dictionary<string, string> Exc = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);   // rule -> confidence
        readonly bool flaskUsed;
        readonly Dictionary<string, string> installs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, Dictionary<string, int>> sig = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);

        public GapExplainer(ScanContext c, GapText t) {
            this.c = c; this.t = t;
            foreach (string[] e in c.Dep.Edges.Items) if (e[0] == "IMPORT" && FlaskImport.IsMatch(e[3])) { flaskUsed = true; break; }
            CollectInstalls();
            CollectSignatures();
        }

        LinkState K { get { return c.Link; } }

        // install instructions written anywhere in text files
        void CollectInstalls() {
            foreach (FileEntry q in K.Fx) {
                if (q.Kind != "text") continue;
                string[] arr = t.Lines(q.No);
                for (int i = 0; i < arr.Length; i++) {
                    Match mi = Install.Match(arr[i]);
                    if (!mi.Success) continue;
                    foreach (string p1 in Spaces.Split(mi.Groups[1].Value)) {
                        string p2 = VersionTail.Replace(p1, "").Trim().ToLowerInvariant();
                        if (p2.Length == 0 || p2.StartsWith("-")) continue;
                        if (!installs.ContainsKey(p2)) installs[p2] = q.Display + " L" + (i + 1) + ": " + t.Clip(arr[i]);
                    }
                }
            }
        }

        // first bytes per extension (consistent-signature rule)
        void CollectSignatures() {
            foreach (FileEntry q in K.Fx) {
                if (q.Kind != "binary") continue;
                byte[] b = new byte[8]; int r;
                try { using (FileStream fs = new FileStream(q.File.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) r = fs.Read(b, 0, 8); } catch { continue; }
                if (r < 4) continue;
                StringBuilder hx = new StringBuilder();
                for (int i = 0; i < r; i++) { if (i > 0) hx.Append(' '); hx.Append(b[i].ToString("X2")); }
                Dictionary<string, int> d;
                if (!sig.TryGetValue(q.Ext, out d)) { d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase); sig[q.Ext] = d; }
                int v; d.TryGetValue(hx.ToString(), out v); d[hx.ToString()] = v + 1;
            }
        }

        void Explain(Gap g, string rule, string ev, string conf) {
            if (g.Explained.Length > 0) return;
            if (string.IsNullOrEmpty(conf)) conf = WeakRules.Contains(rule) ? "weak" : "strong";
            g.Explained = rule; g.ExEv = t.Clip(ev); g.Conf = conf; Exc[rule] = conf;
            Exr[rule] = Exr.Contains(rule) ? (int)Exr[rule] + 1 : 1;
        }
        void Explain(Gap g, string rule, string ev) { Explain(g, rule, ev, ""); }

        static string FirstLine(Gap g, Regex rx) { foreach (string l in g.Out) if (rx.IsMatch(l)) return l; return ""; }
        static string FirstLine(Gap g, string rx) { return FirstLine(g, new Regex(rx, I)); }

        void MentionRule(Gap g) {
            Regex full = new Regex("(?i)" + Regex.Escape(K.ByNo(g.No).File.Name), I);
            List<string> real = new List<string>();
            foreach (string l in g.Out) if (MentionLine.IsMatch(l) && !ImportMention.IsMatch(l)) real.Add(l);
            string hf = null;
            foreach (string l in real) if (full.IsMatch(l)) { hf = l; break; }
            if (hf != null) Explain(g, "mentioned-in-other-file", hf);
            else if (real.Count > 0) Explain(g, "basename-mentioned", real[0]);
        }

        // first line of another text file that contains needle (and not exclude)
        string TextHit(string needle, int skipNo, string[] origins, string exclude) {
            if (string.IsNullOrEmpty(needle)) return "";
            foreach (FileEntry q in K.Fx) {
                if (q.Kind != "text" || q.No == skipNo) continue;
                if (origins != null && Array.IndexOf(origins, OriginRules.Of(q)) < 0) continue;
                string[] arr = t.Lines(q.No);
                for (int i = 0; i < arr.Length; i++) {
                    if (arr[i].IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    if (!string.IsNullOrEmpty(exclude) && arr[i].IndexOf(exclude, StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    return q.Display + " L" + (i + 1) + ": " + t.Clip(arr[i]);
                }
            }
            return "";
        }

        // template-of / superseded-by-sibling / naming-convention / folder-description
        void FileRules(Gap g) {
            if (g.Kind != "isolated-file" && g.Kind != "role-unclassified") return;
            if (g.No == null) return;
            FileEntry q = K.ByNo(g.No);
            string nm = q.File.Name, dir = q.File.DirectoryName, bn = Path.GetFileNameWithoutExtension(nm), ex = q.File.Extension;
            Match mt = Template.Match(nm);
            if (mt.Success) {
                string tgt = mt.Groups[1].Value + mt.Groups[3].Value;
                string h = TextHit(tgt, q.No, null, nm);
                if (h.Length > 0) { Explain(g, "template-of", "template of " + tgt + " ; " + h, "strong"); return; }
            }
            foreach (FileEntry sb in K.Fx) {
                if (sb.No == q.No || !Eq(sb.File.DirectoryName, dir) || !Eq(Path.GetFileNameWithoutExtension(sb.File.Name), bn)) continue;
                string h = TextHit(sb.File.Name, q.No, null, nm);
                if (h.Length == 0) continue;
                string ev = "sibling " + sb.File.Name + " is referenced : " + h;
                string d0 = TextHit("*" + ex, q.No, new string[] { "documentation", "text-data" }, null);
                if (d0.Length > 0) ev = ev + " | " + d0;
                Explain(g, "superseded-by-sibling", ev, "strong"); return;
            }
            string lit = TextHit("\"" + bn + "\"", q.No, new string[] { "source-code" }, null);
            if (lit.Length == 0) lit = TextHit("'" + bn + "'", q.No, new string[] { "source-code" }, null);
            if (lit.Length > 0 && ex.Length > 0) {
                foreach (FileEntry pr in K.Fx) {
                    if (pr.No == q.No || !Eq(pr.File.DirectoryName, dir) || !Eq(pr.File.Extension, ex)) continue;
                    string h = TextHit(pr.File.Name, q.No, null, null);
                    if (h.Length > 0) { Explain(g, "naming-convention", "key \"" + bn + "\" in code : " + lit + " | peer " + pr.File.Name + " (same folder, same extension) referenced : " + h, "strong"); return; }
                }
            }
            string el = ex.ToLowerInvariant();
            if (q.Kind == "text" && (el == ".txt" || el == ".md" || el == ".rst")) {
                string txt = string.Join("\n", t.Lines(q.No));
                int cnt = 0; List<string> exs = new List<string>();
                foreach (string k in K.Names.Keys) {
                    if (k.Length < 5 || k == nm.ToLowerInvariant()) continue;
                    if (txt.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0) { cnt++; if (exs.Count < 6) exs.Add(k); }
                }
                if (cnt >= 5) { Explain(g, "folder-description", "names " + cnt + " files of this folder : " + string.Join(", ", exs.ToArray()), "strong"); return; }
            }
        }

        static bool Eq(string a, string b) { return string.Compare(a, b, StringComparison.CurrentCultureIgnoreCase) == 0; }

        bool InComment(string no, int ln) {
            string[] arr = t.Lines(no);
            if (ln < 1 || ln > arr.Length) return false;
            if (CommentStart.IsMatch(arr[ln - 1].TrimStart())) return true;
            for (int j = ln - 1; j >= Math.Max(1, ln - 60); j--) {
                string a = arr[j - 1];
                int o0 = a.LastIndexOf("/*", StringComparison.Ordinal), c0 = a.LastIndexOf("*/", StringComparison.Ordinal);
                int o1 = a.LastIndexOf("<!--", StringComparison.Ordinal), c1 = a.LastIndexOf("-->", StringComparison.Ordinal);
                if (c0 >= 0 && c0 > o0) return false;
                if (c1 >= 0 && c1 > o1) return false;
                if (o0 >= 0 || o1 >= 0) return true;
            }
            return false;
        }

        public void Run(List<Gap> gaps) {
            foreach (Gap g in gaps) {
                int ln = GapProbes.LineNo(g.Loc);
                string ext0 = g.No != null ? K.ByNo(g.No).File.Extension.ToLowerInvariant() : "";
                FileRules(g);
                switch (g.Kind) {
                    case "scan-empty": { string h = FirstLine(g, @"direct children incl\. hidden : 0$"); if (h.Length > 0) Explain(g, "empty-folder", h); break; }
                    case "file-read-unexplained": RuntimePath(g); break;
                    case "import-unresolved": Import(g); break;
                    case "isolated-file": if (ext0 == ".pyc") Explain(g, "python-bytecode", "compiled cache of a .py file (generated by Python)"); else MentionRule(g); break;
                    case "role-unclassified":
                        if (Eq(K.ByNo(g.No).File.Name, "__init__.py")) Explain(g, "package-init", "python package marker; " + FirstLine(g, @"^\s+head L2:"));
                        else if (ext0 == ".csv" || ext0 == ".tsv") Explain(g, "data-table", "delimited data file; " + FirstLine(g, @"^\s+mention (?!:)"));
                        else if (ext0 == ".json") MentionRule(g);
                        else if (ext0 == ".txt" || ext0 == ".md" || SampleExt.IsMatch(g.Path)) { string h = FirstLine(g, @"^\s+head L"); if (h.Length > 0) Explain(g, "documentation-or-template", h); }
                        break;
                    case "filename-ambiguous": if (ln > 0 && InComment(g.No, ln)) Explain(g, "comment-mention", "line " + g.Loc + " is inside a comment"); break;
                    case "http-ambiguous": case "http-no-route": Http(g); break;
                    case "format-not-parsed": Format(g, ext0); break;
                }
            }
        }

        void RuntimePath(Gap g) {
            string tok = CtxStrip.Replace(g.Subject, "");
            string leaf = SemTool.BaseName(tok);
            string hs = "", hw = "";
            foreach (string l0 in g.Out) {
                Match m0 = ProbeLine.Match(l0);
                if (!m0.Success) continue;
                string code = m0.Groups[2].Value;
                if (RuntimeSkip.IsMatch(code) || !RuntimeKw.IsMatch(code)) continue;
                string kd = m0.Groups[1].Value;
                if (kd.StartsWith("def ") || kd.StartsWith("call ")) { if (hs.Length == 0) hs = l0; }
                else if (kd == ">") { if (hs.Length == 0 && code.IndexOf(leaf, StringComparison.OrdinalIgnoreCase) >= 0) hs = l0; else if (hw.Length == 0) hw = l0; }
                else if (hw.Length == 0) hw = l0;
            }
            if (hs.Length > 0) Explain(g, "runtime-path", hs, "strong");
            else if (hw.Length > 0) Explain(g, "runtime-path-nearby", hw, "weak");
        }

        void Import(Gap g) {
            string root = g.Subject.TrimStart('.').Split('.')[0];
            string h = FirstLine(g, @"(?i)(pip3?|python\s+-m\s+pip|py\s+-m\s+pip)\s+install\b[^\r\n]*\b" + Regex.Escape(root) + @"\b");
            string rl = root.ToLowerInvariant();
            if (h.Length == 0 && installs.ContainsKey(rl)) h = installs[rl];
            string b;
            if (h.Length > 0) Explain(g, "install-instruction", h);
            else if (Bundle.TryGetValue(rl, out b) && b == "flask" && flaskUsed) Explain(g, "bundled-package", root + " is installed together with flask (flask is imported in this folder)");
        }

        void Http(Gap g) {
            bool amb = g.Kind == "http-ambiguous";
            string shp = FirstLine(g, @"^\s+var : property .* also holds");
            if (shp.Length > 0 && amb) Explain(g, "shared-property-url", shp.Trim(), "weak");
            if (amb) {
                List<string> ms = new List<string>();
                foreach (string l in g.Out) { Match mq = UseMethod.Match(l); if (mq.Success) ms.Add(mq.Groups[1].Value); }
                ms = ModuleResolver.Unique(ms);
                string u1 = FirstLine(g, @"^\s+use L\d+: .*\[method=[A-Z]+\]");
                if (ms.Count >= 2) Explain(g, "multi-method-url", "url is used with " + string.Join(" and ", ms.ToArray()) + " in this file; " + u1.Trim(), "strong");
                else if (ms.Count == 1) Explain(g, "method-from-variable-use", "method " + ms[0] + " : " + u1.Trim(), "strong");
            }
            string h = FirstLine(g, @"^\s+> L\d+: .*(\b(const|let|var)\s+.*\b[\w$]+\s*=\s*[""'`]/|\b[\w$]+\s*:\s*[""'`]/)");
            if (h.Length > 0 && amb) Explain(g, "url-in-variable", h);
            else if (h.Length > 0) g.Note = (g.Note + " url is held in a variable / object property; route not found").Trim();
            if (g.Explained.Length == 0 && g.Kind == "http-no-route") {
                string dyn = FirstLine(g, @"^\s+routing .*add_url_rule\s*\(\s*(?![rfu]?[""'])[A-Za-z_]");
                string lit = FirstLine(g, @"^\s+url literal (?!"")");
                if (dyn.Length > 0 && lit.Length > 0) {
                    string fd = RoutingFile.Match(dyn).Groups[1].Value, fl = LiteralFile.Match(lit).Groups[1].Value;
                    if (fd.Length > 0 && Eq(fd, fl)) Explain(g, "dynamic-route-registration", dyn.Trim() + " | " + lit.Trim(), "strong");
                    else Explain(g, "dynamic-route-indirect", dyn.Trim() + " | " + lit.Trim(), "weak");
                }
            }
        }

        void Format(Gap g, string ext0) {
            Dictionary<string, int> sg;
            if (FirstLine(g, "magic=SQLite").Length > 0) Explain(g, "sqlite-schema", "SQLite file; CREATE TABLE statements are extracted in [16-5]");
            else if (FirstLine(g, "head16=4D 5A").Length > 0) Explain(g, "windows-executable", FirstLine(g, "head16=4D 5A"));
            else if (FirstLine(g, "Standard (ACE|Jet) DB").Length > 0) Explain(g, "access-database", FirstLine(g, "Standard (ACE|Jet) DB"));
            else if (ext0 == ".pyc") Explain(g, "python-bytecode", "compiled cache of a .py file");
            else if (sig.TryGetValue(ext0, out sg) && sg.Count == 1) {
                string s0 = null; int nf = 0;
                foreach (KeyValuePair<string, int> kv in sg) { s0 = kv.Key; nf = kv.Value; }
                if (nf >= 2) {
                    StringBuilder asc = new StringBuilder();
                    foreach (string h in s0.Split(' ')) { int v = Convert.ToInt32(h, 16); asc.Append(v >= 32 && v < 127 ? (char)v : '.'); }
                    Explain(g, "consistent-signature", "all " + nf + " " + ext0 + " files start with " + s0 + " (" + asc + ")");
                }
            } else {
                int sec = 0, kv = 0;
                foreach (string l in g.Out) { if (HeadSection.IsMatch(l)) sec++; if (HeadKeyValue.IsMatch(l)) kv++; }
                if (sec >= 1 && kv >= 1) Explain(g, "ini-format", "[section] + key=value lines : sections=" + sec + " keys=" + kv);
            }
        }
    }
}
