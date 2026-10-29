using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Gaps {
    // Probes : extra evidence collected for each gap (probe helpers of v5.18 [19]).
    // The depth grows with the gap level (seen again = probed deeper).
    public sealed class GapProbes {
        const RegexOptions I = RegexOptions.IgnoreCase;
        static readonly Regex LocLine = new Regex(@"^L(\d+)$", I);
        static readonly Regex IdPath = new Regex(@"\b([A-Za-z_]\w*)\s*/\s*(?:[rRbBuUfF]?[""']|[A-Za-z_(])");
        static readonly Regex IdWord = new Regex(@"[A-Za-z_][A-Za-z0-9_]{2,}");
        static readonly Regex ReturnWord = new Regex(@"\breturn\b", I);
        static readonly Regex Ctrl = new Regex("[\\x00-\\x1F\\x7F-\\x9F\\uFFFD]");
        static readonly Regex Routing = new Regex(@"url_prefix|register_blueprint|add_url_rule|Blueprint\s*\(|\.use\s*\(\s*[""'`]/|APIRouter\s*\(|include_router", I);
        static readonly Regex MethodOpt = new Regex(@"(?i)\bmethod\s*:\s*[""'`](GET|POST|PUT|PATCH|DELETE)[""'`]");
        static readonly Regex MethodArg = new Regex(@",\s*[""'`](GET|POST|PUT|PATCH|DELETE)[""'`]\s*\)");
        static readonly HashSet<string> KwSkip = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "if", "else", "elif", "for", "while", "return", "def", "class", "import", "from", "with", "as", "in", "not", "and", "or", "try", "except", "finally", "const", "let", "var",
            "function", "new", "this", "self", "true", "false", "none", "null", "str", "int", "len", "open", "path", "await", "async", "print", "lambda", "json", "time", "get", "set",
            "string", "list", "dict", "type", "object", "window", "document", "console", "raise", "pass", "break", "continue", "yield", "global", "static", "public", "private", "void", "end", "then", "sub" };

        readonly ScanContext c;
        readonly GapText t;
        readonly Dictionary<int, BinText> bin = new Dictionary<int, BinText>();

        // a binary file read as ascii (latin-1) / utf-8 / shift-jis, decoded only when needed
        sealed class BinText {
            public static readonly string[] Names = { "ascii", "utf-8", "shift-jis" };
            static readonly int[] Cps = { 28591, 65001, 932 };
            readonly byte[] by;
            readonly string[] text = new string[3], upper = new string[3];
            public BinText(byte[] by) { this.by = by; }
            public string Text(int i) {
                if (text[i] == null) text[i] = i == 1 ? Encoding.UTF8.GetString(by) : Encoding.GetEncoding(Cps[i]).GetString(by);
                return text[i];
            }
            public string Upper(int i) { if (upper[i] == null) upper[i] = Text(i).ToUpperInvariant(); return upper[i]; }
        }

        public GapProbes(ScanContext c, GapText t) { this.c = c; this.t = t; }

        LinkState K { get { return c.Link; } }

        public static int LineNo(string loc) { Match m = LocLine.Match(loc ?? ""); return m.Success ? int.Parse(m.Groups[1].Value) : 0; }

        public void Run(List<Gap> gaps) {
            Settings s = c.Settings;
            Dictionary<string, int> perKind = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (Gap g in gaps) {
                int pk; perKind.TryGetValue(g.Kind, out pk); perKind[g.Kind] = ++pk;
                if (pk > s.GapMax) continue;
                if (g.Probe.Length == 0) { g.Probed = true; continue; }
                int lv = g.Level;
                int kctx = Math.Min(15, s.GapCtx + 3 * lv), hops = Math.Min(3, 1 + lv), mmax = Math.Min(40, 8 + 8 * lv);
                bool binOn = true;
                int ln = LineNo(g.Loc);
                string p = g.Probe;
                try {
                    if (p == "ctxdef") { if (ln > 0) { Ctx(g, ln, kctx); Defs(g, ln, hops); } }
                    else if (p == "httpvar") { if (ln > 0) { Ctx(g, ln, kctx); Defs(g, ln, hops); VarUse(g, ln, mmax); } }
                    else if (p == "route") { if (ln > 0) Ctx(g, ln, kctx); Route(g, mmax); }
                    else if (p == "headmention") { if (g.Extra != null) foreach (string n in g.Extra) Head(g, n, 12 + 8 * lv); Mention(g, Path.GetFileNameWithoutExtension(K.ByNo(g.No).File.Name), mmax, binOn); }
                    else if (p == "ctx") { if (ln > 0) Ctx(g, ln, kctx); }
                    else if (p.StartsWith("mention:")) Mention(g, p.Substring(8), mmax, binOn);
                    else if (p.StartsWith("mod:")) {
                        string mn = p.Substring(4);
                        if (ln > 0) Ctx(g, ln, 1);
                        List<string> dirs = new List<string>();
                        foreach (DirectoryInfo di in c.AllDirs) if (string.Equals(di.Name, mn, StringComparison.OrdinalIgnoreCase)) dirs.Add(c.Rel(di.FullName));
                        g.Out.Add(dirs.Count > 0 ? "  folder with the same name : " + string.Join(" ; ", dirs.ToArray()) : "  folder with the same name : none");
                        Mention(g, mn, mmax, binOn);
                    }
                    else if (p == "head") { if (g.Extra != null) foreach (string n in g.Extra) Head(g, n, 12 + 8 * lv); }
                    else if (p == "scan") Scan(g, lv);
                } catch (Exception ex) { g.Out.Add("  probe error : " + ex.Message); }
                g.Probed = true;
            }
        }

        // source lines around the gap line
        void Ctx(Gap g, int ln, int k) {
            string[] arr = t.Lines(g.No);
            if (arr.Length == 0 || ln < 1 || ln > arr.Length) return;
            int a = Math.Max(1, ln - k), b = Math.Min(arr.Length, ln + k);
            for (int i = a; i <= b; i++) g.Out.Add("  " + (i == ln ? ">" : " ") + " L" + i + ": " + t.Clip(arr[i - 1]));
        }

        // where the names on the line are defined (and the called function's first lines)
        void Defs(Gap g, int ln, int hops) {
            string[] arr = t.Lines(g.No);
            if (arr.Length == 0 || ln < 1 || ln > arr.Length) return;
            List<int[]> queue = new List<int[]>(); queue.Add(new int[] { ln, 0 });
            HashSet<string> done = new HashSet<string>(StringComparer.CurrentCultureIgnoreCase);
            while (queue.Count > 0) {
                int[] it = queue[0]; queue.RemoveAt(0);
                int l1 = it[0], hp = it[1];
                List<string> idsAll = new List<string>();
                foreach (Match m in IdPath.Matches(arr[l1 - 1])) idsAll.Add(m.Groups[1].Value);
                foreach (Match m in IdWord.Matches(arr[l1 - 1])) idsAll.Add(m.Value);
                List<string> ids = ModuleResolver.Unique(idsAll);
                if (ids.Count > 15) ids = ids.GetRange(0, 15);
                int nf = 0;
                foreach (string id in ids) {
                    if (nf >= 6) break;
                    if (done.Contains(id) || KwSkip.Contains(id.ToLowerInvariant())) continue;
                    done.Add(id);
                    string esc = Regex.Escape(id);
                    Regex rx = new Regex(@"^\s*(?:(?:const|let|var|global|export|static|public|private|readonly|Dim|Const|Set)\s+)*" + esc + @"\s*(?::[^=]+)?=(?!=)|^\s*(?:async\s+)?def\s+" + esc + @"\s*\(|function\s+" + esc + @"\s*\(|^\s*set\s+""?" + esc + "=");
                    for (int j = l1 - 1; j >= 1; j--) {
                        if (!rx.IsMatch(arr[j - 1])) continue;
                        g.Out.Add("  def " + id + " L" + j + ": " + t.Clip(arr[j - 1]));
                        Match cm = Regex.Match(arr[j - 1], @"\b" + esc + @"\s*=\s*([A-Za-z_][\w\.]*)\s*\(");
                        if (cm.Success) {
                            string[] sp = cm.Groups[1].Value.Split('.'); string fn = sp[sp.Length - 1];
                            Regex frx = new Regex(@"^\s*(?:async\s+)?def\s+" + Regex.Escape(fn) + @"\s*\(|function\s+" + Regex.Escape(fn) + @"\s*\(");
                            for (int k0 = 1; k0 <= arr.Length; k0++) {
                                if (!frx.IsMatch(arr[k0 - 1])) continue;
                                int e0 = Math.Min(arr.Length, k0 + 8);
                                for (int k1 = k0; k1 <= e0; k1++) {
                                    g.Out.Add("  call " + fn + " L" + k1 + ": " + t.Clip(arr[k1 - 1]));
                                    if (k1 > k0 && ReturnWord.IsMatch(arr[k1 - 1])) break;
                                }
                                break;
                            }
                        }
                        nf++;
                        if (hp + 1 < hops) queue.Add(new int[] { j, hp + 1 });
                        break;
                    }
                }
            }
        }

        // where a name is mentioned in other files (text, and binary as ascii / utf-8 / shift-jis)
        void Mention(Gap g, string name, int max, bool withBin) {
            if (string.IsNullOrEmpty(name) || name.Length < 3) return;
            int n0 = 0;
            foreach (FileEntry q in K.Fx) {
                if (n0 >= max) break;
                if (q.No.ToString() == g.No) continue;
                if (q.Kind == "text") {
                    string[] arr = t.Lines(q.No);
                    for (int i = 0; i < arr.Length; i++) {
                        if (arr[i].IndexOf(name, StringComparison.OrdinalIgnoreCase) < 0) continue;
                        g.Out.Add("  mention " + q.Display + " L" + (i + 1) + ": " + t.Clip(arr[i])); n0++;
                        if (n0 >= max) break;
                    }
                } else if (withBin && q.Kind == "binary" && q.File.Length <= 50L * 1048576) {
                    try {
                        BinText bt;
                        if (!bin.TryGetValue(q.No, out bt)) { bt = new BinText(File.ReadAllBytes(q.File.FullName)); bin[q.No] = bt; }
                        string up = name.ToUpperInvariant();
                        for (int ei = 0; ei < 3; ei++) {
                            // same result as IndexOf(name, OrdinalIgnoreCase) : both sides upper-cased (invariant), ordinal search
                            int p0 = bt.Upper(ei).IndexOf(up, StringComparison.Ordinal);
                            if (p0 < 0) continue;
                            string tx = bt.Text(ei);
                            int a2 = Math.Max(0, p0 - 40), len2 = Math.Min(140, tx.Length - a2);
                            string ctx2 = Ctrl.Replace(tx.Substring(a2, len2), ".");
                            g.Out.Add("  mention " + q.Display + " (binary, " + BinText.Names[ei] + ") : " + t.Clip(ctx2)); n0++;
                            break;
                        }
                    } catch { }
                }
            }
            if (n0 == 0) g.Out.Add("  mention : \"" + name + "\" not found in other " + (withBin ? "text and binary files" : "text files"));
        }

        // first lines of a text file / magic and strings of a binary file
        void Head(Gap g, string no, int n) {
            FileEntry q = K.ByNo(no);
            if (q == null) return;
            if (q.Kind == "text") {
                string[] arr = t.Lines(q.No); int c1 = 0;
                g.Out.Add("  file " + q.Display + " lines=" + arr.Length + " encoding=" + SemTool.CpName(q.Cp));
                for (int i = 0; i < arr.Length && c1 < n; i++) if (arr[i].Trim().Length > 0) { g.Out.Add("  head L" + (i + 1) + ": " + t.Clip(arr[i])); c1++; }
            } else if (q.Kind == "binary") {
                DatInfo a;
                if (!c.DatA.TryGetValue(q.File.FullName, out a)) { try { a = DatTool.Analyze(q.File.FullName, 4096, 256); } catch { a = null; } }
                if (a != null) g.Out.Add("  file " + q.Display + " bytes=" + a.Size + " magic=" + a.Magic + " type=" + a.Type + " head16=" + a.HeadHex);
                try {
                    List<Unit> us = LinkTool.Units(q.File.FullName, false, c.DefaultCp, 4L * 1048576, 6); int c1 = 0;
                    g.Out.Add("  strings total=" + us.Count + " (>= 6 chars, first 4 MB)");
                    foreach (Unit u in us) { if (c1 >= n) break; g.Out.Add("  str " + u.Loc + ": " + t.Clip(u.Text)); c1++; }
                } catch { }
            }
        }

        static string LastWord(string s) { string[] p = (s ?? "").Split(' '); return p[p.Length - 1]; }

        // routes sharing the last url segment, routing setup lines, url literal in server files
        void Route(Gap g, int max) {
            DepState d = c.Dep;
            string u0 = LastWord(g.Subject);
            string[] segs = u0.TrimEnd('/').Split('/'); string seg = segs[segs.Length - 1];
            int n0 = 0;
            if (seg.Length > 0 && d.Routes.Count > 0) {
                foreach (RouteInfo rt in d.Routes) {
                    if ((rt.Path ?? "").IndexOf(seg, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    g.Out.Add("  route with \"" + seg + "\" : " + rt.Method + " " + rt.Path + "  (" + K.FP(rt.No) + " " + rt.Loc + ")"); n0++;
                    if (n0 >= max) break;
                }
            }
            if (n0 == 0) g.Out.Add("  route with \"" + seg + "\" : none in [16-2]");
            List<int> rNos = new List<int>();
            int n1 = 0;
            foreach (FileEntry q in K.Fx) {
                if ((q.Lang != "py" && q.Lang != "js") || q.Kind != "text" || OriginRules.Of(q) != "source-code") continue;
                string[] arr = t.Lines(q.No);
                for (int i = 0; i < arr.Length; i++) {
                    if (!Routing.IsMatch(arr[i])) continue;
                    if (!rNos.Contains(q.No)) rNos.Add(q.No);
                    g.Out.Add("  routing " + q.Display + " L" + (i + 1) + ": " + t.Clip(arr[i])); n1++;
                    if (n1 >= max) break;
                }
                if (n1 >= max) break;
            }
            if (n1 == 0) g.Out.Add("  routing : no Blueprint / url_prefix / add_url_rule line in server files");
            int n2 = 0;
            if (u0.Length >= 3) {
                List<FileEntry> ordered = new List<FileEntry>();
                foreach (FileEntry q in K.Fx) if (rNos.Contains(q.No)) ordered.Add(q);
                foreach (FileEntry q in K.Fx) if (!rNos.Contains(q.No)) ordered.Add(q);
                Regex lit = new Regex(@"[""'`]" + Regex.Escape(u0) + @"[""'`/]", I);
                foreach (FileEntry q in ordered) {
                    if ((q.Lang != "py" && q.Lang != "js" && q.Lang != "rs" && q.Lang != "cs") || q.Kind != "text" || OriginRules.Of(q) != "source-code" || q.No.ToString() == g.No) continue;
                    bool hasRoute = false; foreach (RouteInfo rt in d.Routes) if (rt.No == q.No) { hasRoute = true; break; }
                    if (!hasRoute && q.Lang != "py") continue;
                    string[] arr = t.Lines(q.No);
                    for (int i = 0; i < arr.Length; i++) {
                        if (!lit.IsMatch(arr[i])) continue;
                        g.Out.Add("  url literal " + q.Display + " L" + (i + 1) + ": " + t.Clip(arr[i])); n2++;
                        if (n2 >= max) break;
                    }
                    if (n2 >= max) break;
                }
            }
            if (n2 == 0) g.Out.Add("  url literal \"" + u0 + "\" : not found in server source files");
        }

        // the variable that holds the url and every use of it with its method
        void VarUse(Gap g, int ln, int max) {
            string[] arr = t.Lines(g.No);
            if (arr.Length == 0 || ln < 1 || ln > arr.Length) return;
            string u0 = LastWord(g.Subject);
            string eu = Regex.Escape(u0);
            Match vm = Regex.Match(arr[ln - 1], @"([A-Za-z_$][\w$]*)\s*[:=]\s*[""'`]" + eu + @"[""'`]");
            if (!vm.Success) { g.Out.Add("  var : url holder not identified on the line"); return; }
            string vn = vm.Groups[1].Value, ev = Regex.Escape(vn);
            g.Out.Add("  var : url \"" + u0 + "\" is held in \"" + vn + "\"");
            if (Regex.IsMatch(arr[ln - 1], @"(?<![\w$])" + ev + @"\s*:\s*[""'`]", I)) {
                int oth = 0;
                Regex other = new Regex(@"(?<![\w$])" + ev + @"\s*:\s*[""'`]/", I);
                for (int i1 = 0; i1 < arr.Length; i1++) {
                    if (i1 == ln - 1) continue;
                    if (other.IsMatch(arr[i1]) && arr[i1].IndexOf(u0, StringComparison.CurrentCulture) < 0) oth++;
                }
                if (oth > 0) g.Out.Add("  var : property \"" + vn + "\" also holds " + oth + " other url(s) in this file -> uses cannot be attributed to this url");
            }
            string rxU = @"(?<![\w$/])" + ev + @"(?![\w$/])";
            Regex use = new Regex(rxU, I);
            Regex decl = new Regex(@"^\s*(const|let|var)\s[^=]*\b" + ev + @"\s*=", I);
            Regex verb = new Regex(@"\.(get|post|put|patch|delete)\s*\([^)]*" + rxU);
            Regex call = new Regex(@"([A-Za-z_$][\w$]*)\s*\([^()]*" + rxU);
            string lg = K.ByNo(g.No).Lang;
            int n0 = 0;
            for (int i0 = 0; i0 < arr.Length; i0++) {
                if (i0 == ln - 1) continue;
                string t0 = arr[i0];
                if (!use.IsMatch(t0) || decl.IsMatch(t0)) continue;
                string mt = "?", how = "";
                Match m1 = MethodOpt.Match(t0);
                if (m1.Success) { mt = m1.Groups[1].Value.ToUpperInvariant(); how = "option"; }
                if (mt == "?") { m1 = MethodArg.Match(t0); if (m1.Success) { mt = m1.Groups[1].Value; how = "argument"; } }
                if (mt == "?") { m1 = verb.Match(t0); if (m1.Success) { mt = m1.Groups[1].Value.ToUpperInvariant(); how = "verb-call"; } }
                if (mt == "?") {
                    m1 = call.Match(t0);
                    if (m1.Success) {
                        string cn = m1.Groups[1].Value; Wrap w;
                        if (K.Wraps.TryGetValue(lg + "|" + cn, out w) && w.Http) {
                            if (!string.IsNullOrEmpty(w.Def)) { mt = w.Def; how = "wrapper-default:" + cn; } else how = "wrapper:" + cn;
                        } else if (cn == "fetch") { mt = "GET"; how = "fetch-default"; }
                    }
                }
                string tag = "[method=" + mt + "]"; if (how.Length > 0) tag = tag + " via " + how;
                g.Out.Add("  use L" + (i0 + 1) + ": " + t.Clip(t0) + " " + tag); n0++;
                if (n0 >= max) break;
            }
            if (n0 == 0) g.Out.Add("  use : \"" + vn + "\" is not used elsewhere in this file");
        }

        // folder access check of the target
        void Scan(Gap g, int lv) {
            try {
                DirectoryInfo di = new DirectoryInfo(c.ScanRoot.EndsWith(":") ? c.ScanRoot + "\\" : c.ScanRoot);
                g.Out.Add("  target attributes : " + di.Attributes);
                List<FileSystemInfo> ch = new List<FileSystemInfo>();
                foreach (DirectoryInfo x in di.GetDirectories()) ch.Add(x);   // Get-ChildItem lists folders first
                foreach (FileInfo x in di.GetFiles()) ch.Add(x);
                g.Out.Add("  direct children incl. hidden : " + ch.Count);
                for (int i = 0; i < ch.Count && i < 20 + 20 * lv; i++) {
                    FileInfo f = ch[i] as FileInfo;
                    g.Out.Add("  child " + ch[i].Name + "  attr=" + ch[i].Attributes + "  bytes=" + (f == null ? "-" : f.Length.ToString()));
                }
            } catch (Exception ex) { g.Out.Add("  access check error : " + ex.Message); }
            if (g.Note.Length > 0) g.Out.Add("  error : " + g.Note);
        }
    }
}
