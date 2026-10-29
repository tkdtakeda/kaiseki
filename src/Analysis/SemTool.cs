using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Security.Cryptography;

// Encoding detection, language detection and semantic extraction (symbols, imports, routes, http, sql ...).
// Ported verbatim from folderscan v5.18 (embedded Add-Type helper).
namespace FolderScan.Analysis {
public class Wrap { public string Name; public string File; public string Lang; public string Def; public string DefBasis = ""; public int MIdx = -1; public int Depth = -1; public bool Http; public string Body; public string Loc; public string Via = ""; }
public static class SemTool {
    static FileStream Open(string p) {
        return new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536);
    }
    static readonly TimeSpan TMO = TimeSpan.FromSeconds(2);
    static Regex R(string p) { return new Regex(p, RegexOptions.CultureInvariant, TMO); }
    static Regex RI(string p) { return new Regex(p, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TMO); }
    // regex timeout : the unit is not analyzed for that rule, but its Loc is reported (nothing silently lost)
    // per thread : files may be analyzed in parallel
    [ThreadStatic] static List<string> tmoLocs;
    public static List<string> TimeoutLocs { get { if (tmoLocs == null) tmoLocs = new List<string>(); return tmoLocs; } }
    static void Tmo(string loc) { if (TimeoutLocs.Count < 200) TimeoutLocs.Add(loc); }

    // ---------- encoding ----------
    public static int DetectCp(string p, int defCp) {
        byte[] b = new byte[1048576]; int n = 0; long len;
        using (FileStream fs = Open(p)) {
            len = fs.Length; int r;
            while (n < b.Length && (r = fs.Read(b, n, b.Length - n)) > 0) n += r;
        }
        if (n >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) return 65001;
        if (n >= 2 && b[0] == 0xFF && b[1] == 0xFE) return 1200;
        if (n >= 2 && b[0] == 0xFE && b[1] == 0xFF) return 1201;
        bool high = false;
        for (int i = 0; i < n; i++) if (b[i] >= 0x80) { high = true; break; }
        if (!high) return defCp;
        UTF8Encoding u = new UTF8Encoding(false, true);
        int cut = (len > n) ? 4 : 1;
        for (int t = 0; t < cut && n - t > 0; t++) {
            try { u.GetCharCount(b, 0, n - t); return 65001; } catch (DecoderFallbackException) { }
        }
        return defCp;
    }
    public static string CpName(int cp) {
        try { return Encoding.GetEncoding(cp).WebName; } catch { return cp.ToString(); }
    }

    // ---------- language by extension ----------
    public static string Lang(string ext) {
        switch ((ext ?? "").ToLowerInvariant()) {
            case ".py": case ".pyw": return "py";
            case ".js": case ".mjs": case ".cjs": case ".ts": case ".jsx": case ".tsx": case ".vue": return "js";
            case ".html": case ".htm": return "html";
            case ".css": return "css";
            case ".bat": case ".cmd": return "bat";
            case ".ps1": case ".psm1": return "ps";
            case ".cs": return "cs";
            case ".vb": case ".bas": case ".cls": case ".vba": case ".frm": case ".vbs": return "vb";
            case ".java": case ".kt": return "java";
            case ".rs": return "rs";
            case ".sql": return "sql";
            case ".json": return "json";
            default: return "";
        }
    }

    // ---------- helpers ----------
    public static string BaseName(string s) {
        if (s == null) return "";
        string t = s.Trim().Trim('"', '\'', '`');
        t = Regex.Replace(t, @"%~[A-Za-z]*[0-9]", "");
        t = Regex.Replace(t, @"%[^%\s]+%", "");
        t = Regex.Replace(t, @"\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_]\w*", "");
        int q = t.IndexOfAny(new char[] { '?', '#' }); if (q >= 0) t = t.Substring(0, q);
        t = t.Replace("::", "/");
        int k = Math.Max(t.LastIndexOf('/'), t.LastIndexOf('\\'));
        if (k >= 0) t = t.Substring(k + 1);
        return t.Trim();
    }
    class Ag { public string K; public int N; public string Loc; public Dictionary<string, int> C = new Dictionary<string, int>(); public string Ex = ""; }
    static Ag Bump(Dictionary<string, Ag> d, List<string> order, string key, string disp, string loc) {
        Ag a;
        if (!d.TryGetValue(key, out a)) { a = new Ag(); a.K = disp; a.Loc = loc; d[key] = a; order.Add(key); }
        a.N++;
        return a;
    }
    static List<string[]> AgRows(Dictionary<string, Ag> d, List<string> order) {
        List<string[]> o = new List<string[]>();
        foreach (string k in order) { Ag a = d[k]; o.Add(new string[] { a.K, a.N.ToString(), a.Loc }); }
        return o;
    }

    // ---------- regex rules ----------
    static readonly Regex PyDef    = R(@"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(");
    static readonly Regex PyClass  = R(@"^(\s*)class\s+([A-Za-z_]\w*)");
    static readonly Regex PyVar    = R(@"^([A-Za-z_]\w*)\s*(?::[^=]+)?=(?!=)");
    static readonly Regex PyImp    = R(@"^\s*import\s+(.+?)\s*(?:#.*)?$");
    static readonly Regex PyFrom   = R(@"^\s*from\s+(\.*[\w\.]*)\s+import\s+(.+?)\s*(?:#.*)?$");
    static readonly Regex PyMain   = R(@"__name__\s*==\s*['""]__main__['""]");
    static readonly Regex JsFunc   = R(@"\bfunction\s*\*?\s+([A-Za-z_$][\w$]*)\s*\(");
    static readonly Regex JsArrow  = R(@"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)");
    static readonly Regex JsClass  = R(@"\bclass\s+([A-Za-z_$][\w$]*)");
    static readonly Regex JsTop    = R(@"^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=");
    static readonly Regex JsImp    = R(@"\bimport\s+(?:[\w$*{}\s,]+?\s+from\s+)?['""]([^'""]+)['""]");
    static readonly Regex JsReq    = R(@"\b(?:require|import)\s*\(\s*['""`]([^'""`]+)['""`]\s*\)");
    static readonly Regex HtmlSrc  = RI(@"\b(?:src|href)\s*=\s*['""]([^'""#]+)['""]");
    static readonly Regex HtmlFn   = R(@"\bfilename\s*=\s*['""]([^'""]+)['""]");
    static readonly Regex Tpl      = R(@"\b(?:render_template|TemplateResponse|get_template)\s*\(\s*['""]([^'""]+)['""]");
    static readonly Regex CssImp   = RI(@"(?:@import\s+(?:url\()?|url\()\s*['""]?([^'""\)\s;]+)");
    static readonly Regex ExecTok  = RI(@"([^\s""'=<>|&]+\.(?:bat|cmd|ps1|py|pyw|exe|vbs|js|jar))\b");
    static readonly Regex BatLabel = R(@"^\s*:([A-Za-z_][\w\-]*)\s*$");
    static readonly Regex PsFunc   = RI(@"^\s*function\s+([\w\-]+)");
    static readonly Regex PsDot    = R(@"^\s*\.\s+['""]?([^'""\s]+)");
    static readonly Regex PsMod    = RI(@"\bImport-Module\s+['""]?([^'""\s]+)");
    static readonly Regex CsType   = R(@"\b(class|struct|interface|enum)\s+([A-Za-z_]\w*)");
    static readonly Regex CsMethod = R(@"^\s*(?:(?:public|private|protected|internal|static|virtual|override|async|abstract|sealed|extern|unsafe|new)\s+)+[\w<>\[\],\.\?]+(?:\s*<[^>]*>)?\s+([A-Za-z_]\w*)\s*\(");
    static readonly Regex CsUsing  = R(@"^\s*using\s+(?:static\s+)?([\w\.]+)\s*;");
    static readonly Regex CsMain   = R(@"\bstatic\s+(?:async\s+)?(?:void|int|Task(?:<int>)?)\s+Main\s*\(");
    static readonly Regex VbProc   = RI(@"^\s*(?:(?:Public|Private|Friend|Static)\s+)*(Sub|Function|Property\s+Get|Property\s+Let|Property\s+Set)\s+([A-Za-z_]\w*)");
    static readonly Regex JavaImp  = R(@"^\s*import\s+(?:static\s+)?([\w\.\*]+)\s*;");
    static readonly Regex JavaMain = R(@"\bpublic\s+static\s+void\s+main\s*\(");
    static readonly Regex RsItem   = R(@"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(fn|struct|enum|trait|mod)\s+([A-Za-z_]\w*)");
    static readonly Regex RsUse    = R(@"^\s*(?:pub\s+)?(use|mod)\s+([\w:]+)");
    static readonly Regex RsMain   = R(@"^\s*(?:async\s+)?fn\s+main\s*\(");
    static readonly Regex RsFn     = R(@"\bfn\s+([A-Za-z_]\w*)");
    static readonly Regex RsRoute  = R(@"#\[\s*(get|post|put|patch|delete)\s*\(\s*""([^""]+)""");
    static readonly Regex RsCmd    = R(@"#\[\s*tauri::command");
    static readonly Regex PyAddUrl = R(@"\.add_url_rule\s*\(\s*([rfu]?)['""](/[^'""]*)['""](.*?,\s*(?:view_func\s*=\s*)?([A-Za-z_]\w*)\b.*)?$");
    static readonly Regex PyRoute  = R(@"^\s*@\s*[\w\.]+\.(route|get|post|put|patch|delete|websocket)\s*\(\s*[rfu]?['""]([^'""]+)['""](.*)$");
    static readonly Regex PyMethods = R(@"methods\s*=\s*[\[\(]([^\]\)]*)");
    static readonly Regex JsRoute  = R(@"\b(?:app|router|server)\.(get|post|put|patch|delete|all|use)\s*\(\s*['""`](/[^'""`]*)['""`]");
    static readonly Regex Invoke   = R(@"\binvoke\s*\(\s*['""`]([A-Za-z_]\w*)['""`]");
    static readonly Regex JsonKey  = R(@"""([A-Za-z_][\w\-\.]*)""\s*:");
    static readonly Regex StrLit   = R(@"['""`]([A-Za-z_][\w\-\.]*)['""`]");
    static readonly Regex Ident    = R(@"[A-Za-z_]\w{2,}");
    static readonly Regex SqlDef   = RI(@"\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?(?:UNIQUE\s+)?(TABLE|VIEW|INDEX|TRIGGER)\s+(?:IF\s+NOT\s+EXISTS\s+)?[""\[`]?([A-Za-z_]\w*)");
    static readonly Regex SqlRefU  = R(@"\b(FROM|JOIN|INTO|UPDATE)\s+[""\[`]?([A-Za-z_]\w*)");
    static readonly Regex SqlRefI  = RI(@"\b(FROM|JOIN|INTO|UPDATE)\s+[""\[`]?([A-Za-z_]\w*)");
    // v5 : env-variable prefixes (%~dp0, %VAR%, ${X}, $(X)) are accepted in the last path segment
    static readonly Regex FileTok  = RI(@"(?<![\w\-\.])((?:[\w\-\*%~\.\$\{\}\(\)]+[\\/])*(?:%~[A-Za-z]*[0-9]|%[A-Za-z_]\w*%|\$\{[^}\s]*\}|\$\([^)\s]*\))*[\w\-\*]+(?:\.[\w\-\*]+)*\.(?:py|pyw|js|mjs|ts|json|xml|csv|tsv|txt|md|bat|cmd|ps1|psm1|dll|exe|html?|css|dat|cab|sqlite3?|db|mdb|accdb|mdf|ldf|xlsx|xlsm|xls|ini|cfg|conf|yaml|yml|toml|log|bmp|jpe?g|png|tiff?|pdf|docx?|pptx?|zip|rs|cs|vb|bas|sql))(?!\.?\w)");
    static readonly HashSet<string> SqlStop = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "select", "where", "set", "values", "the", "a", "an", "to", "this", "that", "which", "import", "table", "dual", "lateral", "only", "it", "its"
    };

    // ---------- [15] symbols : kind, name, loc ----------
    public static List<string[]> Symbols(List<Unit> u, string lang) {
        List<string[]> o = new List<string[]>();
        foreach (Unit x in u) {
            try {
                string s = x.Text; Match m;
                if (lang == "py") {
                    m = PyDef.Match(s); if (m.Success) { o.Add(new string[] { m.Groups[1].Length > 0 ? "method/inner-def" : "def", m.Groups[2].Value, x.Loc }); continue; }
                    m = PyClass.Match(s); if (m.Success) { o.Add(new string[] { "class", m.Groups[2].Value, x.Loc }); continue; }
                    m = PyVar.Match(s); if (m.Success) { string nm = m.Groups[1].Value; o.Add(new string[] { nm == nm.ToUpperInvariant() ? "const" : "var", nm, x.Loc }); continue; }
                } else if (lang == "js" || lang == "html") {
                    foreach (Match k in JsFunc.Matches(s)) o.Add(new string[] { "function", k.Groups[1].Value, x.Loc });
                    foreach (Match k in JsArrow.Matches(s)) o.Add(new string[] { "function", k.Groups[1].Value, x.Loc });
                    foreach (Match k in JsClass.Matches(s)) o.Add(new string[] { "class", k.Groups[1].Value, x.Loc });
                    m = JsTop.Match(s); if (m.Success && !JsArrow.IsMatch(s)) o.Add(new string[] { "top-var", m.Groups[1].Value, x.Loc });
                } else if (lang == "bat") {
                    m = BatLabel.Match(s); if (m.Success) o.Add(new string[] { "label", m.Groups[1].Value, x.Loc });
                } else if (lang == "ps") {
                    m = PsFunc.Match(s); if (m.Success) o.Add(new string[] { "psfunction", m.Groups[1].Value, x.Loc });
                } else if (lang == "cs" || lang == "java") {
                    foreach (Match k in CsType.Matches(s)) o.Add(new string[] { "type:" + k.Groups[1].Value, k.Groups[2].Value, x.Loc });
                    m = CsMethod.Match(s); if (m.Success) o.Add(new string[] { "method", m.Groups[1].Value, x.Loc });
                } else if (lang == "vb") {
                    m = VbProc.Match(s); if (m.Success) o.Add(new string[] { m.Groups[1].Value.ToLowerInvariant().Replace(" ", "-"), m.Groups[2].Value, x.Loc });
                } else if (lang == "rs") {
                    m = RsItem.Match(s); if (m.Success) o.Add(new string[] { m.Groups[1].Value, m.Groups[2].Value, x.Loc });
                } else if (lang == "sql") {
                    foreach (Match k in SqlDef.Matches(s)) o.Add(new string[] { "sql:" + k.Groups[1].Value.ToLowerInvariant(), k.Groups[2].Value, x.Loc });
                }
            } catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
        }
        return o;
    }
    public static bool HasMain(List<Unit> u, string lang) {
        Regex r = null;
        if (lang == "py") r = PyMain; else if (lang == "rs") r = RsMain; else if (lang == "cs") r = CsMain; else if (lang == "java") r = JavaMain;
        if (r == null) return false;
        foreach (Unit x in u) { try { if (r.IsMatch(x.Text)) return true; } catch (RegexMatchTimeoutException) { Tmo(x.Loc); } }
        return false;
    }

    // ---------- [16-1] imports / exec / include : kind, module, names, loc ----------
    static bool SkipHref(string v) {
        string t = v.Trim().ToLowerInvariant();
        return t.Length == 0 || t.Contains("{{") || t.Contains("{%") || t.StartsWith("http:") || t.StartsWith("https:") || t.StartsWith("//") || t.StartsWith("data:") || t.StartsWith("javascript:") || t.StartsWith("mailto:") || t == "#";
    }
    public static List<string[]> Imports(List<Unit> u, string lang) {
        List<string[]> o = new List<string[]>();
        foreach (Unit x in u) {
            try {
                string s = x.Text; Match m;
                if (lang == "py") {
                    m = PyFrom.Match(s);
                    if (m.Success) {
                        o.Add(new string[] { "from", m.Groups[1].Value, m.Groups[2].Value.Replace("(", "").Replace(")", "").Trim(), x.Loc });
                    } else {
                        m = PyImp.Match(s);
                        if (m.Success) {
                            foreach (string part in m.Groups[1].Value.Split(',')) {
                                string p = part.Trim(); if (p.Length == 0) continue;
                                string alias = ""; int a = p.IndexOf(" as ");
                                if (a > 0) { alias = "as " + p.Substring(a + 4).Trim(); p = p.Substring(0, a).Trim(); }
                                if (Regex.IsMatch(p, @"^[\w\.]+$")) o.Add(new string[] { "import", p, alias, x.Loc });
                            }
                        }
                    }
                    foreach (Match k in Tpl.Matches(s)) o.Add(new string[] { "template", k.Groups[1].Value, "", x.Loc });
                } else if (lang == "js") {
                    foreach (Match k in JsImp.Matches(s)) o.Add(new string[] { "import", k.Groups[1].Value, "", x.Loc });
                    foreach (Match k in JsReq.Matches(s)) o.Add(new string[] { "require", k.Groups[1].Value, "", x.Loc });
                } else if (lang == "html") {
                    foreach (Match k in HtmlSrc.Matches(s)) { string v = k.Groups[1].Value; if (SkipHref(v)) continue; o.Add(new string[] { "src/href", v, "", x.Loc }); }
                    foreach (Match k in HtmlFn.Matches(s)) o.Add(new string[] { "static-file", k.Groups[1].Value, "", x.Loc });
                    foreach (Match k in JsImp.Matches(s)) o.Add(new string[] { "import", k.Groups[1].Value, "", x.Loc });
                } else if (lang == "css") {
                    foreach (Match k in CssImp.Matches(s)) { string v = k.Groups[1].Value; if (SkipHref(v)) continue; o.Add(new string[] { "css-url", v, "", x.Loc }); }
                } else if (lang == "bat" || lang == "ps" || lang == "vb") {
                    string tl = s.TrimStart();
                    if (lang == "bat" && (tl.StartsWith("rem ", StringComparison.OrdinalIgnoreCase) || tl.StartsWith("::"))) continue;
                    if (lang == "ps" && tl.StartsWith("#")) continue;
                    if (lang == "vb" && (tl.StartsWith("'") || tl.StartsWith("rem ", StringComparison.OrdinalIgnoreCase))) continue;
                    foreach (Match k in ExecTok.Matches(s)) o.Add(new string[] { "exec", k.Groups[1].Value, "", x.Loc });
                    if (lang == "ps") {
                        m = PsDot.Match(s); if (m.Success) o.Add(new string[] { "dot-source", m.Groups[1].Value, "", x.Loc });
                        m = PsMod.Match(s); if (m.Success) o.Add(new string[] { "module", m.Groups[1].Value, "", x.Loc });
                    }
                } else if (lang == "cs") {
                    m = CsUsing.Match(s); if (m.Success) o.Add(new string[] { "using", m.Groups[1].Value, "", x.Loc });
                } else if (lang == "java") {
                    m = JavaImp.Match(s); if (m.Success) o.Add(new string[] { "import", m.Groups[1].Value, "", x.Loc });
                } else if (lang == "rs") {
                    m = RsUse.Match(s); if (m.Success) o.Add(new string[] { m.Groups[1].Value, m.Groups[2].Value, "", x.Loc });
                }
            } catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
        }
        return o;
    }

    // ---------- [16-2] server routes : method, path, handler, loc ----------
    static string NextName(List<Unit> u, int i, Regex r, int g) {
        for (int j = i + 1; j < u.Count && j <= i + 8; j++) {
            try { Match m = r.Match(u[j].Text); if (m.Success) return m.Groups[g].Value; } catch (RegexMatchTimeoutException) { Tmo(u[j].Loc); }
        }
        return "";
    }
    public static List<string[]> Routes(List<Unit> u, string lang) {
        List<string[]> o = new List<string[]>();
        for (int i = 0; i < u.Count; i++) {
            try {
                string s = u[i].Text; Match m;
                if (lang == "py") {
                    m = PyRoute.Match(s);
                    if (m.Success) {
                        string meth = m.Groups[1].Value.ToUpperInvariant();
                        if (meth == "ROUTE") {
                            Match mm = PyMethods.Match(m.Groups[3].Value);
                            meth = mm.Success ? mm.Groups[1].Value.Replace("'", "").Replace("\"", "").Replace(" ", "").ToUpperInvariant() : "GET";
                        }
                        o.Add(new string[] { meth, m.Groups[2].Value, NextName(u, i, PyDef, 2), u[i].Loc });
                    }
                    Match ma = PyAddUrl.Match(s);
                    if (ma.Success) {
                        Match mm2 = PyMethods.Match(ma.Groups[3].Value);
                        string meth2 = mm2.Success ? mm2.Groups[1].Value.Replace("'", "").Replace("\"", "").Replace(" ", "").ToUpperInvariant() : "GET";
                        o.Add(new string[] { meth2, ma.Groups[2].Value, ma.Groups[4].Value, u[i].Loc });
                    }
                } else if (lang == "js") {
                    foreach (Match k in JsRoute.Matches(s)) o.Add(new string[] { k.Groups[1].Value.ToUpperInvariant(), k.Groups[2].Value, "", u[i].Loc });
                } else if (lang == "rs") {
                    m = RsRoute.Match(s);
                    if (m.Success) o.Add(new string[] { m.Groups[1].Value.ToUpperInvariant(), m.Groups[2].Value, NextName(u, i, RsFn, 1), u[i].Loc });
                    if (RsCmd.IsMatch(s)) { string fn = NextName(u, i, RsFn, 1); if (fn.Length > 0) o.Add(new string[] { "INVOKE", "invoke:" + fn, fn, u[i].Loc }); }
                }
            } catch (RegexMatchTimeoutException) { Tmo(u[i].Loc); }
        }
        return o;
    }

    // ================= v5 : quote / context helpers =================
    public static Dictionary<string, Wrap> NewWrapDict() { return new Dictionary<string, Wrap>(StringComparer.Ordinal); }
    public static string QuoteChars(string lang) {
        if (lang == "js" || lang == "html") return "\"'`";
        if (lang == "bat" || lang == "vb") return "\"";
        return "\"'";
    }
    // 0 = code, 1 = inside string literal, 2 = inside template interpolation ${ } (code)
    public static int QState(string s, int i, string qs) {
        char q = '\0'; bool ip = false; int dep = 0; char q2 = '\0';
        for (int j = 0; j < i && j < s.Length; j++) {
            char c = s[j];
            if (ip) {
                if (q2 != '\0') { if (c == '\\') { j++; continue; } if (c == q2) q2 = '\0'; continue; }
                if (c == '"' || c == '\'') { q2 = c; continue; }
                if (c == '{') dep++;
                else if (c == '}') { dep--; if (dep == 0) ip = false; }
                continue;
            }
            if (q != '\0') {
                if (c == '\\' && qs.Length > 1) { j++; continue; }
                if (q == '`' && c == '$' && j + 1 < s.Length && s[j + 1] == '{') { ip = true; dep = 1; j++; continue; }
                if (c == q) q = '\0';
                continue;
            }
            if (qs.IndexOf(c) >= 0) q = c;
        }
        if (ip) return q2 != '\0' ? 1 : 2;
        return q != '\0' ? 1 : 0;
    }
    static int CountOf(string s, string t) { int n = 0, i = 0; while ((i = s.IndexOf(t, i, StringComparison.Ordinal)) >= 0) { n++; i += t.Length; } return n; }
    // line-level context : comment / doc (python docstring) / block comment ; null = decide per token
    public class LineCtx { public bool InDoc; public bool InBlk; }
    public static string LineContext(string s, string lang, LineCtx st) {
        string t = s.TrimStart();
        if (lang == "") return "text";
        if (lang == "py") { if (st.InDoc) return "doc"; if (t.StartsWith("#")) return "comment"; }
        else if (lang == "ps") { if (t.StartsWith("#")) return "comment"; }
        else if (lang == "bat") { if (t.StartsWith("rem ", StringComparison.OrdinalIgnoreCase) || t.Equals("rem", StringComparison.OrdinalIgnoreCase) || t.StartsWith("::")) return "comment"; }
        else if (lang == "vb") { if (t.StartsWith("'") || t.StartsWith("rem ", StringComparison.OrdinalIgnoreCase)) return "comment"; }
        else if (lang == "sql") { if (t.StartsWith("--")) return "comment"; }
        else if (lang == "js" || lang == "cs" || lang == "java" || lang == "rs" || lang == "css" || lang == "html") { if (st.InBlk || t.StartsWith("//") || t.StartsWith("<!--")) return "comment"; }
        return null;
    }
    public static void UpdateLineCtx(string s, string lang, LineCtx st) {
        if (lang == "py") { int n = CountOf(s, "\"\"\"") + CountOf(s, "'''"); if (n % 2 == 1) st.InDoc = !st.InDoc; }
        if (lang == "js" || lang == "cs" || lang == "java" || lang == "rs" || lang == "css" || lang == "html") {
            int a = Math.Max(s.LastIndexOf("/*", StringComparison.Ordinal), s.LastIndexOf("<!--", StringComparison.Ordinal));
            int b = Math.Max(s.LastIndexOf("*/", StringComparison.Ordinal), s.LastIndexOf("-->", StringComparison.Ordinal));
            if (a >= 0 && a > b) st.InBlk = true; else if (b >= 0) st.InBlk = false;
        }
    }

    // ---------- [16-3] client calls (v5 : url + method) ----------
    // url literal must be closed by the same quote. ${..} in template = dynamic segment
    static readonly Regex UrlLit2  = R(@"(['""`])((?:https?://[^/'""`\s]+)?/[A-Za-z_][\w\-\.]*(?:/(?:[\w\-\.<>:]+|\$\{[^}]*\})?)*)([?#][^'""`]*)?\1");
    static readonly Regex JsDefP   = R(@"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\s*\(([^)]*)\)|\(([^)]*)\)\s*=>|([A-Za-z_$][\w$]*)\s*=>)");
    static readonly Regex PyDefP   = R(@"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)");
    static readonly Regex HttpPrim = R(@"\bfetch\s*\(|\baxios\b|XMLHttpRequest|\$\.ajax\b|\$\.(?:get|post|getJSON)\b|\brequests\.(?:get|post|put|patch|delete|head|request)\b|\burlopen\s*\(|\bhttpx\.|\bsession\.(?:get|post|put|patch|delete)\b|\bHttpClient\b|Invoke-RestMethod|Invoke-WebRequest");
    static readonly Regex PrimVerb = RI(@"\b(?:axios|requests|httpx|session|\$)\.(get|post|put|patch|delete|head)\s*\(");
    static readonly Regex MethBody = RI(@"\bmethod\s*[:=]\s*['""`]([A-Za-z]+)['""`]");
    static readonly Regex MethArg  = RI(@"\bmethod\s*[:=]\s*['""`]([A-Za-z]+)['""`]");
    static readonly Regex TypeArg  = RI(@"\btype\s*:\s*['""`]([A-Za-z]+)['""`]");
    static readonly Regex MethParam = RI(@"^\s*\*{0,2}(?:method|verb|http_?method|httpMethod)\s*(?::[^=]*)?(?:=\s*['""`]([A-Za-z]+)['""`])?\s*$");
    static readonly Regex LitArg   = R(@"^\s*['""`]([A-Za-z]+)['""`]\s*$");
    static readonly HashSet<string> Verbs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "get", "post", "put", "patch", "delete", "head" };
    static readonly HashSet<string> Kw = new HashSet<string>(StringComparer.Ordinal) { "if", "for", "while", "switch", "catch", "return", "function", "typeof", "await", "new", "in", "of", "elif", "and", "or", "not", "print" };

    static int Braces(string s, int from, string qs, int dep, ref bool started) {
        char q = '\0';
        for (int j = from; j < s.Length; j++) {
            char c = s[j];
            if (q != '\0') { if (c == '\\') { j++; continue; } if (c == q) q = '\0'; continue; }
            if (qs.IndexOf(c) >= 0) { q = c; continue; }
            if (c == '{') { dep++; started = true; }
            else if (c == '}') { dep--; if (started && dep <= 0) return 0; }
        }
        return dep;
    }
    static string BodyText(List<Unit> u, int i, int at, string lang) {
        StringBuilder sb = new StringBuilder();
        if (lang == "py") {
            int ind = u[i].Text.Length - u[i].Text.TrimStart().Length;
            sb.AppendLine(u[i].Text);
            for (int j = i + 1; j < u.Count && j <= i + 400; j++) {
                string t = u[j].Text;
                if (t.Trim().Length == 0) { continue; }
                if (t.Length - t.TrimStart().Length <= ind) break;
                sb.AppendLine(t);
                if (sb.Length > 20000) break;
            }
            return sb.ToString();
        }
        string qs = QuoteChars(lang);
        string s0 = u[i].Text;
        int ar = s0.IndexOf("=>", at, StringComparison.Ordinal);
        if (ar >= 0 && !s0.Substring(ar + 2).TrimStart().StartsWith("{")) return s0;
        bool started = false;
        int dep = Braces(s0, at, qs, 0, ref started);
        sb.AppendLine(s0);
        if (started && dep <= 0) return sb.ToString();
        for (int j = i + 1; j < u.Count && j <= i + 400; j++) {
            sb.AppendLine(u[j].Text);
            dep = Braces(u[j].Text, 0, qs, dep, ref started);
            if (started && dep <= 0) break;
            if (sb.Length > 20000) break;
        }
        return sb.ToString();
    }
    // wrapper functions defined in a file (all functions are listed; Http=true only if the body calls http)
    public static List<Wrap> Wrappers(List<Unit> u, string lang, string file) {
        List<Wrap> o = new List<Wrap>();
        if (lang != "js" && lang != "html" && lang != "py") return o;
        for (int i = 0; i < u.Count; i++) {
            try {
                string s = u[i].Text;
                string name = null, prm = null; int at = 0;
                if (lang == "py") {
                    Match m = PyDefP.Match(s);
                    if (!m.Success) continue;
                    name = m.Groups[2].Value; prm = m.Groups[3].Value; at = m.Index;
                } else {
                    Match m = JsDefP.Match(s);
                    if (!m.Success) continue;
                    if (m.Groups[1].Success) { name = m.Groups[1].Value; prm = m.Groups[2].Value; }
                    else { name = m.Groups[3].Value; prm = m.Groups[4].Success ? m.Groups[4].Value : m.Groups[5].Success ? m.Groups[5].Value : m.Groups[6].Value; }
                    at = m.Index;
                }
                Wrap w = new Wrap(); w.Name = name; w.File = file; w.Lang = lang; w.Loc = u[i].Loc;
                string[] ps = prm.Split(',');
                int idx = 0;
                for (int k = 0; k < ps.Length; k++) {
                    string p = ps[k].Trim();
                    if (lang == "py" && k == 0 && (p == "self" || p == "cls")) continue;
                    Match mp = MethParam.Match(p);
                    if (mp.Success && p.Length > 0) { w.MIdx = idx; if (mp.Groups[1].Success) { w.Def = mp.Groups[1].Value.ToUpperInvariant(); w.DefBasis = "parameter-default"; } }
                    idx++;
                }
                w.Body = BodyText(u, i, at, lang);
                w.Http = HttpPrim.IsMatch(w.Body);
                if (w.Http) { w.Via = "primitive"; w.Depth = 0; }
                if (w.Def == null) {
                    MatchCollection mbs = MethBody.Matches(w.Body);
                    HashSet<string> bodyMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (Match bx in mbs) bodyMethods.Add(bx.Groups[1].Value.ToUpperInvariant());
                    MatchCollection pvs = PrimVerb.Matches(w.Body);
                    foreach (Match px in pvs) bodyMethods.Add(px.Groups[1].Value.ToUpperInvariant());
                    // A body-level method is a safe default only when every observed primitive agrees.
                    if (bodyMethods.Count == 1) { foreach (string mv in bodyMethods) w.Def = mv; w.DefBasis = "single-body-method"; }
                    else if (bodyMethods.Count > 1) { w.Def = null; w.DefBasis = "multiple-body-methods"; }
                }
                o.Add(w);
            } catch (RegexMatchTimeoutException) { Tmo(u[i].Loc); }
        }
        return o;
    }
    // wrapper calling wrapper : http flag and default method are inherited (fixed point)
    // v5.10 : breadth-first inheritance, limited to maxDepth call levels.
    // depth 0 = calls fetch / axios / requests ... directly, depth N = calls a depth N-1 wrapper.
    public static void FinalizeWraps(Dictionary<string, Wrap> d, int maxDepth) {
        for (int depth = 1; depth <= maxDepth; depth++) {
            List<Wrap> newly = new List<Wrap>();
            foreach (Wrap w in d.Values) {
                if (w.Http || w.Body == null) continue;
                foreach (Wrap w2 in d.Values) {
                    if (w2 == w || !w2.Http || w2.Depth != depth - 1 || w2.Lang != w.Lang) continue;
                    bool hit = false;
                    try { hit = Regex.IsMatch(w.Body, @"(?<![\w$.])" + Regex.Escape(w2.Name) + @"\s*\(", RegexOptions.None, TimeSpan.FromSeconds(1)); } catch { continue; }
                    if (!hit) continue;
                    newly.Add(w); w.Via = "calls " + w2.Name;
                    // Inherited methods are hints only. Route matching may later reject this hint.
                    if (w.Def == null && w.MIdx < 0 && w2.Def != null && w2.MIdx < 0 && w2.DefBasis != "multiple-body-methods") { w.Def = w2.Def; w.DefBasis = "inherited:" + w2.Name; }
                    break;
                }
            }
            if (newly.Count == 0) break;
            foreach (Wrap w in newly) { w.Http = true; w.Depth = depth; }
        }
        foreach (Wrap w in d.Values) {
            if (w.Http && w.Def == null && w.DefBasis != "multiple-body-methods" && (w.Body.Contains("fetch(") || w.Body.Contains("fetch (") || w.Body.Contains("urlopen("))) { w.Def = "GET"; w.DefBasis = "primitive-default"; }
        }
    }
    static void FindCallee(string s, int idx, out string callee, out int open) {
        callee = ""; open = -1; int depth = 0;
        for (int j = idx - 1; j >= 0; j--) {
            char c = s[j];
            if (c == ')' || c == ']' || c == '}') depth++;
            else if (c == '(' || c == '[' || c == '{') {
                if (depth > 0) { depth--; continue; }
                if (c != '(') continue;
                int k = j - 1;
                while (k >= 0 && s[k] == ' ') k--;
                int e = k;
                while (k >= 0 && (char.IsLetterOrDigit(s[k]) || s[k] == '_' || s[k] == '$' || s[k] == '.')) k--;
                string nm = e >= 0 ? s.Substring(k + 1, e - k) : "";
                if (nm.Length == 0) continue;
                if (Kw.Contains(nm)) return;
                callee = nm; open = j; return;
            }
            else if (c == ';' && depth == 0) return;
        }
    }
    static List<string> SplitArgs(string s, int open, int urlPos, out int urlArg) {
        List<string> a = new List<string>(); urlArg = -1;
        int depth = 0; char q = '\0'; int st = open + 1;
        int j = open + 1;
        for (; j < s.Length; j++) {
            char c = s[j];
            if (q != '\0') { if (c == '\\') { j++; continue; } if (c == q) q = '\0'; continue; }
            if (c == '"' || c == '\'' || c == '`') { q = c; continue; }
            if (c == '(' || c == '[' || c == '{') depth++;
            else if (c == ')' || c == ']' || c == '}') { if (depth == 0) break; depth--; }
            else if (c == ',' && depth == 0) { if (urlPos >= st && urlPos < j) urlArg = a.Count; a.Add(s.Substring(st, j - st)); st = j + 1; }
        }
        int en = Math.Min(j, s.Length);
        if (en > st || a.Count > 0) { if (urlPos >= st && urlPos < en) urlArg = a.Count; a.Add(s.Substring(st, Math.Max(0, en - st))); }
        return a;
    }
    // raw call sites (method resolved later with wrappers of all files)
    // row : path, dynamic, callee, method, basis, argLiterals(\u001f), urlArg, loc
    public static List<string[]> ClientRaw(List<Unit> u, string lang) {
        List<string[]> o = new List<string[]>();
        if (lang != "js" && lang != "html" && lang != "py") return o;
        string qs = QuoteChars(lang);
        foreach (Unit x in u) {
            string s = x.Text;
            try {
                // v5.2 generic separation of server declarations from client calls.
                // A server route declaration describes an endpoint; it is not an outgoing HTTP request.
                // PyRoute covers decorator-style Python servers (Flask/FastAPI-like).
                // JsRoute covers app/router/server .get/.post/... declarations.
                if ((lang == "py" && PyRoute.IsMatch(s)) || (lang == "js" && JsRoute.IsMatch(s))) continue;
                foreach (Match m in UrlLit2.Matches(s)) {
                    if (QState(s, m.Index, qs) == 1) continue;
                    string path = m.Groups[2].Value;
                    if (path.StartsWith("http", StringComparison.OrdinalIgnoreCase)) {
                        int p = path.IndexOf("//"); int q = p >= 0 ? path.IndexOf('/', p + 2) : -1;
                        if (q < 0) continue;
                        path = path.Substring(q);
                    }
                    bool dyn = path.Contains("${");
                    path = Regex.Replace(path, @"\$\{[^}]*\}", "{}");
                    string after = s.Substring(m.Index + m.Length);
                    if (path.EndsWith("/") && Regex.IsMatch(after, @"^\s*\+")) { path += "{}"; dyn = true; }
                    string callee; int open;
                    FindCallee(s, m.Index, out callee, out open);
                    string meth = "", basis = "unknown"; string lits = ""; int ua = -1;
                    if (open >= 0) {
                        List<string> args = SplitArgs(s, open, m.Index, out ua);
                        List<string> lv = new List<string>();
                        bool ajax = callee.IndexOf("ajax", StringComparison.OrdinalIgnoreCase) >= 0;
                        foreach (string a in args) {
                            Match la = LitArg.Match(a); lv.Add(la.Success ? la.Groups[1].Value : "");
                            if (meth.Length == 0) {
                                Match ma = MethArg.Match(a);
                                if (!ma.Success && ajax) ma = TypeArg.Match(a);
                                if (ma.Success) { meth = ma.Groups[1].Value.ToUpperInvariant(); basis = "option"; }
                            }
                        }
                        lits = string.Join("\u001f", lv.ToArray());
                        string last = callee.Substring(callee.LastIndexOf('.') + 1);
                        if (meth.Length == 0 && callee.Contains(".") && Verbs.Contains(last)) { meth = last.ToUpperInvariant(); basis = "callee-verb"; }
                        if (meth.Length == 0 && last == "fetch") { meth = "GET"; basis = "fetch-default"; }
                    }
                    o.Add(new string[] { path, dyn ? "yes" : "no", callee, meth, basis, lits, ua.ToString(), x.Loc });
                }
                foreach (Match k in Invoke.Matches(s)) o.Add(new string[] { "invoke:" + k.Groups[1].Value, "no", "invoke", "INVOKE", "tauri-invoke", "", "0", x.Loc });
            } catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
        }
        return o;
    }
    // resolve method with wrappers, aggregate : path, method, basis, callee, dynamic, count, firstLoc
    public static List<string[]> ResolveCalls(List<string[]> raw, Dictionary<string, Wrap> wraps, string lang) {
        Dictionary<string, Ag> d = new Dictionary<string, Ag>(); List<string> order = new List<string>();
        List<string[]> o = new List<string[]>();
        if (raw == null) return o;
        foreach (string[] r in raw) {
            string meth = r[3], basis = r[4], callee = r[2];
            if (meth.Length == 0 && callee.Length > 0) {
                string last = callee.Substring(callee.LastIndexOf('.') + 1);
                Wrap w;
                if (wraps.TryGetValue(lang + "|" + last, out w) && w.Http) {
                    string[] lv = r[5].Split('\u001f');
                    if (w.MIdx >= 0 && w.MIdx < lv.Length && lv[w.MIdx].Length > 0 && Verbs.Contains(lv[w.MIdx])) { meth = lv[w.MIdx].ToUpperInvariant(); basis = "wrapper-arg(" + w.Name + ")"; }
                    else if (w.Def != null) { meth = w.Def; basis = "wrapper-default(" + w.Name + ":" + w.DefBasis + ")"; }
                }
            }
            if (lang == "py" && meth.Length == 0) continue;
            string key = r[0] + "|" + meth + "|" + basis + "|" + callee + "|" + r[1];
            Ag a = Bump(d, order, key, r[0], r[7]);
            a.Ex = meth + "\u001f" + basis + "\u001f" + callee + "\u001f" + r[1];
        }
        foreach (string k in order) {
            Ag a = d[k]; string[] e = a.Ex.Split('\u001f');
            o.Add(new string[] { a.K, e[0], e[1], e[2], e[3], a.N.ToString(), a.Loc });
        }
        return o;
    }
    static Dictionary<string, Regex> _rc = new Dictionary<string, Regex>();
    public static bool RouteMatch(string route, string url) {
        if (string.IsNullOrEmpty(route) || string.IsNullOrEmpty(url)) return false;
        if (route.StartsWith("invoke:") || url.StartsWith("invoke:")) return route == url;
        Regex r;
        if (!_rc.TryGetValue(route, out r)) {
            string t = Regex.Replace(route, @"<[^>]+>|\{[^}]+\}|(?<=/):[A-Za-z_]\w*|\*", "\u0001");
            string p = Regex.Escape(t).Replace("\u0001", "[^/]+");
            p = "^" + p.TrimEnd('/') + "/?$";
            r = new Regex(p, RegexOptions.CultureInvariant);
            _rc[route] = r;
        }
        return r.IsMatch(url.Replace("{}", "x1"));
    }
    // v5.4 : generic route specificity. Higher is more specific.
    // Static/exact routes outrank parameterized routes; among dynamic routes, fewer
    // parameters and more literal characters win. No framework/app-specific names.
    public static int RouteSpecificity(string route, string url) {
        if (string.IsNullOrEmpty(route) || string.IsNullOrEmpty(url)) return -1;
        if (!RouteMatch(route, url)) return -1;
        if (route.StartsWith("invoke:") || url.StartsWith("invoke:")) return route == url ? 1000000 : -1;
        string rn = route.TrimEnd('/'); string un = url.TrimEnd('/');
        bool dyn = Regex.IsMatch(rn, @"<[^>]+>|\{[^}]+\}|(?<=/):[A-Za-z_]\w*|\*");
        if (!dyn && string.Equals(rn, un, StringComparison.Ordinal)) return 1000000 + rn.Length;
        MatchCollection mm = Regex.Matches(rn, @"<[^>]+>|\{[^}]+\}|(?<=/):[A-Za-z_]\w*|\*");
        string lit = Regex.Replace(rn, @"<[^>]+>|\{[^}]+\}|(?<=/):[A-Za-z_]\w*|\*", "");
        int seg = rn.Split(new char[]{'/'}, StringSplitOptions.RemoveEmptyEntries).Length;
        return 100000 + lit.Length * 100 + seg * 10 - mm.Count * 10000;
    }

    // ---------- [16-4] json keys : key, count, firstLoc ----------
    public static List<string[]> JsonKeys(List<Unit> u) {
        Dictionary<string, Ag> d = new Dictionary<string, Ag>(StringComparer.Ordinal); List<string> order = new List<string>();
        foreach (Unit x in u) {
            try { foreach (Match k in JsonKey.Matches(x.Text)) Bump(d, order, k.Groups[1].Value, k.Groups[1].Value, x.Loc); }
            catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
        }
        return AgRows(d, order);
    }
    public static HashSet<string> Literals(List<Unit> u) {
        HashSet<string> h = new HashSet<string>(StringComparer.Ordinal);
        foreach (Unit x in u) {
            try { foreach (Match k in StrLit.Matches(x.Text)) h.Add(k.Groups[1].Value); }
            catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
        }
        return h;
    }
    // v5 : key used as an access : x["key"]  .get("key")  .setdefault("key")  .pop("key")  getattr(x, "key")  getItem("key")
    static readonly Regex KeyAcc = R(@"(?:\[\s*|\.(?:get|setdefault|pop|getItem|has|hasOwnProperty|containsKey|TryGetValue)\(\s*|getattr\(\s*[\w\.]+\s*,\s*)['""`]([A-Za-z_][\w\-\.]*)['""`]");
    public static HashSet<string> KeyAccess(List<Unit> u) {
        HashSet<string> h = new HashSet<string>(StringComparer.Ordinal);
        foreach (Unit x in u) {
            try { foreach (Match k in KeyAcc.Matches(x.Text)) h.Add(k.Groups[1].Value); }
            catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
        }
        return h;
    }
    public static HashSet<string> Idents(List<Unit> u) {
        HashSet<string> h = new HashSet<string>(StringComparer.Ordinal);
        foreach (Unit x in u) {
            try { foreach (Match k in Ident.Matches(x.Text)) h.Add(k.Value); }
            catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
        }
        return h;
    }

    // ---------- [16-5] sql : kind(DEF/REF), objtype/keyword, name, loc ----------
    public static List<string[]> Sql(List<Unit> u, string lang, bool binary) {
        List<string[]> o = new List<string[]>();
        bool code = lang == "py" || lang == "js" || lang == "html" || lang == "cs" || lang == "vb" || lang == "java" || lang == "rs" || lang == "ps" || lang == "bat" || lang == "sql";
        foreach (Unit x in u) {
            try {
                string s = x.Text;
                foreach (Match k in SqlDef.Matches(s)) o.Add(new string[] { "DEF", k.Groups[1].Value.ToUpperInvariant(), k.Groups[2].Value, x.Loc });
                if (binary || !code) continue;
                if (lang == "py" && (PyFrom.IsMatch(s) || PyImp.IsMatch(s))) continue;
                if ((lang == "js" || lang == "html") && JsImp.IsMatch(s)) continue;
                Regex rr = lang == "sql" ? SqlRefI : SqlRefU;
                foreach (Match k in rr.Matches(s)) {
                    string n = k.Groups[2].Value;
                    if (SqlStop.Contains(n)) continue;
                    o.Add(new string[] { "REF", k.Groups[1].Value.ToUpperInvariant(), n, x.Loc });
                }
            } catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
        }
        return o;
    }

    // ---------- [16-6] file-like tokens (v5 : with context) ----------
    // context of one hit : write-io (file write/output api) / io (file api / path join)
    //                      quoted (string literal) / text (non-code file) / plain (unquoted in code)
    //                      doc (python docstring) / comment / attr (object.property in code : probably not a file)
    static readonly Regex IoRx = RI(@"\b(?:open|Path|glob|rglob|iglob|read_text|read_bytes|write_text|write_bytes|load|loads|dump|read_csv|read_excel|to_csv|to_excel|fopen|readFile\w*|writeFile\w*|createReadStream|createWriteStream|Get-Content|Set-Content|Add-Content|Out-File|Import-Csv|Export-Csv|Test-Path|Join-Path|Copy-Item|Remove-Item|send_file|send_from_directory|render_template|url_for|require|File\.\w+|StreamReader|StreamWriter|FileStream|connect)\s*\(|\w\s*/\s*[rRbBuUfF]?['""]|(?:^|\s)(?:type|copy|move|del|xcopy|robocopy|start|call)\s");
    // v5.9 : write-side file APIs are distinguished from general/read file APIs.
    static readonly Regex WriteIoRx = RI(@"\b(?:write_text|write_bytes|writeFile\w*|createWriteStream|Set-Content|Add-Content|Out-File|Export-Csv|to_csv|to_excel|dump|dumps|save|saveas|touch|mkdir|makedirs|replace|rename|Copy-Item|Move-Item)\s*\(|\bopen\s*\([^\r\n]*['""](?:w|a|x|wb|ab|xb)['""]|(?:^|\s)(?:copy|move|xcopy|robocopy)\s");
    static readonly Regex AttrRx = R(@"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$");
    static readonly string[] CtxOrder = new string[] { "write-io", "io", "quoted", "text", "plain", "doc", "comment", "attr" };
    public static int CtxRank(string c) { int i = Array.IndexOf(CtxOrder, c); return i < 0 ? 99 : i; }
    // row : token, hits, firstLoc, contextSummary, bestContext
    public static List<string[]> FileTokens(List<Unit> u, string lang) {
        Dictionary<string, Ag> d = new Dictionary<string, Ag>(); List<string> order = new List<string>();
        string qs = QuoteChars(lang);
        bool code = lang.Length > 0 && lang != "json";
        LineCtx st = new LineCtx();
        foreach (Unit x in u) {
            string s = x.Text;
            string lc = LineContext(s, lang, st);
            try {
                foreach (Match k in FileTok.Matches(s)) {
                    string v = k.Groups[1].Value; string c = lc;
                    if (c == null) {
                        int q = QState(s, k.Index, qs);
                        if (q == 1) c = WriteIoRx.IsMatch(s) ? "write-io" : IoRx.IsMatch(s) ? "io" : "quoted";
                        else if (!code) c = "text";
                        else if (AttrRx.IsMatch(v)) c = "attr";
                        else c = "plain";
                    }
                    Ag a = Bump(d, order, v.ToLowerInvariant(), v, x.Loc);
                    int n; a.C.TryGetValue(c, out n); a.C[c] = n + 1;
                }
            } catch (RegexMatchTimeoutException) { Tmo(x.Loc); }
            UpdateLineCtx(s, lang, st);
        }
        List<string[]> o = new List<string[]>();
        foreach (string key in order) {
            Ag a = d[key];
            List<string> cs = new List<string>(a.C.Keys);
            cs.Sort(delegate (string p, string q) { return CtxRank(p).CompareTo(CtxRank(q)); });
            List<string> sm = new List<string>();
            foreach (string c in cs) sm.Add(c + "=" + a.C[c]);
            o.Add(new string[] { a.K, a.N.ToString(), a.Loc, string.Join(" ", sm.ToArray()), cs.Count > 0 ? cs[0] : "-" });
        }
        return o;
    }
}
}
