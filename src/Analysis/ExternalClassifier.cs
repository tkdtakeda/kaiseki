using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using FolderScan.Core;

namespace FolderScan.Analysis {
    // Weights / families of evidence and the semantic class of an edge whose target
    // is outside the scanned folder (functions EdgeWeight / EvFamily / ExtClass of v5.18).
    public sealed class ExternalClassifier {
        const RegexOptions I = RegexOptions.IgnoreCase;
        static readonly HashSet<string> PyStd = Set("__future__ abc argparse array ast asyncio atexit base64 binascii bisect builtins bz2 calendar cgi cmath codecs collections colorsys concurrent configparser contextlib copy csv ctypes dataclasses datetime decimal difflib dis email encodings enum errno faulthandler fnmatch fractions ftplib functools gc getopt getpass gettext glob gzip hashlib heapq hmac html http imaplib importlib inspect io ipaddress itertools json keyword linecache locale logging lzma mailbox marshal math mimetypes mmap msvcrt multiprocessing netrc numbers operator optparse os pathlib pickle pkgutil platform plistlib pprint profile pstats queue quopri random re reprlib runpy sched secrets select selectors shelve shlex shutil signal site smtplib socket socketserver sqlite3 ssl stat statistics string struct subprocess sys sysconfig tarfile tempfile textwrap threading time timeit tkinter token tokenize trace traceback tracemalloc types typing unicodedata unittest urllib uuid venv warnings wave weakref webbrowser winreg winsound wsgiref xml xmlrpc zipfile zipimport zlib zoneinfo");
        static readonly HashSet<string> NodeStd = Set("assert buffer child_process cluster crypto dgram dns events fs fs/promises http http2 https module net os path perf_hooks process querystring readline stream string_decoder timers tls url util v8 vm worker_threads zlib");
        public static readonly Dictionary<string, string> PyAlias = Map("pythoncom=pywin32 pywintypes=pywin32 win32api=pywin32 win32con=pywin32 win32gui=pywin32 win32ui=pywin32 win32process=pywin32 win32com=pywin32 win32file=pywin32 win32event=pywin32 win32clipboard=pywin32 win32print=pywin32 win32service=pywin32 win32pipe=pywin32 win32security=pywin32 winerror=pywin32 dde=pywin32 pil=pillow yaml=pyyaml cv2=opencv-python sklearn=scikit-learn bs4=beautifulsoup4 dateutil=python-dateutil dotenv=python-dotenv serial=pyserial usb=pyusb docx=python-docx pptx=python-pptx fitz=pymupdf crypto=pycryptodome jwt=pyjwt magic=python-magic werkzeug=werkzeug jinja2=jinja2");

        static readonly Regex ReqName = new Regex(@"^([A-Za-z0-9_.\-]+)");
        static readonly Regex PypBlock = new Regex(@"dependencies\s*=\s*\[([^\]]*)\]", RegexOptions.Singleline);
        static readonly Regex PypName = new Regex(@"[""']([A-Za-z0-9_.\-]+)");
        static readonly Regex PkgBlock = new Regex(@"""(?:dependencies|devDependencies|peerDependencies|optionalDependencies)""\s*:\s*\{([^}]*)\}", RegexOptions.Singleline);
        static readonly Regex PkgName = new Regex(@"""([^""]+)""\s*:");
        static readonly Regex Norm = new Regex("[-.]");
        static readonly Regex ManifestName = new Regex(@"^(requirements.*\.txt|pyproject\.toml|package\.json|setup\.py|setup\.cfg|pipfile)$", I);
        static readonly Regex ReqFile = new Regex(@"^requirements.*\.txt$", I);
        static readonly Regex CtxTail = new Regex(@"\[([a-z\-]+)\]\s*$");
        static readonly Regex CtxStrip = new Regex(@"\s*\[[a-z\-]+\]\s*$");
        static readonly Regex Wild = new Regex(@"[*?]", I);
        static readonly Regex PatternPrefix = new Regex("^pattern ", I);
        static readonly Regex ProgExt = new Regex(@"\.(exe|com|dll|ocx|sys|drv|jar|bat|cmd|ps1|vbs)$", I);
        static readonly Regex ArchivePart = new Regex(@"(^|[\\/])(xl|word|ppt|docProps|_rels|customXml)[\\/]", I);
        static readonly Regex RuntimeExt = new Regex(@"\.(log|tmp|temp|bak|pid|lock|cache)$", I);
        static readonly Regex LockMid = new Regex(@"\.lock\.", I);
        static readonly Regex LocalJs = new Regex(@"^(\.|/)", I);
        static readonly Regex NodePrefix = new Regex("^node:", I);

        readonly LinkState k;
        // normalized package name -> manifest file name (first one)
        public readonly Hashtable DeclDeps = PsHash.New();
        public readonly bool HasManifest;
        readonly Hashtable writtenLeaves = PsHash.New();

        static HashSet<string> Set(string s) { return new HashSet<string>(s.Split(' '), StringComparer.OrdinalIgnoreCase); }
        static Dictionary<string, string> Map(string s) {
            Dictionary<string, string> d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string p in s.Split(' ')) { int i = p.IndexOf('='); d[p.Substring(0, i)] = p.Substring(i + 1); }
            return d;
        }
        public static string NormName(string s) { return Norm.Replace(s.ToLowerInvariant(), "_"); }

        public ExternalClassifier(LinkState k) {
            this.k = k;
            ReadManifests();
            bool any = false;
            foreach (FileEntry x in k.Fx) if (ManifestName.IsMatch(x.File.Name)) { any = true; break; }
            HasManifest = DeclDeps.Count > 0 || any;
            // file names that some file writes (write-io)
            foreach (SemItem sm in SemInPsOrder(k)) {
                if (sm.Ext == null) continue;
                foreach (string[] r in sm.Ext) if (r[3].IndexOf("write-io=", StringComparison.OrdinalIgnoreCase) >= 0) writtenLeaves[SemTool.BaseName(r[0]).ToLowerInvariant()] = 1;
            }
        }

        // $sem.Values of v5.18 : a Hashtable filled in file order
        public static List<SemItem> SemInPsOrder(LinkState k) {
            Hashtable h = PsHash.New();
            foreach (FileEntry x in k.Fx) { SemItem sm; if (k.Sem.TryGetValue(x.No, out sm)) h[x.No] = sm; }
            List<SemItem> l = new List<SemItem>();
            foreach (object v in h.Values) l.Add((SemItem)v);
            return l;
        }

        void ReadManifests() {
            foreach (FileEntry x in k.Fx) {
                if (x.Kind != "text") continue;
                string fnl = x.File.Name.ToLowerInvariant();
                bool isReq = ReqFile.IsMatch(fnl), isPyp = fnl == "pyproject.toml", isPkg = fnl == "package.json";
                if (!(isReq || isPyp || isPkg)) continue;
                string txt;
                try { txt = File.ReadAllText(x.File.FullName); } catch { continue; }
                List<string> found = new List<string>();
                if (isReq) {
                    foreach (string ln0 in txt.Split('\n')) {
                        string ln1 = ln0.Trim();
                        if (ln1.Length == 0 || ln1.StartsWith("#") || ln1.StartsWith("-")) continue;
                        Match mq = ReqName.Match(ln1);
                        if (mq.Success) found.Add(mq.Groups[1].Value);
                    }
                } else if (isPyp) {
                    foreach (Match b in PypBlock.Matches(txt)) foreach (Match mq in PypName.Matches(b.Groups[1].Value)) found.Add(mq.Groups[1].Value);
                } else {
                    foreach (Match b in PkgBlock.Matches(txt)) foreach (Match mq in PkgName.Matches(b.Groups[1].Value)) found.Add(mq.Groups[1].Value);
                }
                foreach (string nm in found) { string nk = NormName(nm); if (!DeclDeps.ContainsKey(nk)) DeclDeps[nk] = x.File.Name; }
            }
        }

        public static int Weight(string[] e) {
            int w = 0;
            switch (e[5].ToLowerInvariant()) { case "fact": w += 40; break; case "match": w += 30; break; case "candidate": w += 10; break; case "weak": w += 1; break; }
            switch (e[6].ToLowerInvariant()) { case "source-code": w += 15; break; case "text-data": w += 8; break; case "other": w += 5; break; case "test-code": w += 3; break; }
            switch (e[0].ToUpperInvariant()) {
                case "IMPORT": case "EXEC": case "INCLUDE": w += 12; break;
                case "REF": case "HTTP": w += 10; break;
                case "CONFIG": case "SQL": case "SAME": w += 8; break;
                case "PATTERN": w += 5; break;
                case "FILEMATCH": w += 9; break;
                case "SYM": w += 2; break;
                case "KEY": case "STEM": w += 1; break;
            }
            return w;
        }

        public static string Family(string t) {
            switch (t.ToUpperInvariant()) {
                case "REF": case "FILEMATCH": case "PATTERN": return "name";
                case "IMPORT": case "EXEC": case "INCLUDE": return "code";
                case "HTTP": return "protocol";
                case "CONFIG": case "SQL": return "data";
                case "SAME": return "content";
                case "SYM": return "symbol";
                case "KEY": return "value";
                case "STEM": return "stem";
                default: return "other";
            }
        }

        public static bool IsCoreOrigin(string o) { return o == "source-code" || o == "text-data" || o == "other"; }

        // function ExtClass of v5.18
        public string Classify(string[] e) {
            string ty = e[0], d = e[3];
            if (ty == "EXTFILE" || (ty == "PATTERN" && e[2].Length == 0)) {
                Match cm = CtxTail.Match(d); string ctx = cm.Success ? cm.Groups[1].Value : "";
                if (Eq(ctx, "comment") || Eq(ctx, "doc")) return "documentation-mention";
                if (Eq(ctx, "attr")) return "lexical-only";
                string tok = CtxStrip.Replace(d, "");
                bool isPattern = tok.StartsWith("pattern ") || Wild.IsMatch(tok);
                tok = PatternPrefix.Replace(tok, "");
                string leaf = SemTool.BaseName(tok).ToLowerInvariant();
                FileEntry sx = k.ByNo(e[1]); string sl = sx == null ? "" : sx.Lang;
                if (isPattern) return "file-pattern";
                if (ProgExt.IsMatch(leaf)) return "external-program";
                if (ArchivePart.IsMatch(tok) || leaf == "[content_types].xml") return "archive-internal-part";
                if (Eq(ctx, "write-io")) return "output-file-candidate";
                if (Eq(ctx, "io") && writtenLeaves.ContainsKey(leaf)) return "runtime-work-file";
                if (RuntimeExt.IsMatch(leaf) || LockMid.IsMatch(leaf)) return "runtime-file-candidate";
                if (sl == "json") return "configured-data-path";
                if (sl == "html") return "ui-example-or-reference";
                if (e[6] == "binary-string") return "binary-embedded-name";
                if (e[6] == "documentation") return "documentation-mention";
                if (Eq(ctx, "text")) return "text-mention";
                if (Eq(ctx, "io")) return "external-file";
                if (Eq(ctx, "quoted") || Eq(ctx, "plain")) return "external-data-reference";
                return "external-file";
            }
            if (ty == "IMPORT") {
                string[] pp0 = d.Split(' '); string mod = pp0.Length >= 2 ? pp0[1] : "";
                FileEntry sx = k.ByNo(e[1]); string lg = sx == null ? "" : sx.Lang;
                if (lg == "py") {
                    if (mod.StartsWith(".")) return "local-module-missing";
                    string root = mod.Split('.')[0].ToLowerInvariant();
                    if (PyStd.Contains(root)) return "stdlib";
                    if (DeclDeps.ContainsKey(NormName(root))) return "third-party-declared";
                    string pk;
                    if (PyAlias.TryGetValue(root, out pk)) {
                        if (DeclDeps.ContainsKey(NormName(pk))) return "third-party-declared";
                        if ((root == "werkzeug" || root == "jinja2") && DeclDeps.ContainsKey("flask")) return "third-party-declared";
                        return "third-party-known-undeclared";
                    }
                    if (!HasManifest) return "third-party-no-manifest";
                    return "third-party-or-local-undeclared";
                }
                if (lg == "js" || lg == "html") {
                    if (LocalJs.IsMatch(mod)) return "local-module-missing";
                    string m2 = NodePrefix.Replace(mod, "");
                    string root = m2.Split('/')[0].ToLowerInvariant();
                    if (m2.StartsWith("@")) { string[] sp = m2.Split('/'); if (sp.Length >= 2) root = (sp[0] + "/" + sp[1]).ToLowerInvariant(); }
                    if (NodeStd.Contains(root) || NodeStd.Contains(m2.ToLowerInvariant())) return "stdlib";
                    if (DeclDeps.ContainsKey(NormName(root))) return "third-party-declared";
                    return "third-party-or-local-undeclared";
                }
                if (lg == "cs" || lg == "java" || lg == "rs" || lg == "ps" || lg == "vb") return "platform-or-library";
                return "external-module";
            }
            if (ty == "INCLUDE") return "missing-asset-or-served-elsewhere";
            if (ty == "EXEC") return "external-program";
            if (ty == "SQL") return e[5] == "weak" ? "sql-alias-like" : "external-table";
            return "external-other";
        }

        static bool Eq(string a, string b) { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }
    }
}
