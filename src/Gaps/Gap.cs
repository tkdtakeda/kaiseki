using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Gaps {
    // Information the scan could not establish ([19] of v5.18).
    public sealed class Gap {
        public string Kind, Key, Path, Loc, Subject, Probe, Note = "";
        public string No;            // file No. or null (scan gaps)
        public List<string> Extra;   // file Nos for head probes, or null
        public string Status = "new";
        public int Seen = 1, Level = 0;
        public string First;
        public bool Probed;
        public string Explained = "", ExEv = "", Conf = "";
        public readonly List<string> Out = new List<string>();
    }

    // A gap ledger row (folderscan_gaps.tsv).
    public sealed class LedgerRow {
        public string Kind, First, Last, Status, Path, Subject;
        public int Seen;
    }

    // Text of files for probes : lines read once per file (function GapLines of v5.18),
    // and the output clip with secret masking (function GClip).
    public sealed class GapText {
        static readonly Regex Secret = new Regex(@"(?i)((?:password|passwd|pwd|pass|secret|token|apikey|api_key|credential)[\w\-]*[""']?\s*[:=]\s*[""']?)[^""'\s,;}]+");
        readonly LinkState k;
        readonly int snipLen;
        readonly Dictionary<int, string[]> lines = new Dictionary<int, string[]>();

        public GapText(LinkState k, int snipLen) { this.k = k; this.snipLen = snipLen; }

        public string[] Lines(string no) { int n; return int.TryParse(no, out n) ? Lines(n) : new string[0]; }

        public string[] Lines(int no) {
            string[] arr;
            if (lines.TryGetValue(no, out arr)) return arr;
            arr = new string[0];
            FileEntry q = k.ByNo(no);
            if (q != null && q.Kind == "text") { try { arr = File.ReadAllLines(q.File.FullName, Encoding.GetEncoding(q.Cp)); } catch { } }
            lines[no] = arr;
            return arr;
        }

        public string Clip(string s0) {
            string s1 = LinkTool.Clean(s0).TrimEnd();
            s1 = Secret.Replace(s1, "$1***");
            if (s1.Length > snipLen) s1 = s1.Substring(0, snipLen) + "..";
            return s1;
        }
    }
}
