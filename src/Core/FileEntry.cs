using System.Collections.Generic;
using System.IO;
using FolderScan.Analysis;

namespace FolderScan.Core {
    // One file of the file index [9] (target files + files extracted from cab).
    public sealed class FileEntry {
        public int No;
        public string Src;      // "target" or "cab#N"
        public FileInfo File;
        public string Rel;      // path relative to the target / extract folder
        public string Kind = "";// text / binary / empty / skipped / error
        public string Sha = "-";
        public int Cp;
        public string Lang = "";
        public string Ext { get { return File.Extension.ToLowerInvariant(); } }
        public string Display { get { return Src + " " + Rel; } }   // function FP of v5.18
        // how far the content was read : structure (language detector) / generic (strings only) / none
        public string Depth = "none";
    }

    // Semantic items of one analyzed file, collected in [10] and used from [15].
    public sealed class SemItem {
        public int No;
        public string Lang = "";
        public bool Text;
        public List<string[]> Sym;   // kind, name, loc
        public List<string[]> Imp;   // kind, module, names, loc
        public List<string[]> Rt;    // method, path, handler, loc
        public List<string[]> Raw;   // client url sites
        public List<string[]> JK;    // json keys
        public HashSet<string> Lit;  // string literals
        public HashSet<string> Acc;  // key access
        public HashSet<string> Idn;  // identifiers
        public List<string[]> Sql;
        public bool Main;
        public List<string[]> Ext;   // file-like tokens
        public string Tmo = "";      // locations where a regex timed out
        public List<DbHit> DbHits;   // database indicators / file names ([16-5b])
        public List<string[]> Generic;   // kind, value, hits, firstLoc : resources outside the folder ([16-8], any format)
    }

    // Results of [9]-[14], shared with later sections.
    public sealed class LinkState {
        public readonly List<FileEntry> Fx = new List<FileEntry>();
        // lower-case file name -> "No,No,..."
        public readonly Dictionary<string, string> Names = new Dictionary<string, string>();
        // SrcNo, Token, TargetNos, Hits, FirstLoc, Basis, Context
        public readonly List<string[]> Refs = new List<string[]>();
        public List<FileEntry> DbX = new List<FileEntry>();          // database files ([16-5a])
        public readonly Dictionary<int, SemItem> Sem = new Dictionary<int, SemItem>();
        public readonly Dictionary<string, Wrap> Wraps = SemTool.NewWrapDict();
        public readonly List<Wrap> WrapAll = new List<Wrap>();
        public readonly KeyIndex Keys = new KeyIndex();
        public List<string[]> Pairs = new List<string[]>();          // NoA, NoB, Shared, Examples
        public readonly HashSet<string> RefPair = new HashSet<string>(); // "src|dst"
        public readonly List<List<FileEntry>> SameContent = new List<List<FileEntry>>();
        public readonly List<KeyValuePair<string, List<FileEntry>>> SameBase = new List<KeyValuePair<string, List<FileEntry>>>();

        public FileEntry ByNo(int no) { return no >= 1 && no <= Fx.Count ? Fx[no - 1] : null; }
        public FileEntry ByNo(string no) { int n; return int.TryParse(no, out n) ? ByNo(n) : null; }
        public string FP(string no) { FileEntry e = ByNo(no); return e == null ? " " : e.Display; }
        public string FP(int no) { FileEntry e = ByNo(no); return e == null ? " " : e.Display; }
    }
}
