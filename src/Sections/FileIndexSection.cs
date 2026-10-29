using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using FolderScan.Analysis;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [9] FILE INDEX : every file (target + extracted cab) gets a No.
    // Kind / encoding / SHA256 are computed in parallel; the order is the file order.
    public sealed class FileIndexSection : IReportSection {
        static readonly string[] CodeExts = { ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".html", ".htm", ".css", ".bat", ".cmd", ".ps1", ".psm1", ".cs", ".vb", ".bas", ".cls", ".vba", ".java", ".kt", ".rs", ".sql", ".json" };

        public void Write(ScanContext c) {
            c.Progress("[9/19] File index (kind / SHA256 / encoding)...");
            c.L("==== [9] FILE INDEX (No. is used in [10]-[17]) ====");
            LinkState k = c.Link;
            Build(c, k.Fx);
            Parallel.ForEach(k.Fx, delegate (FileEntry x) { Classify(c, x); });

            c.L("Files indexed : " + k.Fx.Count + "  (target + extracted from cab)");
            c.L("Kind : text / binary / empty / skipped(media, archive : content not analyzed) / error");
            c.L("Encoding : detected for text files (UTF-8 / BOM / system default). Lang : decided by extension");
            List<string[]> rows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                string enc = x.Kind == "text" ? SemTool.CpName(x.Cp) : "-";
                string lg = x.Lang.Length > 0 ? x.Lang : "-";
                rows.Add(new string[] { x.No.ToString(), x.Src, x.Rel, x.Ext, x.File.Length.ToString(), PathUtil.Time(x.File.LastWriteTime), x.Kind, x.Sha, enc, lg, OriginRules.Of(x) });
            }
            c.Report.Tsv("file_index", new string[] { "No", "Source", "Path", "Ext", "Bytes", "Modified", "Kind", "SHA256", "Encoding", "Lang", "Origin" }, rows);
            c.L();
            foreach (FileEntry x in k.Fx) {
                string nk = x.File.Name.ToLowerInvariant();
                string v;
                k.Names[nk] = k.Names.TryGetValue(nk, out v) ? v + "," + x.No : x.No.ToString();
            }
            k.DbX = DbRules.Files(k.Fx);
        }

        static void Build(ScanContext c, List<FileEntry> fx) {
            int no = 0;
            foreach (FileInfo f in c.AllFiles) fx.Add(Entry(++no, "target", f, c.Rel(f.FullName), c.DefaultCp));
            foreach (CabEntry m in c.CabMap) {
                List<FileInfo> l = FileCollector.FilesUnder(m.Dir);
                PathUtil.SortByFullName(l);
                foreach (FileInfo f in l) fx.Add(Entry(++no, "cab#" + m.No, f, PathUtil.Rel(m.Dir, f.FullName), c.DefaultCp));
            }
        }

        static FileEntry Entry(int no, string src, FileInfo f, string rel, int cp) {
            FileEntry e = new FileEntry(); e.No = no; e.Src = src; e.File = f; e.Rel = rel; e.Cp = cp;
            return e;
        }

        static void Classify(ScanContext c, FileEntry x) {
            string ext = x.Ext;
            x.Lang = SemTool.Lang(ext);
            if (x.Lang.Length == 0 && ext == ".txt") {
                string bn = Path.GetFileNameWithoutExtension(x.File.Name).ToLowerInvariant();
                foreach (string ce in CodeExts) if (bn.EndsWith(ce)) { x.Lang = SemTool.Lang(ce); break; }
            }
            if (Contains(c.Settings.SkipExt, ext)) x.Kind = "skipped";
            else if (x.File.Length == 0) x.Kind = "empty";
            else {
                try { x.Kind = LinkTool.IsText(x.File.FullName) ? "text" : "binary"; } catch { x.Kind = "error"; }
            }
            if (x.Kind == "text") x.Cp = c.FileCp(x.File.FullName);
            if (c.Settings.HashAll == 1) {
                DatInfo a;
                // .dat files were already hashed in [7] : not read again
                if (c.DatA.TryGetValue(x.File.FullName, out a) && !string.IsNullOrEmpty(a.Sha256)) x.Sha = a.Sha256;
                else { try { x.Sha = LinkTool.Sha(x.File.FullName); } catch { x.Sha = "-"; } }
            }
        }

        public static bool Contains(List<string> l, string v) {
            foreach (string s in l) if (string.Equals(s, v, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
}
