using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FolderScan.Core;

namespace FolderScan.App {
    // What the user asked to scan.
    public sealed class ScanJob {
        public bool IsBatch;              // true = many folders, one batch_gaps file
        public string Description = "";   // shown before a batch starts
        public readonly List<string> Targets = new List<string>();
        public string Error;              // set when the input cannot be used
    }

    // Input rules (same as v5.18):
    //   <folder>     one folder
    //   <folder>\*   every direct subfolder of <folder>
    //   *            every direct subfolder of the folder of folderscan.bat
    //   @list.txt    every folder listed in the file (one per line, # = comment)
    // The output folder itself is never scanned in a batch.
    public sealed class TargetResolver {
        readonly string home;
        readonly string outDir;

        public TargetResolver(string home, string outDir) { this.home = home; this.outDir = outDir; }

        public ScanJob Resolve(string input) {
            ScanJob j = new ScanJob();
            string t = (input ?? "").Replace("\"", "").Trim();
            if (t == "*") t = Path.Combine(home, "*");
            if (t.EndsWith("\\*") || t.EndsWith("/*")) return SubDirs(j, t.Substring(0, t.Length - 2));
            if (t.StartsWith("@")) return ListFile(j, t.Substring(1));
            j.Targets.Add(t);
            return j;
        }

        // Several paths at once (drag and drop of folders onto the bat).
        public ScanJob ResolveMany(IList<string> inputs) {
            if (inputs.Count == 1) return Resolve(inputs[0]);
            ScanJob j = new ScanJob();
            j.IsBatch = true;
            j.Description = "Dropped folders : " + inputs.Count;
            foreach (string s in inputs) {
                ScanJob x = Resolve(s);
                if (x.Error != null) { j.Error = x.Error; return j; }
                j.Targets.AddRange(x.Targets);
            }
            return j;
        }

        ScanJob SubDirs(ScanJob j, string parent) {
            if (!Directory.Exists(parent)) { j.Error = "Folder not found or no read permission:\r\n  " + parent; return j; }
            j.IsBatch = true;
            j.Description = "Parent folder : " + parent;
            List<DirectoryInfo> ds = new List<DirectoryInfo>();
            try { ds.AddRange(new DirectoryInfo(parent).GetDirectories()); } catch (Exception ex) { j.Error = ex.Message; return j; }
            PathUtil.SortByName(ds);
            string od = PathUtil.TrimSep(Path.GetFullPath(outDir));
            foreach (DirectoryInfo d in ds) {
                // "for /d" of v5.18 skipped hidden and system folders
                if ((d.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0) continue;
                if (PathUtil.KeyCmp.Equals(PathUtil.TrimSep(d.FullName), od)) continue;
                j.Targets.Add(d.FullName);
            }
            return j;
        }

        ScanJob ListFile(ScanJob j, string list) {
            if (!File.Exists(list)) { j.Error = "list file not found: " + list; return j; }
            j.IsBatch = true;
            j.Description = "Batch list : " + list;
            foreach (string raw in File.ReadAllLines(list, Encoding.Default)) {
                string l = raw.Trim();
                if (l.Length == 0 || l.StartsWith("#")) continue;
                j.Targets.Add(l.Replace("\"", ""));
            }
            return j;
        }
    }
}
