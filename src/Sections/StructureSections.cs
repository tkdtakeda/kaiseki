using System;
using System.Collections.Generic;
using System.IO;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [1] SUMMARY
    public sealed class SummarySection : IReportSection {
        public void Write(ScanContext c) {
            c.Progress("[1/19] Summary...");
            c.L("==== [1] SUMMARY ====");
            double sum = 0;
            foreach (FileInfo f in c.AllFiles) sum += f.Length;
            int depth = 0;
            foreach (DirectoryInfo d in c.AllDirs) {
                int n = 0;
                foreach (string p in d.FullName.Substring(c.ScanRoot.Length).Split('\\', '/')) if (p.Length > 0) n++;
                if (n > depth) depth = n;
            }
            c.L("Folders  : " + c.AllDirs.Count);
            c.L("Files    : " + c.AllFiles.Count);
            c.L(string.Format("Total    : {0:N0} bytes ({1:N1} MB)", sum, sum / 1048576.0));
            c.L("MaxDepth : " + depth);
            c.L();
            c.L("[by extension]");
            foreach (KeyValuePair<string, List<FileInfo>> g in PathUtil.GroupSorted(c.AllFiles, PathUtil.ExtOrNone)) {
                double s = 0;
                foreach (FileInfo f in g.Value) s += f.Length;
                c.L(string.Format("{0,-12} {1,8} files {2,18:N0} bytes", g.Key, g.Value.Count, s));
            }
            c.L();
        }
    }

    // [2] COUNT BY FOLDER / EXTENSION
    public sealed class FolderExtSection : IReportSection {
        public void Write(ScanContext c) {
            c.Progress("[2/19] Count by folder and extension...");
            c.L("==== [2] COUNT BY FOLDER / EXTENSION ====");
            TextTable t = new TextTable("Folder_Ext", "Count:r", "TotalBytes:r", "MinBytes:r", "MaxBytes:r");
            Func<FileInfo, string> key = delegate (FileInfo f) { return c.Rel(f.DirectoryName) + "  |  " + PathUtil.ExtOrNone(f); };
            foreach (KeyValuePair<string, List<FileInfo>> g in PathUtil.GroupSorted(c.AllFiles, key)) {
                long s = 0, mn = long.MaxValue, mx = long.MinValue;
                foreach (FileInfo f in g.Value) { s += f.Length; if (f.Length < mn) mn = f.Length; if (f.Length > mx) mx = f.Length; }
                t.Add(g.Key, g.Value.Count, s, mn, mx);
            }
            c.Report.Table(t);
            c.L();
        }
    }

    // [3] TREE (with file size)
    public sealed class TreeSection : IReportSection {
        Dictionary<string, List<DirectoryInfo>> cd;
        Dictionary<string, List<FileInfo>> cf;
        ScanContext c;

        public void Write(ScanContext ctx) {
            c = ctx;
            c.Progress("[3/19] Tree...");
            c.L("==== [3] TREE (with file size) ====");
            cd = new Dictionary<string, List<DirectoryInfo>>(PathUtil.KeyCmp);
            cf = new Dictionary<string, List<FileInfo>>(PathUtil.KeyCmp);
            foreach (DirectoryInfo d in c.AllDirs) Child(cd, PathUtil.TrimSep(d.Parent.FullName)).Add(d);
            foreach (FileInfo f in c.AllFiles) Child(cf, PathUtil.DirKey(f)).Add(f);
            foreach (List<DirectoryInfo> l in cd.Values) PathUtil.SortByName(l);
            foreach (List<FileInfo> l in cf.Values) PathUtil.SortByName(l);
            c.L(c.ScanRoot);
            Out(c.ScanRoot, "");
            c.L();
        }

        static List<T> Child<T>(Dictionary<string, List<T>> d, string k) {
            List<T> l;
            if (!d.TryGetValue(k, out l)) { l = new List<T>(); d[k] = l; }
            return l;
        }

        void Out(string p, string pre) {
            List<DirectoryInfo> ds; if (!cd.TryGetValue(p, out ds)) ds = new List<DirectoryInfo>();
            List<FileInfo> fs; if (!cf.TryGetValue(p, out fs)) fs = new List<FileInfo>();
            string fp = ds.Count > 0 ? pre + "|   " : pre + "    ";
            foreach (FileInfo f in fs) c.L(fp + f.Name + "  [" + f.Length + " bytes]");
            for (int i = 0; i < ds.Count; i++) {
                string sub = PathUtil.TrimSep(ds[i].FullName);
                if (i == ds.Count - 1) { c.L(pre + "\\---" + ds[i].Name); Out(sub, pre + "    "); }
                else { c.L(pre + "+---" + ds[i].Name); Out(sub, pre + "|   "); }
            }
        }
    }

    // [4] FILE LIST
    public sealed class FileListSection : IReportSection {
        public void Write(ScanContext c) {
            c.Progress("[4/19] File list...");
            c.L("==== [4] FILE LIST ====");
            TextTable t = new TextTable("Path", "Ext", "Bytes:r", "Modified");
            foreach (FileInfo f in c.AllFiles)
                t.Add(c.Rel(f.FullName), f.Extension.ToLowerInvariant(), f.Length, PathUtil.Time(f.LastWriteTime));
            c.Report.Table(t);
            c.L();
        }
    }
}
