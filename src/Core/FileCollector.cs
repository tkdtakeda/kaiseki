using System;
using System.Collections.Generic;
using System.IO;

namespace FolderScan.Core {
    // A folder or file that could not be read while collecting (ErrorVariable of v5.18).
    public sealed class ScanError {
        public string Target;
        public string Message;
        public ScanError(string target, string message) { Target = target; Message = message; }
    }

    public sealed class FileSet {
        public readonly List<DirectoryInfo> Dirs = new List<DirectoryInfo>();
        public readonly List<FileInfo> Files = new List<FileInfo>();
        public readonly List<ScanError> Errors = new List<ScanError>();
    }

    // Recursive listing of every subfolder and file (hidden / system included),
    // the equivalent of Get-ChildItem -Recurse -Force. Read-only.
    // Junctions / symbolic links to folders are listed but not entered
    // (prevents endless loops).
    public static class FileCollector {
        public static FileSet Collect(string root) {
            FileSet s = new FileSet();
            Stack<DirectoryInfo> st = new Stack<DirectoryInfo>();
            st.Push(new DirectoryInfo(root.EndsWith(":") ? root + "\\" : root));
            while (st.Count > 0) {
                DirectoryInfo d = st.Pop();
                try {
                    foreach (FileSystemInfo e in d.EnumerateFileSystemInfos()) {
                        DirectoryInfo sub = e as DirectoryInfo;
                        if (sub != null) {
                            s.Dirs.Add(sub);
                            if ((sub.Attributes & FileAttributes.ReparsePoint) == 0) st.Push(sub);
                        } else {
                            s.Files.Add((FileInfo)e);
                        }
                    }
                } catch (Exception ex) {
                    s.Errors.Add(new ScanError(d.FullName, ex.Message));
                }
            }
            PathUtil.SortByFullName(s.Dirs);
            PathUtil.SortByFullName(s.Files);
            return s;
        }

        // Files under a folder (used for folders made by this tool, e.g. extracted cab).
        public static List<FileInfo> FilesUnder(string root) {
            List<FileInfo> l = new List<FileInfo>();
            if (!Directory.Exists(root)) return l;
            try {
                foreach (FileInfo f in new DirectoryInfo(root).EnumerateFiles("*", SearchOption.AllDirectories)) l.Add(f);
            } catch { }
            return l;
        }
    }
}
