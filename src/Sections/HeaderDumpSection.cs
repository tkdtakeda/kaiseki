using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [6-1] header dump of target files that are not .cab / .dat
    // [6-2] header dump of files extracted from cab (max 5 per folder)
    public sealed class HeaderDumpSection : IReportSection {
        public void Write(ScanContext c) {
            Settings s = c.Settings;
            c.Progress("[6/19] Header dump of non-dat files...");
            c.L("==== [6-1] HEADER DUMP : NON-CAB / NON-DAT FILES (first " + s.HeadBytes + " bytes, max " + s.HexMax + " per folder) ====");
            List<FileInfo> hf = new List<FileInfo>();
            foreach (FileInfo f in c.AllFiles) if (!IsExt(f, ".cab") && !IsExt(f, ".dat")) hf.Add(f);
            if (hf.Count == 0) { c.L("(none)"); c.L(); } else Dump(c, c.ScanRoot, hf, s.HexMax);

            c.L("==== [6-2] HEADER DUMP : NON-DAT FILES EXTRACTED FROM CAB (max 5 per cab) ====");
            List<FileInfo> ef = new List<FileInfo>();
            foreach (FileInfo f in FileCollector.FilesUnder(c.CabRoot)) if (s.DatInCab != 1 || !IsExt(f, ".dat")) ef.Add(f);
            if (ef.Count == 0) { c.L("(none)"); c.L(); } else Dump(c, c.CabRoot, ef, 5);
        }

        static bool IsExt(FileInfo f, string ext) { return string.Equals(f.Extension, ext, StringComparison.OrdinalIgnoreCase); }

        // function HeadDump of v5.18
        static void Dump(ScanContext c, string root, List<FileInfo> files, int max) {
            int headBytes = c.Settings.HeadBytes;
            foreach (KeyValuePair<string, List<FileInfo>> g in PathUtil.GroupSorted(files, delegate (FileInfo f) { return f.DirectoryName; })) {
                List<FileInfo> l = new List<FileInfo>(g.Value);
                PathUtil.SortByName(l);
                for (int n = 0; n < l.Count && n < max; n++) {
                    FileInfo f = l[n];
                    c.L("----- " + PathUtil.Rel(root, f.FullName) + "  [" + f.Length + " bytes]");
                    try {
                        byte[] b = new byte[512]; int k;
                        using (FileStream fs = OpenRead(f.FullName)) { k = fs.Read(b, 0, 512); }
                        int h = Math.Min(k, headBytes);
                        for (int i = 0; i < h; i += 16) {
                            int e = Math.Min(i + 16, h);
                            StringBuilder hex = new StringBuilder(); StringBuilder asc = new StringBuilder();
                            for (int j = i; j < e; j++) {
                                if (j > i) hex.Append(' ');
                                hex.Append(b[j].ToString("X2"));
                                asc.Append(b[j] >= 32 && b[j] < 127 ? (char)b[j] : '.');
                            }
                            c.L(string.Format("{0:X4}  {1,-48} {2}", i, hex, asc));
                        }
                        if (k > 0) {
                            int pr = 0;
                            for (int i = 0; i < k; i++) { byte v = b[i]; if (v >= 32 || v == 9 || v == 10 || v == 13) pr++; }
                            if ((double)pr / k > 0.95) {
                                int tcp = c.FileCp(f.FullName);
                                c.L("  [text preview : first 20 lines, codepage " + tcp + "]");
                                using (StreamReader sr = new StreamReader(OpenRead(f.FullName), Encoding.GetEncoding(tcp), true)) {
                                    for (int ln = 0; ln < 20; ln++) { string line = sr.ReadLine(); if (line == null) break; c.L("  " + line); }
                                }
                            }
                        }
                    } catch (Exception ex) { c.L("  read error: " + ex.Message); }
                    c.L();
                }
            }
        }

        static FileStream OpenRead(string p) {
            return new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }
    }
}
