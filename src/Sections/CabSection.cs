using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using FolderScan.Core;

namespace FolderScan.Sections {
    // Access to cab files (replaceable, e.g. by another extractor).
    public interface ICabTool {
        List<string> List(string cab);
        void Extract(string cab, string dstDir);
    }

    // Windows expand.exe : "expand -D cab" lists, "expand cab -F:* dst" extracts.
    public sealed class ExpandExeCabTool : ICabTool {
        public List<string> List(string cab) { return Run("-D \"" + cab + "\""); }
        public void Extract(string cab, string dstDir) { Run("\"" + cab + "\" -F:* \"" + dstDir + "\""); }

        static List<string> Run(string args) {
            List<string> lines = new List<string>();
            try {
                ProcessStartInfo si = new ProcessStartInfo("expand.exe", args);
                si.UseShellExecute = false;
                si.CreateNoWindow = true;
                si.RedirectStandardOutput = true;
                si.RedirectStandardError = true;
                Encoding oem = Console.OutputEncoding;
                si.StandardOutputEncoding = oem;
                si.StandardErrorEncoding = oem;
                using (Process p = Process.Start(si)) {
                    StringBuilder err = new StringBuilder();
                    p.ErrorDataReceived += delegate (object s, DataReceivedEventArgs e) { if (e.Data != null) lock (err) err.AppendLine(e.Data); };
                    p.BeginErrorReadLine();
                    string line;
                    while ((line = p.StandardOutput.ReadLine()) != null) lines.Add(line);
                    p.WaitForExit();
                    foreach (string e in err.ToString().Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None)) if (e.Length > 0) lines.Add(e);
                }
            } catch (Exception ex) { lines.Add(ex.Message); }
            return lines;
        }
    }

    // [5] CAB CONTENTS : list the first MAXCAB cabs per folder, extract the first CABEXT
    // cabs per folder to the work folder (never into the target).
    public sealed class CabSection : IReportSection {
        readonly ICabTool tool;
        public CabSection(ICabTool tool) { this.tool = tool; }

        public void Write(ScanContext c) {
            Settings s = c.Settings;
            c.Progress("[5/19] CAB contents / extract...");
            c.L("==== [5] CAB CONTENTS (list: first " + s.MaxCab + " per folder / extract: first " + s.CabExt + " per folder) ====");
            List<FileInfo> cabs = new List<FileInfo>();
            foreach (FileInfo f in c.AllFiles) if (string.Equals(f.Extension, ".cab", StringComparison.OrdinalIgnoreCase)) cabs.Add(f);
            int k = 0;
            foreach (KeyValuePair<string, List<FileInfo>> g in PathUtil.GroupSorted(cabs, delegate (FileInfo f) { return f.DirectoryName; })) {
                List<FileInfo> l = new List<FileInfo>(g.Value);
                PathUtil.SortByName(l);
                int j = 0;
                foreach (FileInfo cab in l) {
                    j++;
                    if (j <= s.MaxCab) {
                        c.L("----- " + c.Rel(cab.FullName) + "  [" + cab.Length + " bytes]");
                        foreach (string line in tool.List(cab.FullName)) c.L("  " + line);
                        c.L();
                    }
                    if (j <= s.CabExt) {
                        k++;
                        string dst = Path.Combine(c.CabRoot, k.ToString());
                        Directory.CreateDirectory(dst);
                        tool.Extract(cab.FullName, dst);
                        CabEntry e = new CabEntry(); e.No = k; e.Cab = cab.FullName; e.Dir = dst;
                        c.CabMap.Add(e);
                    }
                }
            }
            if (cabs.Count == 0) c.L("(no cab file found)");
            else {
                c.L("[extract map]");
                foreach (CabEntry m in c.CabMap) c.L("\\" + m.No + " = " + m.Cab);
            }
            c.L();
        }
    }
}
