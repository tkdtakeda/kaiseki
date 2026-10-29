using System.Collections.Generic;
using FolderScan.Core;

namespace FolderScan.Sections {
    // [16-8] RESOURCES OUTSIDE THE FOLDER (language independent, every text line / binary string)
    public sealed class GenericResourceSection : IReportSection {
        public void Write(ScanContext c) {
            LinkState k = c.Link;
            c.L("---- [16-8] RESOURCES OUTSIDE THE FOLDER (language independent : every file, text lines and binary strings) ----");
            c.L(" Kind : url / unc-path (\\\\server\\share) / absolute-path (C:\\...) / registry / env-var / ip-address");
            c.L(" Passwords in urls or connection strings are masked (***).");
            c.L(" ReadDepth : structure = a language detector read the file / generic = only this layer (strings) / none = not read");
            List<string[]> rows = new List<string[]>();
            foreach (FileEntry x in k.Fx) {
                SemItem sm;
                if (!k.Sem.TryGetValue(x.No, out sm) || sm.Generic == null) continue;
                foreach (string[] r in sm.Generic) rows.Add(new string[] { x.No.ToString(), x.Display, r[0], r[1], r[2], r[3], x.Depth });
            }
            if (rows.Count == 0) c.L("(no outside resource found)");
            c.Report.Tsv("outside_resources", new string[] { "No", "Path", "Kind", "Value", "Hits", "FirstLoc", "ReadDepth" }, rows);
            c.L();
            List<string[]> depth = new List<string[]>();
            foreach (FileEntry x in k.Fx) depth.Add(new string[] { x.No.ToString(), x.Display, x.Depth, x.Lang.Length > 0 ? x.Lang : "-", x.Kind });
            c.L("[read depth per file]");
            c.Report.Tsv("read_depth", new string[] { "No", "Path", "ReadDepth", "Lang", "Kind" }, depth);
            c.L();
        }
    }
}
