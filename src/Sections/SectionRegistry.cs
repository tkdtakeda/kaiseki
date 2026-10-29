using System.Collections.Generic;
using FolderScan.Core;

namespace FolderScan.Sections {
    // Order of the report. A new section = one new class + one line here.
    public static class SectionRegistry {
        public static List<IReportSection> Default() {
            List<IReportSection> l = new List<IReportSection>();
            l.Add(new BannerSection());
            l.Add(new CollectSection());
            l.Add(new SummarySection());                       // [1]
            l.Add(new FolderExtSection());                     // [2]
            l.Add(new TreeSection());                          // [3]
            l.Add(new FileListSection());                      // [4]
            l.Add(new CabSection(new ExpandExeCabTool()));     // [5]
            l.Add(new HeaderDumpSection());                    // [6]
            l.Add(new DatSection());                           // [7] [8]
            l.Add(new FileIndexSection());                     // [9]
            l.Add(new ContentSection());                       // [10]
            l.Add(new ReferenceSection());                     // [11]
            l.Add(new KeyLinkSection());                       // [12]
            l.Add(new SameFileSection());                      // [13]
            l.Add(new RelationMapSection());                   // [14]
            l.Add(new SymbolSection());                        // [15]
            l.Add(new ImportSection());                        // [16] [16-1]
            l.Add(new RouteSection());                         // [16-2]
            l.Add(new HttpWrapperSection());                   // [16-3a]
            l.Add(new ClientCallSection());                    // [16-3]
            l.Add(new ConfigKeySection());                     // [16-4]
            l.Add(new SqlSection());                           // [16-5]
            l.Add(new DatabaseSection());                      // [16-5a] [16-5b]
            l.Add(new FileTokenSection());                     // [16-6]
            l.Add(new SymbolUseSection());                     // [16-7]
            l.Add(new GenericResourceSection());               // [16-8] outside resources (any format)
            l.Add(new IntegratedMapSection());                 // [17]
            l.Add(new ReconcileSection());                     // [18]
            l.Add(new GapSection());                           // [19]
            l.Add(new DiagSection());                          // self diagnosis (diag.json, console)
            l.Add(new MapSection());                           // system map (map.html)
            l.Add(new EndSection());
            return l;
        }
    }
}
