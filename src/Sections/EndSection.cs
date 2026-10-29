using FolderScan.Core;

namespace FolderScan.Sections {
    // Last line of the report.
    public sealed class EndSection : IReportSection {
        public void Write(ScanContext c) { c.L("==== END OF REPORT ===="); }
    }
}
