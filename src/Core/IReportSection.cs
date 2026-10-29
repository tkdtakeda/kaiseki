namespace FolderScan.Core {
    // One block of the report. A new analysis is added by writing a class that
    // implements this interface and registering it in SectionRegistry.
    public interface IReportSection {
        void Write(ScanContext ctx);
    }
}
