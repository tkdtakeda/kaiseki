using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using FolderScan.Analysis;
namespace FolderScan.Core {
    public sealed class CabEntry { public int No; public string Cab; public string Dir; }
    public sealed class ScanContext {
        public const string Version = "v6.1";
        public const string BaseVersion = "v5.18";
        public Settings Settings; public IConsoleLog Log; public ReportWriter Report;
        public string ScanRoot; public string WorkDir; public string OutRoot;
        public string RunDir { get { return Path.GetDirectoryName(Report.Path); } }
        public string BatchGapsPath; public string GapsPath; public string HandOverPath;
        public readonly List<string> OmittedDat = new List<string>();
        public readonly List<string> OmittedText = new List<string>();
        public int DefaultCp; public readonly Stopwatch Watch = Stopwatch.StartNew();
        public FileSet Fs;
        public List<DirectoryInfo> AllDirs { get { return Fs.Dirs; } }
        public List<FileInfo> AllFiles { get { return Fs.Files; } }
        public List<ScanError> ScanErrors { get { return Fs.Errors; } }
        public readonly List<CabEntry> CabMap = new List<CabEntry>();
        public string CabRoot { get { return Path.Combine(WorkDir, "cab"); } }
        public readonly Dictionary<string, DatInfo> DatA = new Dictionary<string, DatInfo>(PathUtil.KeyCmp);
        public readonly LinkState Link = new LinkState();
        public readonly DepState Dep = new DepState();
        public readonly ReconState Recon = new ReconState();
        public List<FolderScan.Gaps.Gap> Gaps = new List<FolderScan.Gaps.Gap>();
        public List<FolderScan.Gaps.LedgerRow> GapsResolved = new List<FolderScan.Gaps.LedgerRow>();
        public string RunId; public FolderScan.Diag.DiagResult Diag; public string MapPath;
        public void L() { Report.L(); } public void L(string s) { Report.L(s); }
        public void Progress(string s) { Log.Info(s); }
        public string Rel(string p) { return PathUtil.Rel(ScanRoot, p); }
        public int FileCp(string p) { try { return SemTool.DetectCp(p, DefaultCp); } catch { return DefaultCp; } }
        public static int AnsiCodePage() { try { return Encoding.Default.CodePage; } catch { return 65001; } }
    }
}
