using System;

namespace FolderScan.Core {
    // Progress / warning output for the person running the scan (Write-Host of v5.18).
    public interface IConsoleLog {
        void Info(string s);
    }

    public sealed class ConsoleLog : IConsoleLog {
        public void Info(string s) { Console.WriteLine(s); }
    }
}
