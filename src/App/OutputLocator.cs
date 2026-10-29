using System;
using System.IO;

namespace FolderScan.App {
    // Output folder : Desktop\folderscan, or TEMP\folderscan when the desktop is not writable.
    public static class OutputLocator {
        public static string Resolve() {
            string desk = "";
            try { desk = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory); } catch { }
            if (string.IsNullOrEmpty(desk)) desk = Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE") ?? Path.GetTempPath(), "Desktop");
            string dir = Path.Combine(desk, "folderscan");
            if (Writable(dir)) return dir;
            dir = Path.Combine(Path.GetTempPath(), "folderscan");
            try { Directory.CreateDirectory(dir); } catch { }
            return dir;
        }

        static bool Writable(string dir) {
            try {
                Directory.CreateDirectory(dir);
                string t = Path.Combine(dir, "_w.tmp");
                File.WriteAllText(t, "");
                File.Delete(t);
                return true;
            } catch { return false; }
        }
    }
}
