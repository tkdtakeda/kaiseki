using System;
using System.Diagnostics;
using System.Threading;

namespace FolderScan.App {
    // Opens a finished report for the user.
    public interface IReportViewer {
        void Open(string path);
    }

    public sealed class NotepadViewer : IReportViewer {
        public void Open(string path) {
            try { Process.Start("notepad.exe", "\"" + path + "\""); } catch (Exception ex) { Console.WriteLine("  [warn] could not open notepad: " + ex.Message); }
        }
    }

    // Lets the user choose a folder (used when Enter is pressed on an empty prompt).
    public interface IFolderPicker {
        string Pick();   // null = cancelled / not available
    }

    public sealed class DialogFolderPicker : IFolderPicker {
        public string Pick() {
            string result = null;
            Thread t = new Thread(delegate () {
                try {
                    using (System.Windows.Forms.FolderBrowserDialog d = new System.Windows.Forms.FolderBrowserDialog()) {
                        d.Description = "folderscan : select the target folder";
                        d.ShowNewFolderButton = false;
                        if (d.ShowDialog() == System.Windows.Forms.DialogResult.OK) result = d.SelectedPath;
                    }
                } catch (Exception ex) { Console.WriteLine("  [warn] folder dialog is not available: " + ex.Message); }
            });
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            t.Join();
            return result;
        }
    }
}
