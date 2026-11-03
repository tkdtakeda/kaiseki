using System.Collections.Generic;
using System.IO;

namespace FolderScan.Core {
    // Builds Settings in three layers ; a later layer wins :
    //   1. built-in defaults (values of v5.18)
    //   2. settings.ini next to folderscan.bat (shipped with the tool, may be replaced by updates)
    //   3. this PC : user_settings.json (changed by the user in the settings menu)
    public static class SettingsLoader {
        public static Settings Load(string iniPath, UserSettingsStore pc) {
            Settings s = new Settings();
            if (string.IsNullOrEmpty(iniPath) || !File.Exists(iniPath)) {
                s.Warnings.Add("settings file not found, defaults are used: " + iniPath);
            } else {
                s.SourcePath = iniPath;
                foreach (KeyValuePair<string, string> p in IniFile.Read(iniPath)) s.ApplyLayer(p.Key, p.Value, Settings.FromIni);
            }
            if (pc != null) {
                s.PcPath = pc.Path;
                s.Warnings.AddRange(pc.Warnings);
                foreach (KeyValuePair<string, string> p in pc.Values) s.ApplyLayer(p.Key, p.Value, Settings.FromPc);
            }
            return s;
        }
    }
}
