using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using FolderScan.Diag;

namespace FolderScan.Core {
    // Settings of this PC : only the keys the user changed in the settings menu.
    // They override settings.ini, so updating the tool files (settings.ini included) keeps them.
    //   %LOCALAPPDATA%\folderscan\user_settings.json   (same parent folder as the built exe)
    //   { "about": "...", "updated": "...", "settings": { "KEY": "value", ... } }
    // Values are kept as text in settings.ini notation.
    public sealed class UserSettingsStore {
        public readonly string Path;
        public readonly List<string> Warnings = new List<string>();
        readonly SortedDictionary<string, string> values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        UserSettingsStore(string path) { Path = path; }

        public static string DefaultPath() {
            string root = "";
            try { root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData); } catch { }
            if (string.IsNullOrEmpty(root)) root = System.IO.Path.GetTempPath();
            return System.IO.Path.Combine(System.IO.Path.Combine(root, "folderscan"), "user_settings.json");
        }

        public static UserSettingsStore Load(string path) {
            UserSettingsStore st = new UserSettingsStore(path);
            if (!File.Exists(path)) return st;
            try {
                object root = Json.Parse(File.ReadAllText(path, Encoding.UTF8));
                Dictionary<string, object> map = Json.O(root, "settings") as Dictionary<string, object>;
                if (map == null) throw new FormatException("\"settings\" object not found");
                foreach (KeyValuePair<string, object> p in map) {
                    if (p.Value == null || p.Value is Dictionary<string, object> || p.Value is List<object>) {
                        st.Warnings.Add("PC setting ignored (not a single value): " + p.Key);
                        continue;
                    }
                    st.values[p.Key] = Convert.ToString(p.Value, CultureInfo.InvariantCulture);
                }
            } catch (Exception ex) {
                // keep the broken file for the user, then start with no PC settings
                string bad = path + ".bad";
                try { File.Copy(path, bad, true); } catch { }
                st.values.Clear();
                st.Warnings.Add("PC settings could not be read (" + ex.Message + "); settings.ini is used. The file was copied to " + bad);
            }
            return st;
        }

        public IDictionary<string, string> Values { get { return new SortedDictionary<string, string>(values, StringComparer.OrdinalIgnoreCase); } }
        public int Count { get { return values.Count; } }
        public bool Has(string key) { return values.ContainsKey(key); }
        public void Set(string key, string value) { values[key] = value ?? ""; }
        public bool Remove(string key) { return values.Remove(key); }

        // Writes the whole file (temp file first, so a failed write never leaves half a file).
        public void Save() {
            string dir = System.IO.Path.GetDirectoryName(Path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            JsonObj map = new JsonObj();
            foreach (KeyValuePair<string, string> p in values) map.Add(p.Key.ToUpperInvariant(), p.Value);
            JsonObj o = new JsonObj()
                .Add("about", "folderscan settings of this PC. They override settings.ini. Change them with 's' at the folderscan prompt.")
                .Add("updated", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))
                .Add("settings", map);
            string tmp = Path + ".tmp";
            File.WriteAllText(tmp, Json.Write(o), new UTF8Encoding(false));
            if (File.Exists(Path)) File.Delete(Path);
            File.Move(tmp, Path);
        }
    }
}
