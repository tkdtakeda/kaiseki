using System;
using System.Collections.Generic;
using FolderScan.Core;

namespace FolderScan.App {
    // Result of one change in the settings menu.
    public sealed class EditResult {
        public bool Ok;
        public bool Changed;          // false = the value was already the same
        public string Key = "", Old = "", New = "", Error = "";
    }

    // Changes settings for this PC : the running Settings are updated at once (the next scan
    // uses them) and the changed keys are written to user_settings.json.
    // No console code here, so the rules can be reused by another front end.
    public sealed class SettingsEditor {
        readonly Settings settings;
        readonly UserSettingsStore pc;
        readonly string iniPath;

        public SettingsEditor(Settings settings, UserSettingsStore pc, string iniPath) {
            this.settings = settings; this.pc = pc; this.iniPath = iniPath;
        }

        public string PcPath { get { return pc.Path; } }
        public Settings Settings { get { return settings; } }

        public bool IsPc(string key) {
            string o;
            return settings.Origin.TryGetValue(key, out o) && o == Settings.FromPc;
        }

        // Value without this PC : settings.ini, or the built-in default when the key is not in it.
        public string BaseValue(string key, out string origin) {
            SettingDef d = SettingDefs.Find(key);
            string v;
            if (d != null && IniFile.Read(iniPath).TryGetValue(d.Key, out v)) {
                Settings probe = new Settings();
                if (probe.TrySet(d.Key, v) == null) { origin = Settings.FromIni; return probe.Get(d.Key); }
            }
            origin = "default";
            return d == null ? "" : new Settings().Get(d.Key);
        }

        public EditResult Change(string key, string value) {
            EditResult r = Start(key);
            if (r.Error.Length > 0) return r;
            string err = settings.TrySet(r.Key, value);
            if (err != null) { r.Error = err; return r; }
            r.New = settings.Get(r.Key);
            r.Ok = true;
            if (r.New == r.Old) return r;
            r.Changed = true;
            pc.Set(r.Key, r.New);
            return Persist(r, delegate { pc.Remove(r.Key); settings.TrySet(r.Key, r.Old); }, Settings.FromPc);
        }

        // Removes the PC value of a key ; settings.ini (or the default) applies again.
        public EditResult Revert(string key) {
            EditResult r = Start(key);
            if (r.Error.Length > 0) return r;
            r.Ok = true;
            if (!pc.Has(r.Key)) { r.New = r.Old; return r; }
            string pcValue = r.Old, origin;
            string b = BaseValue(r.Key, out origin);
            settings.TrySet(r.Key, b);
            pc.Remove(r.Key);
            r.New = b;
            r.Changed = true;
            return Persist(r, delegate { pc.Set(r.Key, pcValue); settings.TrySet(r.Key, pcValue); }, origin == Settings.FromIni ? Settings.FromIni : null);
        }

        public List<EditResult> RevertAll() {
            List<EditResult> l = new List<EditResult>();
            foreach (string k in new List<string>(pc.Values.Keys)) l.Add(Revert(k));
            return l;
        }

        EditResult Start(string key) {
            EditResult r = new EditResult();
            SettingDef d = SettingDefs.Find(key);
            if (d == null) { r.Error = "unknown setting: " + key; return r; }
            r.Key = d.Key;
            r.Old = settings.Get(d.Key);
            return r;
        }

        // Saves the json ; when that fails the change is undone so screen, memory and file agree.
        EditResult Persist(EditResult r, Action undo, string newOrigin) {
            try {
                pc.Save();
            } catch (Exception ex) {
                undo();
                r.Ok = false; r.Changed = false;
                r.Error = "could not save " + pc.Path + " : " + ex.Message;
                return r;
            }
            if (newOrigin == null) settings.Origin.Remove(r.Key); else settings.Origin[r.Key] = newOrigin;
            return r;
        }
    }
}
