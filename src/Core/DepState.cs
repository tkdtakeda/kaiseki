using System;
using System.Collections;
using System.Collections.Generic;
using FolderScan.Analysis;

namespace FolderScan.Core {
    // Hashtable that behaves like PowerShell "@{}" (same comparer and capacity).
    // v5.18 iterates some @{} key collections; their order decides the order of
    // rows and edges. Using the same Hashtable keeps that order on Windows.
    public static class PsHash {
        public static Hashtable New() { return new Hashtable(0, StringComparer.CurrentCultureIgnoreCase); }
    }

    // A server route found in [16-2].
    public sealed class RouteInfo {
        public int No; public string Method; public string Path; public string Handler; public string Loc;
    }

    // Edge list of [17] : Type, SrcNo, DstNo ("" = external), Detail, Loc, Evidence, Origin
    public sealed class EdgeList {
        readonly LinkState link;
        public readonly List<string[]> Items = new List<string[]>();
        public EdgeList(LinkState link) { this.link = link; }

        // function AddE of v5.18 : origin defaults to the origin of the source file
        public void Add(string type, string src, string dst, string detail, string loc, string ev, string origin) {
            if (string.IsNullOrEmpty(origin)) origin = OriginRules.Of(link.ByNo(src));
            Items.Add(new string[] { type, src ?? "", dst ?? "", LinkTool.Clean(detail), loc ?? "", ev, origin });
        }
        public void Add(string type, string src, string dst, string detail, string loc, string ev) { Add(type, src, dst, detail, loc, ev, ""); }
        public void Add(string type, int src, string dst, string detail, string loc, string ev) { Add(type, src.ToString(), dst, detail, loc, ev, ""); }
    }

    // Results of [15]-[17], shared with [18] / [19].
    public sealed class DepState {
        public EdgeList Edges;
        public readonly List<RouteInfo> Routes = new List<RouteInfo>();
        public readonly List<string[]> ClientRows = new List<string[]>();
        public readonly List<string[]> RouteAudit = new List<string[]>();
        // file No -> role text
        public readonly Dictionary<int, string> Role = new Dictionary<int, string>();
        // file No -> (edge type -> count), non-weak and not binary/doc/vendor origin
        public readonly Dictionary<int, Dictionary<string, int>> InT = new Dictionary<int, Dictionary<string, int>>();
        public readonly Dictionary<int, Dictionary<string, int>> OutT = new Dictionary<int, Dictionary<string, int>>();
        public readonly Dictionary<int, int> InAll = new Dictionary<int, int>();
        public readonly Dictionary<int, int> OutAll = new Dictionary<int, int>();
        public readonly List<string> Iso1 = new List<string>();   // no fact/match edge
        public readonly List<string> Iso2 = new List<string>();   // no edge at all

        public bool HasT(Dictionary<int, Dictionary<string, int>> h, int no, string t) {
            Dictionary<string, int> d;
            return h.TryGetValue(no, out d) && d.ContainsKey(t);
        }
        public bool HasT(Dictionary<int, Dictionary<string, int>> h, string no, string t) {
            int n; return int.TryParse(no, out n) && HasT(h, n, t);
        }
    }
}
