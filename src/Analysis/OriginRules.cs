using System;
using System.Text.RegularExpressions;
using FolderScan.Core;

namespace FolderScan.Analysis {
    // Where evidence of a file comes from (function EdgeOrigin of v5.18).
    // binary-string / generated-vendor / documentation / test-code / source-code / text-data / other
    public static class OriginRules {
        const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
        static readonly Regex VendorDir = new Regex(@"(^|/)(vendor|vendors|dist|build|node_modules|third_party|third-party|generated|gen)(/|$)", O);
        static readonly Regex VendorName = new Regex(@"(\.min\.(js|css)$|bundle.*\.js$)", O);
        static readonly Regex DocDir = new Regex(@"(^|/)(docs|doc)(/|$)", O);
        static readonly Regex DocName = new Regex(@"^(readme|license|changelog|changes|notice)(\.|$)", O);
        static readonly Regex TestDir = new Regex(@"(^|/)(test|tests|testing|spec|specs)(/|$)", O);
        static readonly Regex TestName = new Regex(@"(^test_|_test\.|\.test\.|\.spec\.)", O);

        public static string Of(FileEntry q) {
            if (q == null) return "unknown";
            if (q.Kind == "binary") return "binary-string";
            string rp = (q.Rel ?? "").ToLowerInvariant().Replace('\\', '/');
            string nm = q.File.Name.ToLowerInvariant();
            string ex = q.Ext;
            if (VendorDir.IsMatch(rp) || VendorName.IsMatch(nm)) return "generated-vendor";
            if (ex == ".md" || ex == ".rst" || DocDir.IsMatch(rp) || DocName.IsMatch(nm)) return "documentation";
            bool code = !string.IsNullOrEmpty(q.Lang);
            if (code && (TestDir.IsMatch(rp) || TestName.IsMatch(nm))) return "test-code";
            if (code) return "source-code";
            if (q.Kind == "text") return "text-data";
            return "other";
        }
    }
}
