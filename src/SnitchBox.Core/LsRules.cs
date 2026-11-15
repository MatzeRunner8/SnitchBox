using System.Text.Json;
using System.Text.Json.Nodes;

namespace SnitchBox.Core;

/// <summary>Liest und schreibt das .lsrules-Format von Little Snitch (JSON) und gängige Blocklisten-Textformate.
/// Schlüssel laut REA-Befund am Original: name, description, rules[action, process, via, direction, priority, disabled,
/// ports, protocol, remote, remote-hosts, remote-domains, remote-addresses, notes], denied-remote-domains/-hosts/-addresses.</summary>
public static class LsRules
{
    public sealed class Document
    {
        public string Name = "";
        public string Description = "";
        public List<Rule> Rules = [];
        /// <summary>Gesperrte Domains und Hosts einer Blockliste, kleingeschrieben.</summary>
        public HashSet<string> Denied = [];
    }

    private static IEnumerable<string> Strings(JsonNode? n)
    {
        if (n is JsonArray a)
        {
            foreach (var x in a) if (x is JsonValue v && v.TryGetValue<string>(out var s)) yield return s;
        }
        else if (n is JsonValue v && v.TryGetValue<string>(out var s)) yield return s;
    }

    private static string Text(JsonNode? n) => n is JsonValue v ? (v.TryGetValue<string>(out var s) ? s : v.ToString()) : "";

    /// <summary>Erkennt .lsrules (JSON) oder eine Textliste (hosts-Format, eine Domain je Zeile, Adblock „||domain^“).</summary>
    public static Document Parse(string content)
    {
        var doc = new Document();
        var trimmed = content.AsSpan().TrimStart();
        if (trimmed.Length > 0 && trimmed[0] == '{')
        {
            var root = JsonNode.Parse(content, documentOptions: new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip })
                       ?? throw new FormatException("JSON");
            doc.Name = Text(root["name"]);
            doc.Description = Text(root["description"]);
            foreach (var k in new[] { "denied-remote-domains", "denied-remote-hosts" })
                foreach (var d in Strings(root[k])) AddDomain(doc.Denied, d);
            if (root["rules"] is JsonArray rules)
                foreach (var n in rules)
                    if (n is JsonObject o && ParseRule(o) is { } r) doc.Rules.Add(r);
            return doc;
        }
        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash].Trim();
            if (line.Length == 0 || line[0] == '!' || line[0] == '[') continue;
            if (line.StartsWith("||", StringComparison.Ordinal))
            {
                var end = line.IndexOfAny(['^', '/', '$']);
                AddDomain(doc.Denied, end > 2 ? line[2..end] : line[2..]);
                continue;
            }
            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            // hosts-Format: „0.0.0.0 domain“; sonst steht die Domain allein.
            AddDomain(doc.Denied, parts.Length >= 2 && IpKey.TryParse(parts[0], out _) ? parts[1] : parts[0]);
        }
        return doc;
    }

    private static void AddDomain(HashSet<string> set, string d)
    {
        d = d.Trim().TrimEnd('.').ToLowerInvariant();
        if (d.Length < 4 || d.Length > 253 || d.IndexOf('.') < 0 || d is "0.0.0.0" or "localhost.localdomain") return;
        foreach (var ch in d)
            if (!(char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-' or '_')) return;
        if (IpKey.TryParse(d, out _)) return;
        set.Add(d);
    }

    private static Rule? ParseRule(JsonObject o)
    {
        var action = Text(o["action"]).ToLowerInvariant();
        if (action is not ("allow" or "deny")) return null; // „ask“ entspricht hier „keine Regel“
        var r = new Rule
        {
            Action = action == "allow" ? RuleAction.Allow : RuleAction.Deny,
            Direction = Text(o["direction"]).Equals("incoming", StringComparison.OrdinalIgnoreCase) ? Direction.Incoming : Direction.Outgoing,
            HighPriority = Text(o["priority"]).Equals("high", StringComparison.OrdinalIgnoreCase),
            Enabled = !(o["disabled"] is JsonValue dv && dv.TryGetValue<bool>(out var disabled) && disabled),
            Notes = Text(o["notes"]),
        };
        var process = Text(o["process"]);
        r.Process = process.Equals("any", StringComparison.OrdinalIgnoreCase) ? "" : process;
        var ports = Text(o["ports"]);
        r.Ports = ports.Equals("any", StringComparison.OrdinalIgnoreCase) ? "" : ports;
        if (!PortSet.TryParse(r.Ports, out _)) return null;
        r.Protocol = Text(o["protocol"]).ToLowerInvariant() switch { "tcp" or "6" => Proto.Tcp, "udp" or "17" => Proto.Udp, _ => Proto.Any };

        var hosts = Strings(o["remote-hosts"]).ToList();
        var domains = Strings(o["remote-domains"]).ToList();
        var addresses = Strings(o["remote-addresses"]).ToList();
        var remote = Text(o["remote"]).ToLowerInvariant();
        if (hosts.Count > 0) { r.Remote = RemoteKind.Hosts; r.Targets = hosts; }
        else if (domains.Count > 0) { r.Remote = RemoteKind.Domains; r.Targets = domains; }
        else if (addresses.Count > 0)
        {
            r.Remote = RemoteKind.Addresses;
            r.Targets = addresses.SelectMany(a => a.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList();
        }
        else if (remote is "local-net" or "multicast" or "broadcast" or "bonjour") r.Remote = RemoteKind.LocalNet;
        else if (remote == "dns-servers") r.Remote = RemoteKind.DnsServers;
        else if (remote is "" or "any") r.Remote = RemoteKind.Any;
        else return null; // z. B. „bpf“ gibt es unter Windows nicht
        return r;
    }

    public static string Export(string name, IEnumerable<Rule> rules)
    {
        var arr = new JsonArray();
        foreach (var r in rules)
        {
            var o = new JsonObject
            {
                ["action"] = r.Action == RuleAction.Allow ? "allow" : "deny",
                ["process"] = r.AnyProcess ? "any" : r.Process,
                ["direction"] = r.Direction == Direction.Incoming ? "incoming" : "outgoing",
                ["priority"] = r.HighPriority ? "high" : "regular",
            };
            if (!r.Enabled) o["disabled"] = true;
            if (PortSet.TryParse(r.Ports, out var ps) && !ps.Any) o["ports"] = r.Ports;
            if (r.Protocol != Proto.Any) o["protocol"] = r.Protocol == Proto.Tcp ? "tcp" : "udp";
            JsonArray List() => new(r.Targets.Select(t => (JsonNode)JsonValue.Create(t)!).ToArray());
            switch (r.Remote)
            {
                case RemoteKind.Any: o["remote"] = "any"; break;
                case RemoteKind.LocalNet: o["remote"] = "local-net"; break;
                case RemoteKind.DnsServers: o["remote"] = "dns-servers"; break;
                case RemoteKind.Hosts: o["remote-hosts"] = List(); break;
                case RemoteKind.Domains: o["remote-domains"] = List(); break;
                default: o["remote-addresses"] = string.Join(", ", r.Targets); break;
            }
            if (r.Notes.Length > 0) o["notes"] = r.Notes;
            arr.Add(o);
        }
        var root = new JsonObject { ["name"] = name, ["description"] = "SnitchBox", ["rules"] = arr };
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }

    /// <summary>Vorschläge für Blocklisten (frei verfügbare, gepflegte Listen).</summary>
    public static readonly (string Name, string Url)[] Presets =
    [
        ("Peter Lowe (Ads, Tracking)", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
        ("StevenBlack (Ads, Malware)", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
        ("Hagezi Light (Ads, Tracking, Telemetry)", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt"),
        ("WindowsSpyBlocker (Windows Telemetry)", "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"),
    ];
}
