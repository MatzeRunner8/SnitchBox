namespace SnitchBox.Core;

/// <summary>Lädt abonnierte Blocklisten (.lsrules oder Textlisten) und trägt sie in den Bestand ein.</summary>
public static class BlocklistUpdater
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(90) };
    private const int MaxBytes = 60_000_000;

    public static async Task<LsRules.Document> DownloadAsync(string url, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http"))
            throw new FormatException(Loc.T("Keine gültige Web-Adresse.", "Not a valid web address."));
        using var resp = await GetAsync(uri, ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException(resp.StatusCode == System.Net.HttpStatusCode.NotFound
                ? Loc.T("Unter dieser Adresse gibt es keine Liste (Fehler 404).", "There is no list at this address (error 404).")
                : Loc.F("Der Server antwortet mit Fehler {0}.", "The server answered with error {0}.", (int)resp.StatusCode));
        if (resp.Content.Headers.ContentLength > MaxBytes) throw new InvalidDataException(Loc.T("Die Liste ist zu groß.", "The list is too large."));
        var text = await resp.Content.ReadAsStringAsync(ct);
        if (text.Length > MaxBytes) throw new InvalidDataException(Loc.T("Die Liste ist zu groß.", "The list is too large."));
        var doc = LsRules.Parse(text);
        if (doc.Denied.Count == 0 && doc.Rules.Count == 0)
            throw new InvalidDataException(Loc.T("Die Datei enthält keine Einträge.", "The file contains no entries."));
        return doc;
    }

    /// <summary>Holt die Adresse; scheitert schon der Verbindungsaufbau, folgt nach kurzer Pause ein zweiter Versuch.</summary>
    private static async Task<HttpResponseMessage> GetAsync(Uri uri, CancellationToken ct)
    {
        try { return await Http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct); }
        catch (HttpRequestException e)
        {
            Log.Write($"Blockliste {uri}: erster Versuch gescheitert: {Describe(e)}");
            await Task.Delay(1500, ct);
            return await Http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
        }
    }

    /// <summary>Fehlertext samt der inneren Ursachen (bei TLS-Fehlern steht der eigentliche Grund erst dort).</summary>
    public static string Describe(Exception e)
    {
        var text = e.Message;
        for (var inner = e.InnerException; inner != null; inner = inner.InnerException) text += " → " + inner.Message;
        return text;
    }

    /// <summary>Aktualisiert eine Liste; Fehler landen im Log und lassen die alte Fassung bestehen.</summary>
    public static async Task<string?> UpdateAsync(FirewallEngine engine, Blocklist list)
    {
        try
        {
            var doc = await DownloadAsync(list.Url);
            // Die Datei entsteht außerhalb der Sperre der Engine (große Listen bremsen sonst den Netzverkehr).
            engine.Store.SaveBlocklist(list, doc.Denied);
            var subscribed = false;
            engine.Mutate(s =>
            {
                if (!s.Blocklists.Contains(list)) return; // inzwischen entfernt
                subscribed = true;
                list.Domains = doc.Denied;
                list.Count = doc.Denied.Count;
                list.Updated = DateTime.Now;
                if (list.Name.Length == 0) list.Name = doc.Name.Length > 0 ? doc.Name : new Uri(list.Url).Host;
            });
            if (!subscribed) engine.Store.DeleteBlocklistFile(list);
            return null;
        }
        catch (Exception e)
        {
            Log.Write($"Blockliste {list.Url}: {Describe(e)}");
            return Describe(e);
        }
    }
}
