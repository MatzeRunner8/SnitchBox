using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using SnitchBox.Core;

namespace SnitchBox;

/// <summary>Die Ländertabelle für die Karte der Routenverfolgung: „IP to Country Lite“ von DB-IP (CC BY 4.0, db-ip.com).
/// SnitchBox lädt sie nur auf Wunsch herunter (rund 4 MB) und legt sie im Datenordner ab, der nur für Administratoren
/// beschreibbar ist; danach geschieht jede Zuordnung auf diesem PC – keine Adresse wird an einen Dienst geschickt.</summary>
internal static class GeoData
{
    public const string Attribution = "IP Geolocation by DB-IP";
    public const string AttributionUrl = "https://db-ip.com";
    private const long MaxDownload = 32L << 20, MaxUnpacked = 96L << 20;

    private static readonly object Gate = new();
    // Nur ein Download zur Zeit (mehrere Trace-Fenster); wer wartet, nimmt die Tabelle, die der andere gerade geladen hat.
    private static readonly SemaphoreSlim DownloadGate = new(1, 1);
    private static CountryDb? _db;
    private static bool _tried;

    public static string FilePath => Path.Combine(Paths.DataDir, "geo", "dbip-country-lite.mmdb");

    /// <summary>Die geladene Tabelle, null wenn (noch) keine da ist oder sie unbrauchbar ist.</summary>
    public static CountryDb? Current
    {
        get
        {
            lock (Gate)
            {
                if (_db != null || _tried) return _db;
                _tried = true;
                try
                {
                    if (File.Exists(FilePath)) _db = new CountryDb(File.ReadAllBytes(FilePath));
                }
                catch (Exception e) { Log.Write("Ländertabelle unbrauchbar: " + e.Message); }
                return _db;
            }
        }
    }

    /// <summary>Lädt die aktuelle Tabelle herunter, prüft sie und ersetzt die alte erst danach. Gibt einen Fehlertext zurück, sonst null.</summary>
    public static async Task<string?> DownloadAsync(CancellationToken cancel)
    {
        CountryDb? had;
        lock (Gate) had = _db;
        try { await DownloadGate.WaitAsync(cancel).ConfigureAwait(false); }
        catch (OperationCanceledException) { return Loc.T("Abgebrochen.", "Cancelled."); }
        try
        {
            lock (Gate) if (_db != null && _db != had) return null;
            return await Download(cancel).ConfigureAwait(false);
        }
        finally { DownloadGate.Release(); }
    }

    private static async Task<string?> Download(CancellationToken cancel)
    {
        // HttpClient.Timeout gilt nur bis zu den Kopfzeilen; das Lesen des Inhalts begrenzt diese Frist (hängende Verbindung).
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        deadline.CancelAfter(TimeSpan.FromSeconds(120));
        var token = deadline.Token;
        string? temp = null;
        try
        {
            using var http = new HttpClient(new SocketsHttpHandler { AutomaticDecompression = DecompressionMethods.None, AllowAutoRedirect = false })
            {
                Timeout = TimeSpan.FromSeconds(90),
            };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("SnitchBox/" + App.Version);
            // DB-IP veröffentlicht die Tabelle am Monatsanfang unter dem Monat im Namen; ganz am Anfang des Monats evtl. noch die alte.
            var now = DateTime.UtcNow;
            string? last = null;
            foreach (var month in new[] { now, now.AddMonths(-1) })
            {
                // Jahr und Monat immer im gregorianischen Kalender (eine thailändische Regionaleinstellung ergäbe sonst 2569).
                var url = "https://download.db-ip.com/free/dbip-country-lite-" + month.ToString("yyyy-MM", CultureInfo.InvariantCulture) + ".mmdb.gz";
                using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
                if (response.StatusCode == HttpStatusCode.NotFound) { last = Loc.T("Die Ländertabelle ist auf dem Server nicht zu finden.", "The country table was not found on the server."); continue; }
                response.EnsureSuccessStatusCode();
                if (response.Content.Headers.ContentLength > MaxDownload) return Loc.T("Die Datei ist unerwartet groß.", "The file is unexpectedly large.");
                var packed = await ReadLimited(await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false), MaxDownload, token).ConfigureAwait(false);
                byte[] data;
                using (var gz = new GZipStream(new MemoryStream(packed), CompressionMode.Decompress))
                    data = await ReadLimited(gz, MaxUnpacked, token).ConfigureAwait(false);
                var db = new CountryDb(data); // wirft bei kaputter oder falscher Datei
                if (db.CountryOf(IPAddress.Parse("193.99.144.80")) == null && db.CountryOf(IPAddress.Parse("8.8.8.8")) == null)
                    return Loc.T("Die heruntergeladene Tabelle enthält keine Länder.", "The downloaded table contains no countries.");
                var dir = Path.GetDirectoryName(FilePath)!;
                Directory.CreateDirectory(dir);
                temp = FilePath + "." + Path.GetRandomFileName() + ".neu";
                await File.WriteAllBytesAsync(temp, data, token).ConfigureAwait(false);
                File.Move(temp, FilePath, true);
                temp = null;
                lock (Gate)
                {
                    _db = db;
                    _tried = true;
                }
                Log.Write($"Ländertabelle geladen: {url} ({data.Length:N0} Bytes, Stand {db.BuildTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)})");
                return null;
            }
            return last;
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { return Loc.T("Abgebrochen.", "Cancelled."); }
        catch (OperationCanceledException)
        {
            Log.Write("Ländertabelle herunterladen: Zeitüberschreitung");
            return Loc.T("Zeitüberschreitung beim Herunterladen der Ländertabelle.", "The download of the country table timed out.");
        }
        catch (Exception e)
        {
            Log.Write("Ländertabelle herunterladen: " + e.Message);
            return e is InvalidDataException ? Loc.T("Die heruntergeladene Datei ist keine gültige Ländertabelle.", "The downloaded file is not a valid country table.")
                : Loc.F("Herunterladen fehlgeschlagen: {0}", "Download failed: {0}", e.Message);
        }
        finally
        {
            if (temp != null) try { File.Delete(temp); } catch (Exception) { }
        }
    }

    private static async Task<byte[]> ReadLimited(Stream source, long limit, CancellationToken cancel)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int n;
        while ((n = await source.ReadAsync(chunk, cancel).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + n > limit) throw new InvalidDataException("Datei zu groß");
            buffer.Write(chunk, 0, n);
        }
        return buffer.ToArray();
    }
}
