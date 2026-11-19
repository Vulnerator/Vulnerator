using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace Vulnerator.Model.StigManager
{
    /// <summary>A STIG Manager Collection the signed-in account can read.</summary>
    public sealed class StigManagerCollection
    {
        public StigManagerCollection(string id, string name)
        {
            Id = id;
            Name = name;
        }

        public string Id { get; }
        public string Name { get; }
        public override string ToString() => Name + " (" + Id + ")";
    }

    /// <summary>An Asset in a Collection and the STIGs (benchmark IDs) assigned to it.</summary>
    public sealed class StigManagerAsset
    {
        public StigManagerAsset(string id, string name, IList<string> benchmarkIds)
        {
            Id = id;
            Name = name;
            BenchmarkIds = new List<string>(benchmarkIds ?? new string[0]).AsReadOnly();
        }

        public string Id { get; }
        public string Name { get; }
        public IReadOnlyList<string> BenchmarkIds { get; }
    }

    /// <summary>A checklist archive saved to disk, with what STIG Manager's _manifest.json says about it.</summary>
    public sealed class StigManagerArchive
    {
        public string ZipPath { get; internal set; }
        public int MemberCount { get; internal set; }
        public List<string> Members { get; } = new List<string>();
        /// <summary>One line per asset STIG Manager could not export (the request still returns HTTP 200).</summary>
        public List<string> Errors { get; } = new List<string>();
    }

    public sealed class StigManagerException : Exception
    {
        public StigManagerException(string message, Exception inner = null) : base(message, inner) { }
    }

    /// <summary>
    /// Reads checklists from a STIG Manager server (github.com/NUWCDIVNPT/stig-manager) through its REST API.
    /// Sign-in uses the server's OpenID Connect provider: client credentials (service account) or the system browser
    /// with Authorization Code + PKCE and a loopback redirect (works with CAC sign-in and non-admin accounts).
    /// Only the configured addresses are contacted, and only over HTTPS (plain HTTP is allowed for this computer only).
    /// The access token stays in memory; nothing is written to disk except the downloaded archive.
    /// </summary>
    public sealed class StigManagerClient : IDisposable
    {
        public const string DefaultScope = "openid stig-manager:collection:read";
        private static readonly TimeSpan RequestTimeout = TimeSpan.FromMinutes(30);
        private readonly HttpClient _http;
        private readonly string _apiBase;
        private readonly string _authority;
        private readonly string _clientId;
        private readonly string _scope;
        private string _tokenEndpoint;
        private string _authorizationEndpoint;
        private string _accessToken;

        public StigManagerClient(string apiAddress, string authority, string clientId, string scope, HttpMessageHandler handler = null)
        {
            _apiBase = CheckAddress(apiAddress, "STIG Manager API address").TrimEnd('/');
            _authority = CheckAddress(authority, "OIDC provider address").TrimEnd('/');
            if (string.IsNullOrWhiteSpace(clientId))
            { throw new StigManagerException("Enter the client ID registered for Vulnerator in the OIDC provider."); }
            _clientId = clientId.Trim();
            _scope = string.IsNullOrWhiteSpace(scope) ? DefaultScope : string.Join(" ", scope.Split((char[])null, StringSplitOptions.RemoveEmptyEntries));
            _http = new HttpClient(handler ?? CreateHandler(), true) { Timeout = RequestTimeout };
            _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public bool IsSignedIn => !string.IsNullOrEmpty(_accessToken);

        private static HttpMessageHandler CreateHandler()
        {
            // Windows' proxy settings with the user's own Windows credentials; TLS and certificate checks are Windows'
            // (SChannel), so the internal CA must be trusted in the Windows certificate store.
            HttpClientHandler handler = new HttpClientHandler { AllowAutoRedirect = false };
            try
            {
                IWebProxy proxy = WebRequest.GetSystemWebProxy();
                proxy.Credentials = CredentialCache.DefaultCredentials;
                handler.Proxy = proxy;
                handler.UseProxy = true;
            }
            catch (Exception)
            { }
            return handler;
        }

        /// <summary>
        /// The address must be an absolute https:// URL. http:// is accepted only for this computer (localhost,
        /// 127.0.0.1, ::1). Returns the trimmed address or throws <see cref="StigManagerException"/>.
        /// </summary>
        public static string CheckAddress(string address, string what)
        {
            Uri uri;
            if (string.IsNullOrWhiteSpace(address) || !Uri.TryCreate(address.Trim(), UriKind.Absolute, out uri))
            { throw new StigManagerException("Enter the " + what + " as a full URL (https://...)."); }
            if (uri.Scheme == Uri.UriSchemeHttps)
            { return address.Trim(); }
            if (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)
            { return address.Trim(); }
            throw new StigManagerException("The " + what + " must start with https:// (plain http is only allowed for this computer).");
        }

        #region Sign-in

        /// <summary>Reads the provider's discovery document (token and authorization endpoints).</summary>
        public async Task DiscoverAsync()
        {
            if (_tokenEndpoint != null)
            { return; }
            string url = _authority.EndsWith("/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase)
                ? _authority
                : _authority + "/.well-known/openid-configuration";
            Dictionary<string, object> document = await GetJsonAsync(url, false, "OIDC discovery").ConfigureAwait(true) as Dictionary<string, object>;
            if (document == null)
            { throw new StigManagerException("The OIDC provider's discovery document could not be read (" + url + ")."); }
            _tokenEndpoint = CheckAddress(Text(document, "token_endpoint"), "token endpoint");
            string authorization = Text(document, "authorization_endpoint");
            _authorizationEndpoint = string.IsNullOrEmpty(authorization) ? null : CheckAddress(authorization, "authorization endpoint");
        }

        /// <summary>Signs in as a service account (OAuth client credentials).</summary>
        public async Task SignInWithClientSecretAsync(string clientSecret)
        {
            if (string.IsNullOrEmpty(clientSecret))
            { throw new StigManagerException("Enter the client secret for the service account."); }
            await DiscoverAsync().ConfigureAwait(true);
            Dictionary<string, string> form = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", _clientId },
                { "client_secret", clientSecret },
                { "scope", _scope }
            };
            await RequestTokenAsync(form).ConfigureAwait(true);
        }

        /// <summary>
        /// Signs in through the system browser: Authorization Code with PKCE (S256) and a redirect to
        /// http://127.0.0.1:&lt;port&gt;/ on this computer. <paramref name="redirectPort"/> 0 picks a free port; set a
        /// fixed port when the provider does not accept any loopback port. <paramref name="openBrowser"/> opens the
        /// sign-in address (the default is the system browser). Waits up to <paramref name="timeout"/>.
        /// </summary>
        public async Task SignInWithBrowserAsync(int redirectPort, Action<Uri> openBrowser, TimeSpan timeout, CancellationToken cancellation)
        {
            await DiscoverAsync().ConfigureAwait(true);
            if (_authorizationEndpoint == null)
            { throw new StigManagerException("The OIDC provider does not publish an authorization endpoint; use a service account instead."); }
            if (redirectPort < 0 || redirectPort > 65535)
            { throw new StigManagerException("The sign-in port must be between 0 and 65535."); }
            string verifier = Base64Url(RandomBytes(32));
            string challenge = CodeChallenge(verifier);
            string state = Base64Url(RandomBytes(16));

            TcpListener listener = new TcpListener(IPAddress.Loopback, redirectPort);
            try
            {
                try { listener.Start(); }
                catch (SocketException exception)
                { throw new StigManagerException("Port " + redirectPort + " on this computer is in use; choose another sign-in port.", exception); }
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                string redirectUri = "http://127.0.0.1:" + port.ToString(CultureInfo.InvariantCulture) + "/";
                string separator = _authorizationEndpoint.Contains("?") ? "&" : "?";
                Uri signIn = new Uri(_authorizationEndpoint + separator +
                    "response_type=code" +
                    "&client_id=" + Uri.EscapeDataString(_clientId) +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                    "&scope=" + Uri.EscapeDataString(_scope) +
                    "&state=" + Uri.EscapeDataString(state) +
                    "&code_challenge=" + Uri.EscapeDataString(challenge) +
                    "&code_challenge_method=S256");
                (openBrowser ?? new Action<Uri>(OpenSystemBrowser))(signIn);

                using (CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                {
                    limit.CancelAfter(timeout);
                    using (limit.Token.Register(() => { try { listener.Stop(); } catch (Exception) { } }))
                    {
                        Dictionary<string, string> reply = await WaitForRedirectAsync(listener, limit.Token).ConfigureAwait(true);
                        string error;
                        if (reply.TryGetValue("error", out error))
                        {
                            string description;
                            reply.TryGetValue("error_description", out description);
                            throw new StigManagerException("Sign-in was refused: " + error + (string.IsNullOrEmpty(description) ? string.Empty : " (" + description + ")"));
                        }
                        string returnedState, code;
                        if (!reply.TryGetValue("state", out returnedState) || returnedState != state)
                        { throw new StigManagerException("Sign-in failed: the reply did not match this sign-in (state)."); }
                        if (!reply.TryGetValue("code", out code) || string.IsNullOrEmpty(code))
                        { throw new StigManagerException("Sign-in failed: no authorization code was returned."); }
                        Dictionary<string, string> form = new Dictionary<string, string>
                        {
                            { "grant_type", "authorization_code" },
                            { "client_id", _clientId },
                            { "code", code },
                            { "redirect_uri", redirectUri },
                            { "code_verifier", verifier }
                        };
                        await RequestTokenAsync(form).ConfigureAwait(true);
                    }
                }
            }
            finally
            {
                try { listener.Stop(); } catch (Exception) { }
            }
        }

        public void SignOut() { _accessToken = null; }

        private static void OpenSystemBrowser(Uri address)
        { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(address.AbsoluteUri) { UseShellExecute = true }); }

        /// <summary>Accepts loopback connections until one carries the sign-in reply (?code=...&amp;state=... or ?error=...).</summary>
        private static async Task<Dictionary<string, string>> WaitForRedirectAsync(TcpListener listener, CancellationToken cancellation)
        {
            while (true)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync().ConfigureAwait(false); }
                catch (Exception exception) when (exception is ObjectDisposedException || exception is SocketException || exception is InvalidOperationException)
                {
                    if (cancellation.IsCancellationRequested)
                    { throw new StigManagerException("Sign-in was cancelled or timed out before the browser returned."); }
                    throw new StigManagerException("Sign-in stopped: the local sign-in listener closed.", exception);
                }
                using (client)
                {
                    client.ReceiveTimeout = 10000;
                    client.SendTimeout = 10000;
                    NetworkStream stream = client.GetStream();
                    string requestLine;
                    try
                    {
                        StreamReader reader = new StreamReader(stream, Encoding.ASCII, false, 4096, true);
                        requestLine = await reader.ReadLineAsync().ConfigureAwait(false);
                        string header;
                        do { header = await reader.ReadLineAsync().ConfigureAwait(false); }
                        while (!string.IsNullOrEmpty(header));
                    }
                    catch (IOException)
                    { continue; }
                    Dictionary<string, string> query = ParseRequestQuery(requestLine);
                    bool isReply = query.ContainsKey("code") || query.ContainsKey("error");
                    string body = isReply
                        ? "<!DOCTYPE html><html><head><title>Vulnerator</title></head><body style=\"font-family:Segoe UI,sans-serif\"><h3>Vulnerator: sign-in " +
                          (query.ContainsKey("code") ? "complete" : "failed") + ".</h3><p>You can close this browser tab and return to Vulnerator.</p></body></html>"
                        : string.Empty;
                    byte[] bytes = Encoding.UTF8.GetBytes(body);
                    string head = (isReply ? "HTTP/1.1 200 OK" : "HTTP/1.1 404 Not Found") + "\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: " +
                                  bytes.Length.ToString(CultureInfo.InvariantCulture) + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
                    try
                    {
                        byte[] headBytes = Encoding.ASCII.GetBytes(head);
                        await stream.WriteAsync(headBytes, 0, headBytes.Length).ConfigureAwait(false);
                        await stream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
                        await stream.FlushAsync().ConfigureAwait(false);
                    }
                    catch (IOException)
                    { }
                    if (isReply)
                    { return query; }
                }
            }
        }

        /// <summary>"GET /?a=1&amp;b=2 HTTP/1.1" -> {a:1, b:2} (URL-decoded).</summary>
        public static Dictionary<string, string> ParseRequestQuery(string requestLine)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.Ordinal);
            if (string.IsNullOrEmpty(requestLine))
            { return result; }
            string[] parts = requestLine.Split(' ');
            if (parts.Length < 2 || !parts[0].Equals("GET", StringComparison.OrdinalIgnoreCase))
            { return result; }
            int question = parts[1].IndexOf('?');
            if (question < 0)
            { return result; }
            foreach (string pair in parts[1].Substring(question + 1).Split('&'))
            {
                if (pair.Length == 0) continue;
                int equals = pair.IndexOf('=');
                string key = Uri.UnescapeDataString((equals < 0 ? pair : pair.Substring(0, equals)).Replace('+', ' '));
                string value = equals < 0 ? string.Empty : Uri.UnescapeDataString(pair.Substring(equals + 1).Replace('+', ' '));
                if (!result.ContainsKey(key))
                { result[key] = value; }
            }
            return result;
        }

        private async Task RequestTokenAsync(Dictionary<string, string> form)
        {
            _accessToken = null;
            HttpResponseMessage response;
            try
            {
                using (FormUrlEncodedContent content = new FormUrlEncodedContent(form))
                { response = await _http.PostAsync(_tokenEndpoint, content).ConfigureAwait(true); }
            }
            catch (Exception exception) when (exception is HttpRequestException || exception is TaskCanceledException)
            { throw new StigManagerException("The OIDC provider could not be reached (" + Describe(exception) + ").", exception); }
            using (response)
            {
                string text = await response.Content.ReadAsStringAsync().ConfigureAwait(true);
                Dictionary<string, object> json = TryParse(text) as Dictionary<string, object>;
                if (!response.IsSuccessStatusCode)
                {
                    string error = json == null ? null : Text(json, "error");
                    string description = json == null ? null : Text(json, "error_description");
                    throw new StigManagerException("Sign-in was refused by the OIDC provider (HTTP " + (int)response.StatusCode +
                        (string.IsNullOrEmpty(error) ? string.Empty : ", " + error) + (string.IsNullOrEmpty(description) ? string.Empty : ": " + description) + ").");
                }
                string token = json == null ? null : Text(json, "access_token");
                if (string.IsNullOrEmpty(token))
                { throw new StigManagerException("The OIDC provider did not return an access token."); }
                _accessToken = token;
            }
        }

        /// <summary>PKCE S256 code challenge (RFC 7636): BASE64URL(SHA-256(ASCII(verifier))). Uses Windows CNG (FIPS-approved).</summary>
        public static string CodeChallenge(string verifier)
        {
            using (SHA256 sha = new SHA256Cng())
            { return Base64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier))); }
        }

        private static byte[] RandomBytes(int count)
        {
            byte[] bytes = new byte[count];
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
            { random.GetBytes(bytes); }
            return bytes;
        }

        public static string Base64Url(byte[] bytes)
        { return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }

        #endregion

        #region API

        /// <summary>GET /collections: the Collections this account can read.</summary>
        public async Task<List<StigManagerCollection>> GetCollectionsAsync()
        {
            object[] items = await GetJsonAsync(_apiBase + "/collections", true, "list Collections").ConfigureAwait(true) as object[];
            List<StigManagerCollection> collections = new List<StigManagerCollection>();
            foreach (Dictionary<string, object> item in (items ?? new object[0]).OfType<Dictionary<string, object>>())
            {
                string id = Text(item, "collectionId");
                if (!string.IsNullOrEmpty(id))
                { collections.Add(new StigManagerCollection(id, Text(item, "name") ?? id)); }
            }
            return collections.OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>GET /assets?collectionId=..&amp;projection=stigs: the Assets in a Collection with their STIGs.</summary>
        public async Task<List<StigManagerAsset>> GetAssetsAsync(string collectionId)
        {
            string url = _apiBase + "/assets?collectionId=" + Uri.EscapeDataString(collectionId) + "&projection=stigs";
            object[] items = await GetJsonAsync(url, true, "list Assets").ConfigureAwait(true) as object[];
            List<StigManagerAsset> assets = new List<StigManagerAsset>();
            foreach (Dictionary<string, object> item in (items ?? new object[0]).OfType<Dictionary<string, object>>())
            {
                string id = Text(item, "assetId");
                if (string.IsNullOrEmpty(id)) continue;
                List<string> benchmarks = new List<string>();
                object stigs;
                if (item.TryGetValue("stigs", out stigs) && stigs is object[])
                {
                    foreach (object stig in (object[])stigs)
                    {
                        Dictionary<string, object> stigObject = stig as Dictionary<string, object>;
                        string benchmark = stigObject != null ? Text(stigObject, "benchmarkId") : stig as string;
                        if (!string.IsNullOrEmpty(benchmark)) benchmarks.Add(benchmark);
                    }
                }
                assets.Add(new StigManagerAsset(id, Text(item, "name") ?? id, benchmarks));
            }
            return assets.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>
        /// POST /collections/{id}/archive/ckl?mode=mono (or /archive/cklb): one checklist per Asset and STIG (the
        /// default revision of every STIG on each Asset), streamed to <paramref name="zipPath"/>. Then reads the
        /// archive's _manifest.json, which lists the Assets STIG Manager could not export.
        /// </summary>
        public async Task<StigManagerArchive> DownloadChecklistsAsync(string collectionId, IEnumerable<string> assetIds, bool cklb, string zipPath)
        {
            List<string> ids = (assetIds ?? new string[0]).Where(i => !string.IsNullOrWhiteSpace(i)).Distinct().ToList();
            if (ids.Count == 0)
            { throw new StigManagerException("Select at least one Asset."); }
            string body = new JavaScriptSerializer().Serialize(ids.Select(i => new Dictionary<string, object> { { "assetId", i } }).ToArray());
            string url = _apiBase + "/collections/" + Uri.EscapeDataString(collectionId) + "/archive/" + (cklb ? "cklb" : "ckl") + "?mode=mono";
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(zipPath)));
            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, url))
            {
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
                using (HttpResponseMessage response = await SendAsync(request, HttpCompletionOption.ResponseHeadersRead, "download checklists").ConfigureAwait(true))
                using (Stream source = await response.Content.ReadAsStreamAsync().ConfigureAwait(true))
                using (FileStream target = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None))
                { await source.CopyToAsync(target).ConfigureAwait(true); }
            }
            return ReadArchive(zipPath);
        }

        /// <summary>Reads a STIG Manager checklist archive: its members and the errors in _manifest.json.</summary>
        public static StigManagerArchive ReadArchive(string zipPath)
        {
            StigManagerArchive archive = new StigManagerArchive { ZipPath = zipPath };
            try
            {
                using (ZipArchive zip = ZipFile.OpenRead(zipPath))
                {
                    foreach (ZipArchiveEntry entry in zip.Entries)
                    {
                        if (entry.FullName.Equals("_manifest.json", StringComparison.OrdinalIgnoreCase))
                        {
                            using (StreamReader reader = new StreamReader(entry.Open(), Encoding.UTF8))
                            { ReadManifest(reader.ReadToEnd(), archive); }
                        }
                        else if (entry.Name.Length > 0)
                        { archive.Members.Add(entry.FullName); }
                    }
                }
            }
            catch (InvalidDataException exception)
            { throw new StigManagerException("STIG Manager did not return a readable zip file.", exception); }
            archive.MemberCount = archive.Members.Count;
            return archive;
        }

        private static void ReadManifest(string json, StigManagerArchive archive)
        {
            Dictionary<string, object> manifest = TryParse(json) as Dictionary<string, object>;
            object errors;
            if (manifest == null || !manifest.TryGetValue("errors", out errors) || !(errors is object[]))
            { return; }
            foreach (object error in (object[])errors)
            {
                Dictionary<string, object> item = error as Dictionary<string, object>;
                if (item == null) continue;
                string asset = Text(item, "assetName") ?? Text(item, "assetId");
                string message = Text(item, "message");
                object inner;
                if (string.IsNullOrEmpty(message) && item.TryGetValue("error", out inner) && inner is Dictionary<string, object>)
                { message = Text((Dictionary<string, object>)inner, "message"); }
                archive.Errors.Add((string.IsNullOrEmpty(asset) ? "Archive" : asset) + ": " + (message ?? "not exported"));
            }
        }

        #endregion

        #region HTTP and JSON helpers

        private async Task<object> GetJsonAsync(string url, bool authorized, string what)
        {
            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url))
            {
                if (!authorized)
                { request.Properties["anonymous"] = true; }
                using (HttpResponseMessage response = await SendAsync(request, HttpCompletionOption.ResponseContentRead, what).ConfigureAwait(true))
                {
                    string text = await response.Content.ReadAsStringAsync().ConfigureAwait(true);
                    object parsed = TryParse(text);
                    if (parsed == null)
                    { throw new StigManagerException("Could not " + what + ": the reply was not JSON. Check that the address is the API address (it usually ends in /api)."); }
                    return parsed;
                }
            }
        }

        private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, HttpCompletionOption completion, string what)
        {
            bool anonymous = request.Properties.ContainsKey("anonymous");
            if (!anonymous)
            {
                if (!IsSignedIn)
                { throw new StigManagerException("Sign in to STIG Manager first."); }
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            }
            HttpResponseMessage response;
            try
            { response = await _http.SendAsync(request, completion).ConfigureAwait(true); }
            catch (Exception exception) when (exception is HttpRequestException || exception is TaskCanceledException)
            { throw new StigManagerException("Could not " + what + ": the server could not be reached (" + Describe(exception) + ").", exception); }
            if (response.IsSuccessStatusCode)
            { return response; }
            int status = (int)response.StatusCode;
            string detail = string.Empty;
            try
            {
                Dictionary<string, object> json = TryParse(await response.Content.ReadAsStringAsync().ConfigureAwait(true)) as Dictionary<string, object>;
                if (json != null) detail = Text(json, "message") ?? Text(json, "error") ?? string.Empty;
            }
            catch (Exception) { }
            response.Dispose();
            string reason;
            switch (status)
            {
                case 401: reason = "the sign-in is not valid or has expired; sign in again"; break;
                case 403: reason = "this account is not allowed (it needs the stig-manager:collection:read scope and a grant to the Collection)"; break;
                case 404: reason = "not found; check the API address (it usually ends in /api)"; break;
                default:
                    reason = status >= 300 && status < 400 ? "the server redirected the request; enter the final https:// address" : "HTTP " + status;
                    break;
            }
            if (status == 401) _accessToken = null;
            throw new StigManagerException("Could not " + what + ": " + reason + (string.IsNullOrEmpty(detail) ? "." : " (" + detail + ")."));
        }

        private static string Describe(Exception exception)
        {
            Exception inner = exception;
            while (inner.InnerException != null) inner = inner.InnerException;
            return exception is TaskCanceledException ? "timed out" : inner.Message;
        }

        private static object TryParse(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            try { return new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 }.DeserializeObject(json); }
            catch (Exception) { return null; }
        }

        private static string Text(Dictionary<string, object> json, string key)
        {
            object value;
            if (json == null || !json.TryGetValue(key, out value) || value == null) return null;
            if (value is string) return (string)value;
            if (value is IEnumerable) return null;
            return Convert.ToString(value, CultureInfo.InvariantCulture);
        }

        #endregion

        public void Dispose()
        {
            _accessToken = null;
            _http.Dispose();
        }
    }
}
