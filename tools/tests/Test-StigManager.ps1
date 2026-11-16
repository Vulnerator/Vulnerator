# Checks the STIG Manager pull (Vulnerability Management > Ingest > Pull from STIG Manager...) against a fake STIG
# Manager server started here on 127.0.0.1: OIDC discovery, service-account sign-in, browser sign-in (Authorization
# Code + PKCE through the loopback redirect, driven by a fake browser), Collections, Assets, the checklist archive
# (streamed to disk, _manifest.json errors read), and that the zip goes through the normal checklist collector.
# Also checks the address rules (https only, except this computer), the PKCE challenge (RFC 7636 test vector) and the
# DPAPI-protected secret. The checklist served is the synthetic fixture stigman-export.ckl.
#
# Windows PowerShell 5.1 (.NET Framework 4.8). Pure ASCII; no PowerShell 7 syntax.
# Usage: %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -File tools\tests\Test-StigManager.ps1 -BinDir bin\Release
param([Parameter(Mandatory = $true)][string]$BinDir)
$ErrorActionPreference = 'Stop'

$binPath = (Resolve-Path $BinDir).Path
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ('VulneratorStigMan_' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($workDir)
$failures = New-Object System.Collections.Generic.List[string]

function Fail([string]$Message) {
    Write-Host ('FAIL ' + $Message)
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host ('::error::' + ($Message -replace "`r?`n", ' ')) }
    exit 1
}
function Check([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host ('ok   ' + $Message) }
    else {
        Write-Host ('FAIL ' + $Message)
        if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host ('::error::FAIL ' + ($Message -replace "`r?`n", ' ')) }
        $failures.Add($Message)
    }
}
# Runs a task-returning call; returns the result, or the innermost exception message prefixed with "ERROR: ".
function Await([scriptblock]$Call) {
    try {
        $task = & $Call
        $awaiter = $task.GetAwaiter()
        return $awaiter.GetResult()
    }
    catch {
        $e = $_.Exception
        while ($null -ne $e.InnerException -and ($e -is [System.Management.Automation.MethodInvocationException] -or $e -is [System.AggregateException] -or $e -is [System.Management.Automation.RuntimeException])) { $e = $e.InnerException }
        return ('ERROR: ' + $e.GetType().Name + ': ' + $e.Message)
    }
}

$fakeServer = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class FakeStigManager
{
    public static string Base;
    public static string CklPath;
    public static string ClientSecret = "s3cret";
    public static string AuthMode = "ok";
    public static string Challenge;
    public static string RedirectUri;
    public static bool VerifierMatched;
    public static string LastArchivePath;
    public static string LastArchiveBody;
    public static string LastArchiveAuth;
    public static string BrowserResult;
    public static readonly List<string> TokenGrants = new List<string>();
    private static HttpListener _listener;

    public static void Start(int port, string cklPath)
    {
        CklPath = cklPath;
        Base = "http://127.0.0.1:" + port;
        _listener = new HttpListener();
        _listener.Prefixes.Add(Base + "/");
        _listener.Start();
        Thread thread = new Thread(Loop) { IsBackground = true };
        thread.Start();
    }

    public static void Stop() { try { _listener.Stop(); } catch (Exception) { } }

    private static void Loop()
    {
        while (_listener.IsListening)
        {
            HttpListenerContext context;
            try { context = _listener.GetContext(); }
            catch (Exception) { return; }
            try { Handle(context); }
            catch (Exception exception) { Reply(context, 500, "{\"message\":\"" + exception.Message.Replace("\"", "'") + "\"}"); }
        }
    }

    private static void Reply(HttpListenerContext context, int status, string json)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json";
        context.Response.ContentLength64 = bytes.Length;
        context.Response.OutputStream.Write(bytes, 0, bytes.Length);
        context.Response.Close();
    }

    private static Dictionary<string, string> Form(string body)
    {
        Dictionary<string, string> form = new Dictionary<string, string>();
        foreach (string pair in body.Split('&'))
        {
            int i = pair.IndexOf('=');
            if (i < 0) continue;
            form[Uri.UnescapeDataString(pair.Substring(0, i).Replace('+', ' '))] = Uri.UnescapeDataString(pair.Substring(i + 1).Replace('+', ' '));
        }
        return form;
    }

    private static string B64Url(byte[] bytes) { return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }

    private static bool Authorized(HttpListenerContext context)
    {
        string auth = context.Request.Headers["Authorization"] ?? "";
        return auth == "Bearer tok-cc" || auth == "Bearer tok-ac";
    }

    private static void Handle(HttpListenerContext context)
    {
        string path = context.Request.Url.AbsolutePath;
        string method = context.Request.HttpMethod;
        string body = new StreamReader(context.Request.InputStream, Encoding.UTF8).ReadToEnd();
        if (path == "/realms/test/.well-known/openid-configuration")
        {
            Reply(context, 200, "{\"issuer\":\"" + Base + "/realms/test\",\"token_endpoint\":\"" + Base + "/realms/test/token\",\"authorization_endpoint\":\"" + Base + "/realms/test/auth\"}");
            return;
        }
        if (path == "/realms/test/auth")
        {
            Challenge = context.Request.QueryString["code_challenge"];
            RedirectUri = context.Request.QueryString["redirect_uri"];
            string state = context.Request.QueryString["state"];
            bool ok = context.Request.QueryString["response_type"] == "code" && context.Request.QueryString["code_challenge_method"] == "S256" &&
                      context.Request.QueryString["client_id"] == "vulnerator" && (context.Request.QueryString["scope"] ?? "").Contains("stig-manager:collection:read");
            string location = RedirectUri + (AuthMode == "ok" && ok ? "?code=code-123&state=" : "?error=access_denied&error_description=User+said+no&state=") + Uri.EscapeDataString(state ?? "");
            context.Response.StatusCode = 302;
            context.Response.RedirectLocation = location;
            context.Response.Close();
            return;
        }
        if (path == "/realms/test/token" && method == "POST")
        {
            Dictionary<string, string> form = Form(body);
            string grant;
            form.TryGetValue("grant_type", out grant);
            TokenGrants.Add(grant);
            if (grant == "client_credentials")
            {
                if (form["client_id"] != "vulnerator" || form["client_secret"] != ClientSecret)
                { Reply(context, 401, "{\"error\":\"unauthorized_client\",\"error_description\":\"Invalid client secret\"}"); return; }
                Reply(context, 200, "{\"access_token\":\"tok-cc\",\"token_type\":\"Bearer\",\"expires_in\":300}");
                return;
            }
            if (grant == "authorization_code")
            {
                string expected;
                using (SHA256 sha = SHA256.Create()) { expected = B64Url(sha.ComputeHash(Encoding.ASCII.GetBytes(form["code_verifier"]))); }
                VerifierMatched = expected == Challenge;
                if (form["code"] != "code-123" || !VerifierMatched || form["redirect_uri"] != RedirectUri)
                { Reply(context, 400, "{\"error\":\"invalid_grant\"}"); return; }
                Reply(context, 200, "{\"access_token\":\"tok-ac\",\"token_type\":\"Bearer\",\"expires_in\":300}");
                return;
            }
            Reply(context, 400, "{\"error\":\"unsupported_grant_type\"}");
            return;
        }
        if (!path.StartsWith("/api/")) { Reply(context, 404, "{\"message\":\"not found\"}"); return; }
        if (!Authorized(context)) { Reply(context, 401, "{\"message\":\"no token\"}"); return; }
        if (path == "/api/collections" && method == "GET")
        {
            Reply(context, 200, "[{\"collectionId\":\"21\",\"name\":\"Test Collection\"},{\"collectionId\":\"7\",\"name\":\"Another Collection\"}]");
            return;
        }
        if (path == "/api/assets" && method == "GET")
        {
            if (context.Request.QueryString["collectionId"] != "21" || context.Request.QueryString["projection"] != "stigs")
            { Reply(context, 400, "{\"message\":\"bad query\"}"); return; }
            Reply(context, 200, "[{\"assetId\":\"102\",\"name\":\"stigman-host02\",\"stigs\":[]}," +
                                "{\"assetId\":\"101\",\"name\":\"STIGMAN-HOST01\",\"stigs\":[{\"benchmarkId\":\"Test_App_STIG\",\"revisionStr\":\"V1R2\",\"benchmarkDate\":\"2026-02-05\",\"revisionPinned\":false,\"ruleCount\":4}]}]");
            return;
        }
        if (path == "/api/collections/21/archive/ckl" && method == "POST")
        {
            LastArchivePath = context.Request.Url.PathAndQuery;
            LastArchiveBody = body;
            LastArchiveAuth = context.Request.Headers["Authorization"];
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/zip";
            context.Response.SendChunked = true;
            using (MemoryStream buffer = new MemoryStream())
            {
                using (ZipArchive zip = new ZipArchive(buffer, ZipArchiveMode.Create, true))
                {
                    ZipArchiveEntry ckl = zip.CreateEntry("CUI_STIGMAN-HOST01-Test_App_STIG-V1R2.ckl");
                    using (Stream s = ckl.Open()) { byte[] b = File.ReadAllBytes(CklPath); s.Write(b, 0, b.Length); }
                    ZipArchiveEntry manifest = zip.CreateEntry("_manifest.json");
                    using (StreamWriter w = new StreamWriter(manifest.Open()))
                    { w.Write("{\"errorCount\":1,\"errors\":[{\"assetId\":\"103\",\"assetName\":\"stigman-host03\",\"stigs\":[],\"error\":{\"message\":\"No STIGs assigned\"}}],\"memberCount\":1,\"members\":[\"CUI_STIGMAN-HOST01-Test_App_STIG-V1R2.ckl\"]}"); }
                }
                buffer.Position = 0;
                buffer.CopyTo(context.Response.OutputStream);
            }
            context.Response.Close();
            return;
        }
        Reply(context, 404, "{\"message\":\"not found\"}");
    }

    /// <summary>A fake browser: opens the sign-in address, follows the provider's redirect to the loopback listener.</summary>
    public static void Browser(Uri signIn)
    {
        Task.Run(() =>
        {
            try
            {
                HttpWebRequest first = (HttpWebRequest)WebRequest.Create(signIn);
                first.AllowAutoRedirect = false;
                first.Proxy = null;
                string location;
                using (HttpWebResponse response = (HttpWebResponse)first.GetResponse()) { location = response.Headers["Location"]; }
                HttpWebRequest second = (HttpWebRequest)WebRequest.Create(location);
                second.Proxy = null;
                using (HttpWebResponse response = (HttpWebResponse)second.GetResponse())
                using (StreamReader reader = new StreamReader(response.GetResponseStream()))
                { BrowserResult = (int)response.StatusCode + " " + reader.ReadToEnd(); }
            }
            catch (WebException exception)
            {
                HttpWebResponse response = exception.Response as HttpWebResponse;
                BrowserResult = response == null ? "error " + exception.Message : (int)response.StatusCode + " " + new StreamReader(response.GetResponseStream()).ReadToEnd();
            }
            catch (Exception exception) { BrowserResult = "error " + exception.Message; }
        });
    }

    /// <summary>A browser that never comes back (the user closed it).</summary>
    public static void NoBrowser(Uri signIn) { }

    public static int FreePort()
    {
        System.Net.Sockets.TcpListener probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }
}
'@

try {
    # Same set-up as Test-AddOns.ps1: the application's configuration, then the program's assemblies.
    [AppDomain]::CurrentDomain.SetData('APP_CONFIG_FILE', (Join-Path $binPath 'Vulnerator.exe.config'))
    Add-Type -AssemblyName System.Configuration
    $manager = [System.Configuration.ConfigurationManager]
    $manager.GetField('s_initState', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, 0)
    $manager.GetField('s_configSystem', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $null)
    ($manager.Assembly.GetTypes() | Where-Object { $_.FullName -eq 'System.Configuration.ClientConfigPaths' }).GetField('s_current', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $null)
    [System.IO.Directory]::SetCurrentDirectory($binPath)
    Add-Type -AssemblyName System.Net.Http, System.Web.Extensions, System.Security, System.IO.Compression, System.IO.Compression.FileSystem
    $app = [System.Reflection.Assembly]::LoadFrom((Join-Path $binPath 'Vulnerator.exe'))
    foreach ($name in 'log4net.dll', 'System.Data.SQLite.dll') {
        $path = Join-Path $binPath $name
        if (Test-Path $path) { [void][System.Reflection.Assembly]::LoadFrom($path) }
    }
    Add-Type -TypeDefinition $fakeServer -ReferencedAssemblies ([System.Net.HttpListener].Assembly.Location), ([System.Linq.Enumerable].Assembly.Location), ([System.IO.Compression.ZipArchive].Assembly.Location)
    $clientType = [Vulnerator.Model.StigManager.StigManagerClient]

    # --- Address rules and PKCE --------------------------------------------------------------
    $refused = $null
    try { [void]$clientType::CheckAddress('http://stigman.example.test/api', 'API address') } catch { $refused = $_.Exception.InnerException.Message }
    Check ($refused -like '*https*') ('plain http to another computer is refused (' + $refused + ')')
    Check ($clientType::CheckAddress('https://stigman.example.test/api', 'x') -eq 'https://stigman.example.test/api') 'https addresses are accepted'
    Check ($clientType::CheckAddress('http://127.0.0.1:5000/api', 'x') -eq 'http://127.0.0.1:5000/api') 'http is accepted for this computer only'
    $relative = $null
    try { [void]$clientType::CheckAddress('stigman/api', 'API address') } catch { $relative = $_.Exception.InnerException.Message }
    Check ($relative -like '*full URL*') ('a relative address is refused (' + $relative + ')')
    $challenge = $clientType::CodeChallenge('dBjftJeZ4CVP-mJ92K27uhbUJU1p1r_wW1gFWFOEjXk')
    Check ($challenge -eq 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM') ('PKCE S256 matches the RFC 7636 test vector (' + $challenge + ')')
    $query = $clientType::ParseRequestQuery('GET /?code=a%2Fb&state=x+y&empty HTTP/1.1')
    Check ($query['code'] -eq 'a/b' -and $query['state'] -eq 'x y' -and $query.ContainsKey('empty')) 'the loopback redirect query is decoded'

    # --- Fake server -------------------------------------------------------------------------
    $port = [FakeStigManager]::FreePort()
    [FakeStigManager]::Start($port, (Join-Path $fixtures 'stigman-export.ckl'))
    $base = [FakeStigManager]::Base
    $api = $base + '/api'
    $authority = $base + '/realms/test'
    Write-Host ('     fake STIG Manager at ' + $base)

    # Not signed in: nothing is sent.
    $client = New-Object Vulnerator.Model.StigManager.StigManagerClient($api, $authority, 'vulnerator', '', $null)
    $notSigned = Await { $client.GetCollectionsAsync() }
    Check ($notSigned -like 'ERROR:*Sign in*') ('API calls need a sign-in first (' + $notSigned + ')')

    # Service account: a wrong secret is refused with the provider's reason, the right one signs in.
    $wrong = Await { $client.SignInWithClientSecretAsync('nope') }
    Check ($wrong -like 'ERROR:*Invalid client secret*' -and -not $client.IsSignedIn) ('a wrong client secret is refused with the reason (' + $wrong + ')')
    $right = Await { $client.SignInWithClientSecretAsync('s3cret') }
    Check ($client.IsSignedIn -and @([FakeStigManager]::TokenGrants)[-1] -eq 'client_credentials') ('the service account signs in (' + $right + ')')

    $collections = Await { $client.GetCollectionsAsync() }
    $collectionNames = if ($collections -is [string]) { $collections } else { (@($collections) | ForEach-Object { $_.Id + ':' + $_.Name }) -join ', ' }
    Check (-not ($collections -is [string]) -and @($collections).Count -eq 2 -and @($collections)[0].Name -eq 'Another Collection') ('Collections are listed by name (' + $collectionNames + ')')
    $assets = Await { $client.GetAssetsAsync('21') }
    $assetText = if ($assets -is [string]) { $assets } else { (@($assets) | ForEach-Object { $_.Name + '[' + (@($_.BenchmarkIds) -join '+') + ']' }) -join ', ' }
    Check (-not ($assets -is [string]) -and @($assets).Count -eq 2 -and @($assets)[0].Name -eq 'STIGMAN-HOST01' -and @(@($assets)[0].BenchmarkIds)[0] -eq 'Test_App_STIG' -and @(@($assets)[1].BenchmarkIds).Count -eq 0) ('Assets come with their STIGs (' + $assetText + ')')

    $zipPath = Join-Path $workDir 'download\Test Collection-CKL.zip'
    $ids = New-Object 'System.Collections.Generic.List[string]'
    $ids.Add('101'); $ids.Add('103')
    $archive = Await { $client.DownloadChecklistsAsync('21', $ids, $false, $zipPath) }
    $archiveText = if ($archive -is [string]) { $archive } else { 'members ' + $archive.MemberCount + ', errors: ' + ($archive.Errors -join '; ') }
    Check (-not ($archive -is [string]) -and $archive.MemberCount -eq 1 -and (Test-Path $zipPath)) ('the checklist zip is saved (' + $archiveText + ')')
    Check (-not ($archive -is [string]) -and $archive.Errors.Count -eq 1 -and $archive.Errors[0] -eq 'stigman-host03: No STIGs assigned') ('Assets STIG Manager could not export are reported from _manifest.json (' + $archiveText + ')')
    Check ([FakeStigManager]::LastArchivePath -eq '/api/collections/21/archive/ckl?mode=mono') ('one checklist per Asset and STIG is asked for (' + [FakeStigManager]::LastArchivePath + ')')
    Check ([FakeStigManager]::LastArchiveBody -eq '[{"assetId":"101"},{"assetId":"103"}]') ('the request names the selected Assets (' + [FakeStigManager]::LastArchiveBody + ')')
    Check ([FakeStigManager]::LastArchiveAuth -eq 'Bearer tok-cc') 'the access token is sent as a Bearer token'
    $noAssets = Await { $client.DownloadChecklistsAsync('21', (New-Object 'System.Collections.Generic.List[string]'), $false, $zipPath) }
    Check ($noAssets -like 'ERROR:*at least one Asset*') ('an empty selection is refused before contacting the server (' + $noAssets + ')')

    # The zip goes through the same collector as a zip picked from disk (Import CKL / CKLB).
    $collector = New-Object Vulnerator.Model.BusinessLogic.IngestionFileCollector -ArgumentList (, [string[]]@('.ckl', '.cklb'))
    $collector.ExtractionFolder = Join-Path $workDir 'extract'
    $collector.Add($zipPath)
    $found = @($collector.Files)
    Check ($found.Count -eq 1 -and $found[0].Path -like '*CUI_STIGMAN-HOST01-Test_App_STIG-V1R2.ckl') ('the ingestion collector finds the checklist and skips _manifest.json (' + (($found | ForEach-Object { $_.Path }) -join ', ') + ')')
    if ($found.Count -eq 1) {
        $file = New-Object Vulnerator.Model.Object.File ($found[0].DisplayName, 'Checklist', 'Ready', $found[0].Path, 'True')
        $file = (New-Object Vulnerator.Model.BusinessLogic.CklReader).ObtainIdentifiers($file)
        Check ($file.FileHostName -eq 'STIGMAN-HOST01' -and $file.FileIpAddress -eq '10.20.30.40') ('the checklist host is read for the ingestion list (' + $file.FileHostName + ' / ' + $file.FileIpAddress + ')')
    }
    $client.Dispose()

    # --- Browser sign-in (Authorization Code + PKCE, loopback redirect) ----------------------
    $browser = [Delegate]::CreateDelegate([Action[Uri]], [FakeStigManager].GetMethod('Browser'))
    $browserClient = New-Object Vulnerator.Model.StigManager.StigManagerClient($api, $authority, 'vulnerator', 'openid stig-manager:collection:read', $null)
    $signed = Await { $browserClient.SignInWithBrowserAsync(0, $browser, [TimeSpan]::FromSeconds(30), [System.Threading.CancellationToken]::None) }
    Check ($browserClient.IsSignedIn -and [FakeStigManager]::VerifierMatched) ('browser sign-in with PKCE completes (' + $signed + '; verifier matched ' + [FakeStigManager]::VerifierMatched + ')')
    Check ([FakeStigManager]::RedirectUri -match '^http://127\.0\.0\.1:\d+/$') ('the redirect is to this computer (' + [FakeStigManager]::RedirectUri + ')')
    Start-Sleep -Milliseconds 300
    Check ([FakeStigManager]::BrowserResult -like '200 *sign-in complete*') ('the browser is told sign-in is complete (' + [FakeStigManager]::BrowserResult + ')')
    $afterBrowser = Await { $browserClient.GetCollectionsAsync() }
    Check (-not ($afterBrowser -is [string]) -and @($afterBrowser).Count -eq 2) 'the browser sign-in token reads Collections'
    $browserClient.Dispose()

    [FakeStigManager]::AuthMode = 'deny'
    $deniedClient = New-Object Vulnerator.Model.StigManager.StigManagerClient($api, $authority, 'vulnerator', '', $null)
    $denied = Await { $deniedClient.SignInWithBrowserAsync(0, $browser, [TimeSpan]::FromSeconds(30), [System.Threading.CancellationToken]::None) }
    Check ($denied -like 'ERROR:*access_denied*User said no*' -and -not $deniedClient.IsSignedIn) ('a refused browser sign-in shows the reason (' + $denied + ')')
    $deniedClient.Dispose()

    $fixedPort = [FakeStigManager]::FreePort()
    $silent = [Delegate]::CreateDelegate([Action[Uri]], [FakeStigManager].GetMethod('NoBrowser'))
    $timeoutClient = New-Object Vulnerator.Model.StigManager.StigManagerClient($api, $authority, 'vulnerator', '', $null)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = Await { $timeoutClient.SignInWithBrowserAsync($fixedPort, $silent, [TimeSpan]::FromSeconds(2), [System.Threading.CancellationToken]::None) }
    $watch.Stop()
    Check ($timedOut -like 'ERROR:*cancelled or timed out*' -and $watch.Elapsed.TotalSeconds -lt 15) ('browser sign-in stops waiting at the time limit (' + $timedOut + ', ' + [int]$watch.Elapsed.TotalSeconds + ' s)')
    $probe = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $fixedPort)
    $released = $true
    try { $probe.Start(); $probe.Stop() } catch { $released = $false }
    Check $released 'the sign-in port is released afterwards'
    $timeoutClient.Dispose()

    # --- Wrong API address -------------------------------------------------------------------
    $badClient = New-Object Vulnerator.Model.StigManager.StigManagerClient(($base + '/wrong'), $authority, 'vulnerator', '', $null)
    [void](Await { $badClient.SignInWithClientSecretAsync('s3cret') })
    $notFound = Await { $badClient.GetCollectionsAsync() }
    Check ($notFound -like 'ERROR:*not found*/api*') ('a wrong API address says so (' + $notFound + ')')
    $badClient.Dispose()

    # --- Remembered secret (DPAPI, current Windows account) ----------------------------------
    $settingsType = $app.GetType('Vulnerator.Properties.Settings', $true)
    $defaultSettings = $settingsType.GetProperty('Default', [System.Reflection.BindingFlags]'Public,Static').GetValue($null, $null)
    $indexer = [System.Configuration.ApplicationSettingsBase].GetProperty('Item', [Type[]]@([string]))
    Check ($indexer.GetValue($defaultSettings, [object[]]@('StigManagerEnabled')) -eq $false) 'STIG Manager connections are off by default'
    [Vulnerator.Model.StigManager.StigManagerSettings]::SaveSecret('p@ss-W0rd')
    $stored = [string]$indexer.GetValue($defaultSettings, [object[]]@('StigManagerClientSecret'))
    Check ($stored.Length -gt 20 -and $stored -notlike '*p@ss*') 'the remembered secret is stored encrypted'
    Check ([Vulnerator.Model.StigManager.StigManagerSettings]::LoadSecret() -eq 'p@ss-W0rd') 'the remembered secret is read back'
    [Vulnerator.Model.StigManager.StigManagerSettings]::SaveSecret('')
    Check ([string]$indexer.GetValue($defaultSettings, [object[]]@('StigManagerClientSecret')) -eq '' -and [Vulnerator.Model.StigManager.StigManagerSettings]::LoadSecret() -eq '') 'forgetting the secret clears it'
}
catch {
    $failures.Add('Unhandled error: ' + $_.Exception.ToString())
    Write-Host ('ERROR ' + $_.Exception.ToString())
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host ('::error::ERROR ' + ($_.Exception.ToString() -replace "`r?`n", ' ') + ' AT ' + ($_.InvocationInfo.PositionMessage -replace "`r?`n", ' ')) }
}
finally {
    try { [FakeStigManager]::Stop() } catch { }
    try { Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}

if ($failures.Count -gt 0) { Fail ('' + $failures.Count + ' STIG Manager check(s) failed: ' + ($failures -join '; ')) }
Write-Host 'All STIG Manager checks passed.'
exit 0
