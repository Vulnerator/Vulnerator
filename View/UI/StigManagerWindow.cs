using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Vulnerator.Helper;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.StigManager;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// "Pull from STIG Manager...": sign in to the organization's STIG Manager server, pick a Collection and its
    /// Assets, and download their checklists as one zip. The zip then goes into the normal checklist ingestion list
    /// (<see cref="ZipPath"/>), so imports follow the same rules as files picked from disk.
    /// </summary>
    public sealed class StigManagerWindow : Window
    {
        private readonly TextBox _api = Field();
        private readonly TextBox _authority = Field();
        private readonly TextBox _clientId = Field();
        private readonly TextBox _scope = Field();
        private readonly RadioButton _browser = new RadioButton { Content = "Browser sign-in (your account or CAC)", GroupName = "signin", Margin = new Thickness(0, 0, 16, 0) };
        private readonly RadioButton _service = new RadioButton { Content = "Service account (client secret)", GroupName = "signin" };
        private readonly PasswordBox _secret = new PasswordBox { Margin = new Thickness(0, 0, 0, 6) };
        private readonly CheckBox _rememberSecret = new CheckBox { Content = "Remember the secret on this computer (encrypted for your Windows account)", Margin = new Thickness(0, 0, 0, 6) };
        private readonly TextBox _port = Field();
        private readonly Button _signIn = new Button { Content = "Sign in", MinWidth = 100, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 4, 0, 8) };
        private readonly ComboBox _collections = new ComboBox { Margin = new Thickness(0, 0, 0, 6), IsEnabled = false };
        private readonly StackPanel _assetList = new StackPanel();
        private readonly CheckBox _cklb = new CheckBox { Content = "Download CKLB (STIG Viewer 3) instead of CKL", Margin = new Thickness(0, 6, 0, 6) };
        private readonly TextBlock _status = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 6) };
        private readonly Button _pull = new Button { Content = "Add to ingestion list", MinWidth = 150, IsEnabled = false, IsDefault = true, Margin = new Thickness(0, 0, 8, 0) };
        private readonly StackPanel _secretRow = new StackPanel();
        private readonly StackPanel _portRow = new StackPanel();
        private StigManagerClient _client;
        private CancellationTokenSource _signInCancel;

        /// <summary>The downloaded checklist zip, set when the window closes with OK.</summary>
        public string ZipPath { get; private set; }

        /// <summary>Assets STIG Manager could not export (from the archive's _manifest.json).</summary>
        public IReadOnlyList<string> ExportErrors { get; private set; } = new string[0];

        public StigManagerWindow()
        {
            Title = "Pull checklists from STIG Manager";
            Width = 640;
            Height = 720;
            MinWidth = 480;
            MinHeight = 480;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Vulnerator.Properties.Settings settings = Vulnerator.Properties.Settings.Default;
            _api.Text = settings.StigManagerApiAddress;
            _authority.Text = settings.StigManagerAuthority;
            _clientId.Text = settings.StigManagerClientId;
            _scope.Text = string.IsNullOrWhiteSpace(settings.StigManagerScope) ? StigManagerClient.DefaultScope : settings.StigManagerScope;
            _port.Text = settings.StigManagerRedirectPort.ToString(CultureInfo.InvariantCulture);
            _cklb.IsChecked = settings.StigManagerCklb;
            string remembered = StigManagerSettings.LoadSecret();
            _secret.Password = remembered;
            _rememberSecret.IsChecked = remembered.Length > 0;
            _service.IsChecked = settings.StigManagerUseServiceAccount;
            _browser.IsChecked = !settings.StigManagerUseServiceAccount;
            _browser.Checked += (sender, e) => ShowSignInFields();
            _service.Checked += (sender, e) => ShowSignInFields();

            StackPanel form = new StackPanel { Margin = new Thickness(12) };
            form.Children.Add(Note("Reads checklists from your organization's STIG Manager server and adds them to the ingestion list. " +
                                   "Only the addresses below are contacted. Ask your STIG Manager administrator for the values; " +
                                   "the account needs the stig-manager:collection:read scope and a grant to the Collection."));
            form.Children.Add(Caption("STIG Manager API address (usually ends in /api)"));
            form.Children.Add(_api);
            form.Children.Add(Caption("OIDC provider address (for Keycloak: https://<server>/realms/<realm>)"));
            form.Children.Add(_authority);
            form.Children.Add(Caption("Client ID registered for Vulnerator"));
            form.Children.Add(_clientId);
            form.Children.Add(Caption("Scope"));
            form.Children.Add(_scope);
            StackPanel methods = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 6) };
            methods.Children.Add(_browser);
            methods.Children.Add(_service);
            form.Children.Add(methods);
            _secretRow.Children.Add(Caption("Client secret"));
            _secretRow.Children.Add(_secret);
            _secretRow.Children.Add(_rememberSecret);
            form.Children.Add(_secretRow);
            _portRow.Children.Add(Caption("Sign-in port on this computer (0 = any free port; set a fixed one if the provider only accepts a registered redirect)"));
            _portRow.Children.Add(_port);
            form.Children.Add(_portRow);
            form.Children.Add(_signIn);
            form.Children.Add(Caption("Collection"));
            form.Children.Add(_collections);
            DockPanel assetHeader = new DockPanel { LastChildFill = false, Margin = new Thickness(0, 4, 0, 2) };
            assetHeader.Children.Add(Caption("Assets (all STIGs assigned to each, default revisions)"));
            Button none = SmallButton("None");
            Button all = SmallButton("All");
            DockPanel.SetDock(none, Dock.Right);
            DockPanel.SetDock(all, Dock.Right);
            assetHeader.Children.Add(none);
            assetHeader.Children.Add(all);
            form.Children.Add(assetHeader);
            form.Children.Add(new Border
            {
                BorderThickness = new Thickness(1),
                BorderBrush = Brushes.Gray,
                Height = 200,
                Child = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _assetList, Padding = new Thickness(4) }
            });
            form.Children.Add(_cklb);
            form.Children.Add(_status);

            StackPanel buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(12, 0, 12, 12) };
            Button close = new Button { Content = "Close", MinWidth = 80, IsCancel = true };
            buttons.Children.Add(_pull);
            buttons.Children.Add(close);
            DockPanel root = new DockPanel();
            DockPanel.SetDock(buttons, Dock.Bottom);
            root.Children.Add(buttons);
            root.Children.Add(new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = form });
            Content = root;

            _signIn.Click += async (sender, e) => await SignInAsync();
            _collections.SelectionChanged += async (sender, e) => await LoadAssetsAsync();
            all.Click += (sender, e) => SetAll(true);
            none.Click += (sender, e) => SetAll(false);
            _pull.Click += async (sender, e) => await PullAsync();
            Closed += (sender, e) =>
            {
                if (_signInCancel != null) _signInCancel.Cancel();
                if (_client != null) _client.Dispose();
            };
            ShowSignInFields();
        }

        private void ShowSignInFields()
        {
            bool service = _service.IsChecked == true;
            _secretRow.Visibility = service ? Visibility.Visible : Visibility.Collapsed;
            _portRow.Visibility = service ? Visibility.Collapsed : Visibility.Visible;
        }

        private async System.Threading.Tasks.Task SignInAsync()
        {
            if (_signInCancel != null)
            {
                _signInCancel.Cancel();
                return;
            }
            int port;
            if (!int.TryParse((_port.Text ?? "0").Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out port) || port < 0 || port > 65535)
            {
                Status("The sign-in port must be a number from 0 to 65535.", true);
                return;
            }
            bool service = _service.IsChecked == true;
            try
            {
                if (_client != null) _client.Dispose();
                _client = null;
                _collections.ItemsSource = null;
                _collections.IsEnabled = false;
                _assetList.Children.Clear();
                _pull.IsEnabled = false;
                StigManagerClient client = new StigManagerClient(_api.Text, _authority.Text, _clientId.Text, _scope.Text);
                if (service)
                {
                    Busy(true, "Signing in as the service account...");
                    await client.SignInWithClientSecretAsync(_secret.Password);
                }
                else
                {
                    _signInCancel = new CancellationTokenSource();
                    _signIn.Content = "Cancel sign-in";
                    Busy(true, "Finish signing in in your browser, then come back here. Choose Cancel sign-in to stop waiting.");
                    _signIn.IsEnabled = true;
                    await client.SignInWithBrowserAsync(port, null, TimeSpan.FromMinutes(5), _signInCancel.Token);
                }
                _client = client;
                SaveSettings(port, service);
                Busy(true, "Signed in. Reading Collections...");
                List<StigManagerCollection> collections = await _client.GetCollectionsAsync();
                _collections.ItemsSource = collections;
                _collections.IsEnabled = collections.Count > 0;
                LogWriter.LogStatusUpdate("STIG Manager: signed in; " + collections.Count + " Collection(s) available.");
                Status(collections.Count == 0
                    ? "Signed in, but this account cannot read any Collection. Ask the STIG Manager administrator for a grant."
                    : "Signed in. Pick a Collection.", collections.Count == 0);
                if (collections.Count == 1) _collections.SelectedIndex = 0;
            }
            catch (StigManagerException exception)
            {
                LogWriter.LogStatusUpdate("STIG Manager: " + exception.Message);
                Status(exception.Message, true);
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("STIG Manager: sign-in failed.", exception);
                Status("Sign-in failed: " + exception.Message, true);
            }
            finally
            {
                if (_signInCancel != null) _signInCancel.Dispose();
                _signInCancel = null;
                _signIn.Content = _client != null && _client.IsSignedIn ? "Sign in again" : "Sign in";
                Busy(false, null);
            }
        }

        private void SaveSettings(int port, bool service)
        {
            Vulnerator.Properties.Settings settings = Vulnerator.Properties.Settings.Default;
            settings.StigManagerApiAddress = (_api.Text ?? string.Empty).Trim();
            settings.StigManagerAuthority = (_authority.Text ?? string.Empty).Trim();
            settings.StigManagerClientId = (_clientId.Text ?? string.Empty).Trim();
            settings.StigManagerScope = (_scope.Text ?? string.Empty).Trim();
            settings.StigManagerUseServiceAccount = service;
            settings.StigManagerRedirectPort = port;
            if (service)
            { StigManagerSettings.SaveSecret(_rememberSecret.IsChecked == true ? _secret.Password : string.Empty); }
            settings.Save();
        }

        private async System.Threading.Tasks.Task LoadAssetsAsync()
        {
            StigManagerCollection collection = _collections.SelectedItem as StigManagerCollection;
            _assetList.Children.Clear();
            _pull.IsEnabled = false;
            if (collection == null || _client == null) return;
            try
            {
                Busy(true, "Reading the Assets in " + collection.Name + "...");
                List<StigManagerAsset> assets = await _client.GetAssetsAsync(collection.Id);
                foreach (StigManagerAsset asset in assets)
                {
                    CheckBox box = new CheckBox
                    {
                        Content = asset.Name + "  (" + asset.BenchmarkIds.Count + " STIG" + (asset.BenchmarkIds.Count == 1 ? ")" : "s)"),
                        ToolTip = asset.BenchmarkIds.Count == 0 ? "No STIGs assigned" : string.Join(Environment.NewLine, asset.BenchmarkIds),
                        Tag = asset.Id,
                        IsChecked = asset.BenchmarkIds.Count > 0,
                        IsEnabled = asset.BenchmarkIds.Count > 0,
                        Margin = new Thickness(0, 1, 0, 1)
                    };
                    box.Checked += (sender, e) => UpdatePullButton();
                    box.Unchecked += (sender, e) => UpdatePullButton();
                    _assetList.Children.Add(box);
                }
                Status(assets.Count + " Asset(s) in " + collection.Name + ".", false);
            }
            catch (StigManagerException exception)
            { Status(exception.Message, true); }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("STIG Manager: the Assets could not be read.", exception);
                Status("The Assets could not be read: " + exception.Message, true);
            }
            finally
            {
                Busy(false, null);
                UpdatePullButton();
            }
        }

        private List<string> SelectedAssetIds()
        {
            return _assetList.Children.OfType<CheckBox>().Where(b => b.IsEnabled && b.IsChecked == true).Select(b => (string)b.Tag).ToList();
        }

        private void SetAll(bool value)
        {
            foreach (CheckBox box in _assetList.Children.OfType<CheckBox>().Where(b => b.IsEnabled))
            { box.IsChecked = value; }
            UpdatePullButton();
        }

        private void UpdatePullButton()
        { _pull.IsEnabled = _client != null && _client.IsSignedIn && _signInCancel == null && SelectedAssetIds().Count > 0; }

        private async System.Threading.Tasks.Task PullAsync()
        {
            StigManagerCollection collection = _collections.SelectedItem as StigManagerCollection;
            List<string> ids = SelectedAssetIds();
            if (collection == null || ids.Count == 0 || _client == null) return;
            bool cklb = _cklb.IsChecked == true;
            Vulnerator.Properties.Settings.Default.StigManagerCklb = cklb;
            string folder = Path.Combine(IngestionFileCollector.WorkingRoot, "StigManager_" + DateTime.Now.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture));
            string zip = Path.Combine(folder, SafeName(collection.Name) + (cklb ? "-CKLB" : "-CKL") + ".zip");
            try
            {
                Busy(true, "Downloading " + ids.Count + " Asset(s) from " + collection.Name + "...");
                StigManagerArchive archive = await _client.DownloadChecklistsAsync(collection.Id, ids, cklb, zip);
                LogWriter.LogStatusUpdate("STIG Manager: " + archive.MemberCount + " checklist(s) downloaded from Collection " + collection.Id +
                                          (archive.Errors.Count > 0 ? "; " + archive.Errors.Count + " Asset(s) not exported" : string.Empty) + ".");
                foreach (string error in archive.Errors)
                { LogWriter.LogWarning("STIG Manager: " + error); }
                if (archive.Errors.Count > 0)
                {
                    string message = archive.MemberCount + " checklist(s) downloaded. STIG Manager could not export " + archive.Errors.Count + " Asset(s):" +
                                     Environment.NewLine + string.Join(Environment.NewLine, archive.Errors.Take(15)) +
                                     (archive.Errors.Count > 15 ? Environment.NewLine + "(see the log for the rest)" : string.Empty) +
                                     Environment.NewLine + Environment.NewLine + "Add the checklists that were downloaded?";
                    if (MessageBox.Show(this, message, "STIG Manager", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                    {
                        Status("Nothing was added.", false);
                        return;
                    }
                }
                if (archive.MemberCount == 0)
                {
                    Status("STIG Manager returned no checklists for the selected Assets.", true);
                    return;
                }
                ZipPath = zip;
                ExportErrors = archive.Errors.AsReadOnly();
                DialogResult = true;
            }
            catch (StigManagerException exception)
            {
                LogWriter.LogStatusUpdate("STIG Manager: " + exception.Message);
                Status(exception.Message, true);
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("STIG Manager: the checklists could not be downloaded.", exception);
                Status("The checklists could not be downloaded: " + exception.Message, true);
            }
            finally
            {
                if (IsLoaded) Busy(false, null);
            }
        }

        private static string SafeName(string name)
        {
            char[] invalid = Path.GetInvalidFileNameChars();
            string safe = new string((name ?? "Collection").Select(c => invalid.Contains(c) ? '_' : c).ToArray()).Trim();
            if (safe.Length > 60) safe = safe.Substring(0, 60);
            return safe.Length == 0 ? "Collection" : safe;
        }

        private void Busy(bool busy, string message)
        {
            Cursor = busy ? Cursors.Wait : null;
            _signIn.IsEnabled = !busy;
            _collections.IsEnabled = !busy && _collections.ItemsSource != null && _collections.Items.Count > 0;
            _assetList.IsEnabled = !busy;
            if (message != null) Status(message, false);
            if (busy) _pull.IsEnabled = false;
            else UpdatePullButton();
        }

        private void Status(string message, bool problem)
        {
            _status.Text = message ?? string.Empty;
            _status.Foreground = problem ? Brushes.OrangeRed : SystemColors.ControlTextBrush;
        }

        private static TextBox Field() { return new TextBox { Margin = new Thickness(0, 0, 0, 6) }; }

        private static TextBlock Caption(string text) { return new TextBlock { Text = text, Margin = new Thickness(0, 2, 0, 2), TextWrapping = TextWrapping.Wrap }; }

        private static TextBlock Note(string text) { return new TextBlock { Text = text, Margin = new Thickness(0, 0, 0, 8), TextWrapping = TextWrapping.Wrap }; }

        private static Button SmallButton(string text) { return new Button { Content = text, MinWidth = 50, Margin = new Thickness(4, 0, 0, 0) }; }
    }
}
