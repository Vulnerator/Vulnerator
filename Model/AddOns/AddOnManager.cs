using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using GalaSoft.MvvmLight.Messaging;
using Vulnerator.AddOns;
using Vulnerator.Helper;
using Vulnerator.ViewModel;

namespace Vulnerator.Model.AddOns
{
    public enum AddOnState
    {
        Loaded,
        Skipped,
        Failed
    }

    /// <summary>One add-on file found at startup and what happened to it.</summary>
    public sealed class LoadedAddOn
    {
        internal LoadedAddOn(string file)
        {
            File = file;
            Id = Path.GetFileNameWithoutExtension(file);
            Name = Id;
            Version = string.Empty;
            Description = string.Empty;
        }

        public string File { get; }
        public string Id { get; internal set; }
        public string Name { get; internal set; }
        public string Version { get; internal set; }
        public string Description { get; internal set; }
        public AddOnState State { get; internal set; }

        /// <summary>Why the add-on was skipped or failed; empty when it loaded.</summary>
        public string Message { get; internal set; } = string.Empty;

        public IReadOnlyList<AddOnView> Pages { get; internal set; } = new AddOnView[0];
        public IReadOnlyList<AddOnView> SettingsSections { get; internal set; } = new AddOnView[0];

        internal AddOnHost Host { get; set; }

        /// <summary>The add-on's entry object, when it loaded.</summary>
        internal IAddOn Instance { get; set; }

        /// <summary>"Dashboards 1.0.0 - loaded" style line for Settings and the log.</summary>
        public string Summary
        {
            get
            {
                string name = Name + (string.IsNullOrWhiteSpace(Version) ? string.Empty : " " + Version);
                switch (State)
                {
                    case AddOnState.Loaded: return name + " - loaded";
                    case AddOnState.Skipped: return name + " - not loaded: " + Message;
                    default: return name + " - failed: " + Message;
                }
            }
        }
    }

    /// <summary>
    /// Finds and loads add-ons once at startup. Add-ons are "*.AddOn.dll" files in the Add-ons folder next to
    /// Vulnerator.exe, or one folder below it (with their own dependencies beside them). An add-on that is missing,
    /// incompatible or throws is logged and skipped; it never stops Vulnerator from starting.
    /// </summary>
    public static class AddOnManager
    {
        public const string FolderName = "Add-ons";
        private const string FilePattern = "*.AddOn.dll";
        private static readonly object Gate = new object();
        private static bool _loaded;
        private static bool _listening;
        private static List<LoadedAddOn> _addOns = new List<LoadedAddOn>();

        public static string Folder => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, FolderName);

        /// <summary>Every add-on file found, loaded or not.</summary>
        public static IReadOnlyList<LoadedAddOn> AddOns => _addOns;

        /// <summary>Pages from loaded add-ons, in load order.</summary>
        public static IEnumerable<AddOnView> Pages => _addOns.Where(a => a.State == AddOnState.Loaded).SelectMany(a => a.Pages);

        /// <summary>Settings sections from loaded add-ons, in load order.</summary>
        public static IEnumerable<AddOnView> SettingsSections => _addOns.Where(a => a.State == AddOnState.Loaded).SelectMany(a => a.SettingsSections);

        /// <summary>Loads the add-ons (only the first call does anything). Call on the UI thread before the main window opens.</summary>
        public static void LoadAll()
        {
            lock (Gate)
            {
                if (_loaded) return;
                _loaded = true;
            }
            LoadFrom(Folder);
        }

        /// <summary>Loads the add-ons in a folder and makes them the current set (the tests point this at their own folder).</summary>
        public static IReadOnlyList<LoadedAddOn> LoadFrom(string folder)
        {
            try
            { _addOns = Discover(folder); }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Add-ons could not be loaded; Vulnerator continues without them.", exception);
                _addOns = new List<LoadedAddOn>();
            }
            if (!_listening && _addOns.Any(a => a.State == AddOnState.Loaded))
            {
                _listening = true;
                Messenger.Default.Register<GalaSoft.MvvmLight.Messaging.NotificationMessage<string>>(typeof(AddOnManager), MessengerToken.ModelUpdated, _ => NotifyDataChanged());
            }
            return _addOns;
        }

        private static List<LoadedAddOn> Discover(string folder)
        {
            List<LoadedAddOn> result = new List<LoadedAddOn>();
            if (!Directory.Exists(folder))
            {
                LogWriter.LogStatusUpdate("Add-ons: no '" + FolderName + "' folder next to Vulnerator.exe; none loaded.");
                return result;
            }
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => ResolveDependency(folder, args);

            List<string> files = Directory.GetFiles(folder, FilePattern, SearchOption.TopDirectoryOnly).ToList();
            foreach (string subfolder in Directory.GetDirectories(folder))
            { files.AddRange(Directory.GetFiles(subfolder, FilePattern, SearchOption.TopDirectoryOnly)); }

            HashSet<string> ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string file in files.OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
            {
                LoadedAddOn addOn = LoadOne(file);
                if (addOn.State == AddOnState.Loaded && !ids.Add(addOn.Id))
                {
                    addOn.State = AddOnState.Skipped;
                    addOn.Message = "another add-on with the id '" + addOn.Id + "' is already loaded";
                    addOn.Pages = new AddOnView[0];
                    addOn.SettingsSections = new AddOnView[0];
                }
                string line = "Add-ons: " + Path.GetFileName(file) + ": " + addOn.Summary;
                if (addOn.State == AddOnState.Loaded) LogWriter.LogStatusUpdate(line);
                else LogWriter.LogWarning(line);
                result.Add(addOn);
            }
            if (files.Count == 0)
            { LogWriter.LogStatusUpdate("Add-ons: no " + FilePattern + " files in '" + folder + "'."); }
            return result;
        }

        private static LoadedAddOn LoadOne(string file)
        {
            LoadedAddOn addOn = new LoadedAddOn(file);
            Assembly assembly;
            try
            { assembly = Assembly.LoadFrom(file); }
            catch (NotSupportedException)
            {
                // .NET refuses LoadFrom on files Windows marks as downloaded from the internet.
                return Fail(addOn, AddOnState.Skipped, "Windows marks this file as downloaded from the internet. Right-click it, " +
                                                        "choose Properties, tick Unblock, then restart Vulnerator.");
            }
            catch (BadImageFormatException)
            { return Fail(addOn, AddOnState.Skipped, "not a .NET Framework 64-bit or Any CPU assembly"); }
            catch (Exception exception)
            { return Fail(addOn, AddOnState.Failed, "the file could not be loaded (" + exception.Message + ")", exception); }

            VulneratorAddOnAttribute attribute;
            try
            { attribute = assembly.GetCustomAttributes(typeof(VulneratorAddOnAttribute), false).OfType<VulneratorAddOnAttribute>().FirstOrDefault(); }
            catch (Exception exception)
            { return Fail(addOn, AddOnState.Failed, "its add-on information could not be read (" + exception.Message + ")", exception); }
            if (attribute == null || attribute.AddOnType == null)
            { return Fail(addOn, AddOnState.Skipped, "not a Vulnerator add-on (no VulneratorAddOn attribute)"); }

            if (attribute.ApiVersion > AddOnApi.Version)
            { return Fail(addOn, AddOnState.Skipped, "it needs a newer Vulnerator (add-on interface version " + attribute.ApiVersion + ", this Vulnerator has " + AddOnApi.Version + ")"); }
            if (attribute.ApiVersion < AddOnApi.MinimumSupportedVersion)
            { return Fail(addOn, AddOnState.Skipped, "it was built for an older Vulnerator that is no longer supported (interface version " + attribute.ApiVersion + ")"); }
            if (!string.IsNullOrWhiteSpace(attribute.MinimumCoreVersion))
            {
                Version needed;
                if (System.Version.TryParse(attribute.MinimumCoreVersion.Trim(), out needed) && CoreFileVersion() < needed)
                { return Fail(addOn, AddOnState.Skipped, "it needs Vulnerator " + attribute.MinimumCoreVersion.Trim() + " or later"); }
            }
            if (!typeof(IAddOn).IsAssignableFrom(attribute.AddOnType) || attribute.AddOnType.IsAbstract || attribute.AddOnType.GetConstructor(Type.EmptyTypes) == null)
            { return Fail(addOn, AddOnState.Failed, attribute.AddOnType.FullName + " is not a public IAddOn class with a parameterless constructor"); }

            AddOnHost host = null;
            IAddOn instance;
            try
            {
                instance = (IAddOn)Activator.CreateInstance(attribute.AddOnType);
                addOn.Id = string.IsNullOrWhiteSpace(instance.Id) ? addOn.Id : instance.Id.Trim();
                addOn.Name = string.IsNullOrWhiteSpace(instance.Name) ? addOn.Id : instance.Name.Trim();
                addOn.Version = instance.Version ?? string.Empty;
                addOn.Description = instance.Description ?? string.Empty;
                host = new AddOnHost(addOn);
                instance.Initialize(host);
            }
            catch (Exception exception)
            {
                Exception inner = exception is TargetInvocationException && exception.InnerException != null ? exception.InnerException : exception;
                return Fail(addOn, AddOnState.Failed, "it stopped with an error while starting (" + inner.Message + ")", inner);
            }
            finally
            {
                if (host != null) host.Open = false;
            }
            addOn.Host = host;
            addOn.Instance = instance;
            addOn.Pages = host.Pages.ToList().AsReadOnly();
            addOn.SettingsSections = host.SettingsSections.ToList().AsReadOnly();
            addOn.State = AddOnState.Loaded;
            return addOn;
        }

        private static LoadedAddOn Fail(LoadedAddOn addOn, AddOnState state, string message, Exception exception = null)
        {
            addOn.State = state;
            addOn.Message = message;
            addOn.Pages = new AddOnView[0];
            addOn.SettingsSections = new AddOnView[0];
            if (exception != null)
            { LogWriter.LogErrorWithDebug("Add-ons: " + Path.GetFileName(addOn.File) + ": " + message, exception); }
            return addOn;
        }

        private static Version CoreFileVersion()
        {
            Version version = typeof(AddOnManager).Assembly.GetName().Version;
            return new Version(version.Major, version.Minor, Math.Max(version.Build, 0));
        }

        /// <summary>Add-on dependencies are looked up beside the add-ons: the Add-ons folder and the folders one level down.</summary>
        private static Assembly ResolveDependency(string folder, ResolveEventArgs args)
        {
            string name = new AssemblyName(args.Name).Name;
            if (name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase)) return null;
            try
            {
                IEnumerable<string> places = new[] { folder }.Concat(Directory.GetDirectories(folder));
                foreach (string place in places)
                {
                    string candidate = Path.Combine(place, name + ".dll");
                    if (System.IO.File.Exists(candidate)) return Assembly.LoadFrom(candidate);
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Add-ons: dependency " + name + " could not be loaded.", exception); }
            return null;
        }

        /// <summary>The folder add-on data goes in: the database's folder, else %LOCALAPPDATA%\Vulnerator.</summary>
        public static string BaseFolder()
        {
            string baseFolder = null;
            try
            {
                string database = Properties.Settings.Default.Database;
                if (!string.IsNullOrWhiteSpace(database) && database != "Undefined")
                { baseFolder = Path.GetDirectoryName(Path.GetFullPath(database)); }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Add-ons: the database folder could not be determined.", exception); }
            if (string.IsNullOrWhiteSpace(baseFolder))
            { baseFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Vulnerator"); }
            return baseFolder;
        }

        /// <summary>Tells the loaded add-ons that the data changed (after an import or a database change).</summary>
        public static void NotifyDataChanged()
        {
            foreach (LoadedAddOn addOn in _addOns.Where(a => a.State == AddOnState.Loaded && a.Host != null))
            { addOn.Host.RaiseDataChanged(); }
        }
    }
}
