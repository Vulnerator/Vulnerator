using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Vulnerator.AddOns;
using Vulnerator.Helper;

namespace Vulnerator.Model.AddOns
{
    /// <summary>A page or settings section an add-on registered.</summary>
    public sealed class AddOnView
    {
        internal AddOnView(LoadedAddOn owner, string title, string iconName, Func<object> createView)
        {
            Owner = owner;
            Title = title;
            IconName = iconName;
            CreateView = createView;
        }

        public LoadedAddOn Owner { get; }
        public string Title { get; }
        public string IconName { get; }
        public Func<object> CreateView { get; }
    }

    /// <summary>The host one add-on sees. Registrations are kept only if the add-on's Initialize succeeds.</summary>
    internal sealed class AddOnHost : IAddOnHost, IAddOnLog
    {
        private static readonly IFindingsData SharedData = new AddOnData();
        private readonly LoadedAddOn _owner;
        private readonly string _tag;
        internal readonly List<AddOnView> Pages = new List<AddOnView>();
        internal readonly List<AddOnView> SettingsSections = new List<AddOnView>();
        internal bool Open = true;

        internal AddOnHost(LoadedAddOn owner)
        {
            _owner = owner;
            _tag = "[Add-on " + owner.Id + "] ";
        }

        public int ApiVersion => AddOnApi.Version;

        public string CoreVersion => AppVersion.Display;

        public string ClassificationMarking => Properties.Settings.Default.EmassClassificationMarking ?? string.Empty;

        public IAddOnLog Log => this;

        public IFindingsData Data => SharedData;

        public string DataFolder
        {
            get
            {
                string folder = Path.Combine(AddOnManager.BaseFolder(), "Add-on data", SafeName(_owner.Id));
                Directory.CreateDirectory(folder);
                return folder;
            }
        }

        /// <summary>Vulnerator 2.0 uses no licenses (since 7.5.0): always empty. Kept for add-ons built for interface 2-3.</summary>
        public IReadOnlyList<string> Licenses => new string[0];

        /// <summary>Never raised (no licenses since 7.5.0). Kept for add-ons built for interface 2-3.</summary>
        public event EventHandler LicensesChanged { add { } remove { } }

        public event EventHandler DataChanged;

        public void AddPage(string title, string iconName, Func<object> createView)
        {
            Require(title, createView);
            Pages.Add(new AddOnView(_owner, title.Trim(), iconName, createView));
        }

        public void AddSettingsSection(string title, Func<object> createView)
        {
            Require(title, createView);
            SettingsSections.Add(new AddOnView(_owner, title.Trim(), null, createView));
        }

        internal void RaiseDataChanged() => Raise(DataChanged, "DataChanged");

        private void Raise(EventHandler handler, string name)
        {
            if (handler == null) return;
            foreach (EventHandler subscriber in handler.GetInvocationList().Cast<EventHandler>())
            {
                try
                { subscriber(this, EventArgs.Empty); }
                catch (Exception exception)
                { Error(name + " handler failed.", exception); }
            }
        }

        public void Info(string message) => LogWriter.LogStatusUpdate(_tag + message);

        public void Warning(string message) => LogWriter.LogWarning(_tag + message);

        public void Error(string message, Exception exception = null)
        {
            if (exception == null) LogWriter.LogError(_tag + message);
            else LogWriter.LogErrorWithDebug(_tag + message, exception);
        }

        private void Require(string title, Func<object> createView)
        {
            if (!Open) throw new InvalidOperationException("Pages and settings sections can only be added during Initialize.");
            if (string.IsNullOrWhiteSpace(title)) throw new ArgumentException("A title is required.", nameof(title));
            if (createView == null) throw new ArgumentNullException(nameof(createView));
        }

        private static string SafeName(string id)
        {
            char[] invalid = Path.GetInvalidFileNameChars();
            string safe = new string(id.Select(c => invalid.Contains(c) ? '_' : c).ToArray()).Trim('.', ' ');
            return safe.Length == 0 ? "add-on" : safe;
        }
    }
}
