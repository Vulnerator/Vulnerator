using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MahApps.Metro.Controls;
using MahApps.Metro.IconPacks;
using Vulnerator.AddOns;
using Vulnerator.Helper;
using Vulnerator.Model.AddOns;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Shows an add-on's view, created the first time it is displayed. If the add-on fails to create it, a short
    /// message is shown instead and the error is logged; Vulnerator keeps running.
    /// </summary>
    public sealed class AddOnViewHost : ContentControl
    {
        private readonly AddOnView _view;
        private bool _created;

        public AddOnViewHost(AddOnView view)
        {
            _view = view;
            Focusable = false;
            HorizontalContentAlignment = HorizontalAlignment.Stretch;
            VerticalContentAlignment = VerticalAlignment.Stretch;
            Loaded += (sender, e) => Create();
        }

        private void Create()
        {
            if (_created) return;
            _created = true;
            try
            {
                object content = _view.CreateView();
                if (content == null) throw new InvalidOperationException("the add-on returned no view");
                Content = content;
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Add-ons: " + _view.Owner.Name + " could not show '" + _view.Title + "'.", exception);
                Content = new TextBlock
                {
                    Margin = new Thickness(10),
                    TextWrapping = TextWrapping.Wrap,
                    Text = _view.Owner.Name + " could not show this page: " + exception.Message + Environment.NewLine + "Details are in the Vulnerator log."
                };
            }
        }
    }

    /// <summary>Adds add-on pages to the navigation menu and the Integrations section to Settings.</summary>
    public static class AddOnUi
    {
        /// <summary>Inserts each add-on page into the main menu, before News (or at the end).</summary>
        public static void AddPages(HamburgerMenu menu)
        {
            try
            {
                HamburgerMenuItemCollection items = menu.ItemsSource as HamburgerMenuItemCollection;
                if (items == null) return;
                int position = items.Count;
                for (int i = 0; i < items.Count; i++)
                {
                    HamburgerMenuItem item = items[i] as HamburgerMenuItem;
                    if (item != null && string.Equals(item.Label, "News", StringComparison.Ordinal))
                    { position = i; break; }
                }
                foreach (AddOnView page in AddOnManager.Pages)
                {
                    try
                    {
                        PackIconMaterialKind kind;
                        if (string.IsNullOrWhiteSpace(page.IconName) || !Enum.TryParse(page.IconName.Trim(), true, out kind))
                        { kind = PackIconMaterialKind.PuzzleOutline; }
                        items.Insert(position, new HamburgerMenuIconItem
                        {
                            Label = page.Title,
                            ToolTip = page.Title + " (" + page.Owner.Name + " add-on)",
                            Icon = new PackIconMaterial { Kind = kind, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
                            Tag = new AddOnViewHost(page)
                        });
                        position++;
                    }
                    catch (Exception exception)
                    { LogWriter.LogErrorWithDebug("Add-ons: the page '" + page.Title + "' of " + page.Owner.Name + " could not be added to the menu.", exception); }
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Add-ons: pages could not be added to the menu.", exception); }
        }

        /// <summary>
        /// Fills the Settings &gt; Integrations panel: each add-on found, its state and its settings sections.
        /// <paramref name="message"/>, when given, is shown at the end.
        /// </summary>
        public static void FillIntegrations(Panel panel, string message = null)
        {
            try
            {
                panel.Children.Clear();
                if (AddOnManager.AddOns.Count == 0)
                {
                    panel.Children.Add(Note("No add-ons are installed. Add-ons are *.AddOn.dll files placed in this folder: " + AddOnManager.Folder));
                    return;
                }
                foreach (LoadedAddOn addOn in AddOnManager.AddOns)
                {
                    string text = addOn.Summary;
                    if (!string.IsNullOrWhiteSpace(addOn.Description)) text += Environment.NewLine + addOn.Description;
                    TextBlock line = Note(text);
                    if (addOn.State != AddOnState.Loaded) line.Foreground = Brushes.OrangeRed;
                    panel.Children.Add(line);
                    foreach (AddOnView section in addOn.SettingsSections)
                    {
                        panel.Children.Add(new GroupBox
                        {
                            Margin = new Thickness(5, 0, 5, 5),
                            Header = section.Title,
                            Content = new AddOnViewHost(section)
                        });
                    }
                }
                if (!string.IsNullOrWhiteSpace(message))
                { panel.Children.Add(Note(message)); }
                panel.Children.Add(Note("Add-ons folder: " + AddOnManager.Folder));
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Add-ons: the Integrations section could not be shown.", exception); }
        }

        private static TextBlock Note(string text)
        {
            return new TextBlock { Margin = new Thickness(5, 0, 5, 5), TextWrapping = TextWrapping.Wrap, Text = text };
        }
    }
}
