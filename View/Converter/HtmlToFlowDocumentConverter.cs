using System;
using System.Globalization;
using System.Windows.Data;
using HTMLConverter;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Documents;
using System.Linq;
using System.Collections.Generic;
using System.Windows.Navigation;
using System.Diagnostics;

namespace Vulnerator.View.Converter
{
    class HtmlToFlowDocumentConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            string xaml = HtmlToXamlConverter.ConvertHtmlToXaml((string)value, true);
            FlowDocument flowDocument = XamlReader.Parse(xaml) as FlowDocument;
            if (flowDocument is FlowDocument)
            { SubscribeToAllHyperlinks(flowDocument); }
            return flowDocument;
        }

        private void SubscribeToAllHyperlinks(FlowDocument flowDocument)
        {
            var hyperlinks = GetVisuals(flowDocument).OfType<Hyperlink>();
            foreach (var link in hyperlinks)
            { link.RequestNavigate += LinkRequestNavigate; }
        }

        private static IEnumerable<DependencyObject> GetVisuals(DependencyObject root)
        {
            foreach (var child in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>())
            {
                yield return child;
                foreach (var descendants in GetVisuals(child))
                { yield return descendants; }
            }
        }

        private void LinkRequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri));
            e.Handled = true;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        { throw new NotImplementedException(); }
    }
}
