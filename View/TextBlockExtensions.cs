using System;
using System.Windows;
using System.Windows.Controls;

namespace Vulnerator.View
{
    class TextBlockExtensions : TextBlock
    {
        public static readonly DependencyProperty UrlProperty = DependencyProperty.RegisterAttached(
            "Url",
            typeof(string),
            typeof(TextBlockExtensions),
            new FrameworkPropertyMetadata("")
            );

        public static void SetUrl(UIElement element, string value)
        { element.SetValue(UrlProperty, value); }

        public static string GetUrl(UIElement element)
        { return (string)element.GetValue(UrlProperty); }
    }
}
