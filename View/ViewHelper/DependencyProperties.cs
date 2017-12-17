using System;
using System.Windows;
using System.Windows.Controls;

namespace Vulnerator.View.ViewHelper
{
    class DependencyProperties : TextBlock
    {
        public static readonly DependencyProperty UrlProperty = DependencyProperty.RegisterAttached(
            "Url",
            typeof(string),
            typeof(DependencyProperties),
            new FrameworkPropertyMetadata("")
            );

        public static void SetUrl(UIElement element, string value)
        { element.SetValue(UrlProperty, value); }

        public static string GetUrl(UIElement element)
        { return (string)element.GetValue(UrlProperty); }

        public static readonly DependencyProperty FloatingWatermarkProperty = DependencyProperty.RegisterAttached(
              "FloatingWatermark", 
              typeof(string), 
              typeof(DependencyProperties),
              new PropertyMetadata(""));

        public static string GetFloatingWatermark(DependencyObject d)
        { return (string)d.GetValue(FloatingWatermarkProperty); }

        public static void SetFloatingWatermark(DependencyObject d, string value)
        { d.SetValue(FloatingWatermarkProperty, value); }
    }
}
