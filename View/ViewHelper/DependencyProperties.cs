using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

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

        public static readonly DependencyProperty FloatingWatermarkForegroundProperty = DependencyProperty.RegisterAttached(
              "FloatingWatermarkForeground",
              typeof(SolidColorBrush),
              typeof(DependencyProperties),
              new PropertyMetadata(new SolidColorBrush(Color.FromRgb(153, 153, 153))));

        public static SolidColorBrush GetFloatingWatermarkForeground(DependencyObject d)
        { return (SolidColorBrush)d.GetValue(FloatingWatermarkProperty); }

        public static void SetFloatingWatermarkForeground(DependencyObject d, SolidColorBrush value)
        { d.SetValue(FloatingWatermarkProperty, value); }

        public static readonly DependencyProperty ShowCharacterCountProperty = DependencyProperty.RegisterAttached(
            "ShowCharacterCount",
            typeof(bool),
            typeof(DependencyProperties),
            new FrameworkPropertyMetadata(false));

        public static bool GetShowCharacterCount(DependencyObject d)
        { return (bool)d.GetValue(ShowCharacterCountProperty); }

        public static void SetShowCharacterCount(DependencyObject d, bool value)
        { d.SetValue(ShowCharacterCountProperty, value); }

        public static readonly DependencyProperty PrimaryTextProperty = DependencyProperty.RegisterAttached(
            "PrimaryText",
            typeof(string),
            typeof(DependencyProperties),
            new FrameworkPropertyMetadata(""));

        public static string GetPrimaryText(DependencyObject d)
        { return (string) d.GetValue(PrimaryTextProperty); }

        public static void SetPrimaryText(DependencyObject d, string value)
        { d.SetValue(PrimaryTextProperty, value); }

        public static readonly DependencyProperty SecondaryTextProperty = DependencyProperty.RegisterAttached(
            "SecondaryText",
            typeof(string),
            typeof(DependencyProperties),
            new FrameworkPropertyMetadata(""));

        public static string GetSecondaryText(DependencyObject d)
        { return (string)d.GetValue(SecondaryTextProperty); }

        public static void SetSecondaryText(DependencyObject d, string value)
        { d.SetValue(SecondaryTextProperty, value); }

        public static readonly DependencyProperty AlternateTextTriggerProperty = DependencyProperty.RegisterAttached(
            "AlternateTextTrigger",
            typeof(object),
            typeof(DependencyProperties));

        public static object GetAlternateTextTrigger(DependencyObject d)
        { return (object)d.GetValue(AlternateTextTriggerProperty); }

        public static void SetAlternateTextTrigger(DependencyObject d, object value)
        { d.SetValue(AlternateTextTriggerProperty, value); }
    }
}
