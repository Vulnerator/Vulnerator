// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
// Simple charts drawn with plain WPF (no chart library, so the add-on stays one file with no native or extra DLLs).
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Vulnerator.Metrics;

namespace Vulnerator.Dashboards
{
    internal static class Charts
    {
        // Worst first; distinguishable without relying on red/green alone. Index = (int)SeverityLevel.
        public static readonly Brush[] LevelBrushes =
        {
            Frozen("#7A0019"), Frozen("#D9480F"), Frozen("#E8A100"), Frozen("#2F6FD0"), Frozen("#8C959F"), Frozen("#C6CBD1")
        };

        public static readonly Brush UnverifiedBrush = Frozen("#8E6CC4");
        public static readonly Brush GoodBrush = Frozen("#2E7D32");
        public static readonly Brush TrackBrush = Frozen("#22888888");

        public static readonly string[] CatNames = { "CAT I", "CAT II", "CAT III", "CAT IV" };
        public static readonly Brush[] CatBrushes = { LevelBrushes[1], LevelBrushes[2], LevelBrushes[3], LevelBrushes[4] };

        public static string Number(int value) => value.ToString("N0", CultureInfo.CurrentCulture);

        public static string Date(DateTime? value) => value.HasValue && value.Value > DateTime.MinValue ? value.Value.ToString("yyyy-MM-dd") : "-";

        public static TextBlock Text(string text, double size = 13, bool bold = false, Thickness? margin = null)
        {
            return new TextBlock
            {
                Text = text,
                FontSize = size,
                FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
                TextWrapping = TextWrapping.Wrap,
                Margin = margin ?? new Thickness(0, 0, 0, 6)
            };
        }

        public static TextBlock Heading(string text) => Text(text, 16, true, new Thickness(0, 4, 0, 8));

        /// <summary>A horizontal bar made of segments, scaled so that <paramref name="max"/> fills the width.</summary>
        public static FrameworkElement StackedBar(IList<int> values, IList<Brush> brushes, IList<string> names, int max, double height = 18)
        {
            var grid = new Grid { Height = height, Background = TrackBrush, MinWidth = 120 };
            int total = values.Sum();
            for (int i = 0; i < values.Count; i++)
            {
                if (values[i] <= 0) continue;
                grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(values[i], GridUnitType.Star) });
                var segment = new Border { Background = brushes[i], ToolTip = names[i] + ": " + Number(values[i]) };
                Grid.SetColumn(segment, grid.ColumnDefinitions.Count - 1);
                grid.Children.Add(segment);
            }
            int rest = Math.Max(0, max - total);
            if (rest > 0 || total == 0) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(Math.Max(rest, 1), GridUnitType.Star) });
            return grid;
        }

        /// <summary>Rows of label | bar | text, aligned.</summary>
        public static Grid BarRows(IEnumerable<Tuple<string, FrameworkElement, string>> rows, double labelWidth = 220)
        {
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(labelWidth) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
            int row = 0;
            foreach (Tuple<string, FrameworkElement, string> item in rows)
            {
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var label = Text(item.Item1, 13, false, new Thickness(0, 3, 8, 3));
                label.TextTrimming = TextTrimming.CharacterEllipsis;
                label.TextWrapping = TextWrapping.NoWrap;
                label.ToolTip = item.Item1;
                Place(grid, label, row, 0);
                item.Item2.Margin = new Thickness(0, 3, 8, 3);
                item.Item2.VerticalAlignment = VerticalAlignment.Center;
                Place(grid, item.Item2, row, 1);
                Place(grid, Text(item.Item3, 12, false, new Thickness(0, 3, 0, 3)), row, 2);
                row++;
            }
            return grid;
        }

        /// <summary>A colour key: swatch + name for each entry.</summary>
        public static FrameworkElement Legend(IList<string> names, IList<Brush> brushes)
        {
            var panel = new WrapPanel { Margin = new Thickness(0, 0, 0, 8) };
            for (int i = 0; i < names.Count; i++)
            {
                panel.Children.Add(new Border { Width = 12, Height = 12, Background = brushes[i], Margin = new Thickness(0, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center });
                panel.Children.Add(Text(names[i], 12, false, new Thickness(0, 0, 14, 0)));
            }
            return panel;
        }

        /// <summary>A read-only table of text rows (columns bind to row[i]).</summary>
        public static DataGrid Table(IList<string> headers, IEnumerable<string[]> rows, double maxHeight = 420)
        {
            var grid = new DataGrid
            {
                AutoGenerateColumns = false,
                IsReadOnly = true,
                CanUserAddRows = false,
                CanUserDeleteRows = false,
                CanUserSortColumns = true,
                HeadersVisibility = DataGridHeadersVisibility.Column,
                GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
                SelectionUnit = DataGridSelectionUnit.FullRow,
                MaxHeight = maxHeight,
                Margin = new Thickness(0, 0, 0, 10),
                ItemsSource = rows.ToList()
            };
            for (int i = 0; i < headers.Count; i++)
            {
                grid.Columns.Add(new DataGridTextColumn { Header = headers[i], Binding = new Binding("[" + i + "]") });
            }
            return grid;
        }

        /// <summary>Count table: row labels down the side, column headers across.</summary>
        public static Grid Matrix(IList<string> rowNames, IList<string> columnNames, Func<int, int, int> value, IList<Brush> columnBrushes = null)
        {
            var grid = new Grid { Margin = new Thickness(0, 0, 0, 10), HorizontalAlignment = HorizontalAlignment.Left };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            for (int c = 0; c < columnNames.Count + 1; c++) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(90) });
            for (int r = 0; r < rowNames.Count + 1; r++) grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            for (int c = 0; c < columnNames.Count; c++)
            {
                var header = Text(columnNames[c], 12, true, new Thickness(6, 2, 6, 4));
                header.HorizontalAlignment = HorizontalAlignment.Right;
                if (columnBrushes != null) header.Foreground = columnBrushes[c];
                Place(grid, header, 0, c + 1);
            }
            var totalHeader = Text("Total", 12, true, new Thickness(6, 2, 6, 4));
            totalHeader.HorizontalAlignment = HorizontalAlignment.Right;
            Place(grid, totalHeader, 0, columnNames.Count + 1);
            for (int r = 0; r < rowNames.Count; r++)
            {
                Place(grid, Text(rowNames[r], 12, false, new Thickness(0, 2, 12, 2)), r + 1, 0);
                int total = 0;
                for (int c = 0; c < columnNames.Count; c++)
                {
                    int v = value(r, c);
                    total += v;
                    var cell = Text(v == 0 ? "-" : Number(v), 12, false, new Thickness(6, 2, 6, 2));
                    cell.HorizontalAlignment = HorizontalAlignment.Right;
                    Place(grid, cell, r + 1, c + 1);
                }
                var totalCell = Text(Number(total), 12, true, new Thickness(6, 2, 6, 2));
                totalCell.HorizontalAlignment = HorizontalAlignment.Right;
                Place(grid, totalCell, r + 1, columnNames.Count + 1);
            }
            return grid;
        }

        /// <summary>Vertical stacked columns, one per entry, with a label under each.</summary>
        public static FrameworkElement Columns(IList<string> labels, IList<int[]> values, IList<Brush> brushes, IList<string> names, double height = 180)
        {
            int max = Math.Max(1, values.Select(v => v.Sum()).DefaultIfEmpty(0).Max());
            var panel = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Bottom };
            for (int i = 0; i < labels.Count; i++)
            {
                var column = new StackPanel { Width = 34, Margin = new Thickness(2, 0, 2, 0), VerticalAlignment = VerticalAlignment.Bottom };
                var bars = new StackPanel { VerticalAlignment = VerticalAlignment.Bottom, Height = height };
                var stack = new StackPanel { VerticalAlignment = VerticalAlignment.Bottom };
                for (int s = values[i].Length - 1; s >= 0; s--)
                {
                    if (values[i][s] <= 0) continue;
                    stack.Children.Add(new Border
                    {
                        Height = Math.Max(1, height * values[i][s] / max),
                        Background = brushes[s],
                        ToolTip = labels[i] + " - " + names[s] + ": " + Number(values[i][s])
                    });
                }
                bars.Children.Add(new Border { Height = Math.Max(0, height - stack.Children.OfType<Border>().Sum(b => b.Height)) });
                bars.Children.Add(stack);
                column.Children.Add(Text(Number(values[i].Sum()), 10, false, new Thickness(0, 0, 0, 2)));
                column.Children.Add(bars);
                var label = Text(labels[i], 10, false, new Thickness(0, 2, 0, 0));
                label.TextWrapping = TextWrapping.NoWrap;
                label.LayoutTransform = new RotateTransform(-60);
                column.Children.Add(label);
                panel.Children.Add(column);
            }
            return new ScrollViewer { Content = panel, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled };
        }

        /// <summary>Banner colour by marking (DoD/ISOO conventions); the text is the marking as set in Vulnerator.</summary>
        public static string BannerColor(string marking, out bool darkText)
        {
            string m = (marking ?? string.Empty).ToUpperInvariant();
            darkText = false;
            if (m.Contains("TOP SECRET") && m.Contains("SCI")) { darkText = true; return "#FCE83A"; }
            if (m.Contains("TOP SECRET")) return "#FF8C00";
            if (m.Contains("SECRET")) return "#C8102E";
            if (m.Contains("CONFIDENTIAL")) return "#0033A0";
            if (m.Contains("CUI") || m.Contains("CONTROLLED")) return "#502B85";
            if (m.Contains("UNCLASSIFIED")) return "#007A33";
            return "#505050";
        }

        public static Border Banner(string marking)
        {
            bool darkText;
            string color = BannerColor(marking, out darkText);
            return new Border
            {
                Background = Frozen(color),
                Padding = new Thickness(4),
                Child = new TextBlock
                {
                    Text = marking,
                    Foreground = darkText ? Brushes.Black : Brushes.White,
                    FontWeight = FontWeights.Bold,
                    HorizontalAlignment = HorizontalAlignment.Center
                }
            };
        }

        public static void Place(Grid grid, UIElement element, int row, int column)
        {
            Grid.SetRow(element, row);
            Grid.SetColumn(element, column);
            grid.Children.Add(element);
        }

        private static Brush Frozen(string color)
        {
            var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
            brush.Freeze();
            return brush;
        }
    }
}
