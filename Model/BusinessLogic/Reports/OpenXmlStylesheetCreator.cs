using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Spreadsheet;
using System;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    class OpenXmlStylesheetCreator
    {
        public Stylesheet CreateStylesheet()
        {
            try
            {
                HorizontalAlignmentValues leftHorizontal = HorizontalAlignmentValues.Left;
                HorizontalAlignmentValues rightHorizontal = HorizontalAlignmentValues.Right;
                HorizontalAlignmentValues centerHorizontal = HorizontalAlignmentValues.Center;
                VerticalAlignmentValues topVertical = VerticalAlignmentValues.Top;
                VerticalAlignmentValues centerVertical = VerticalAlignmentValues.Center;

                return new Stylesheet(
                    new Fonts(
                        /*Index 0 - Black*/ CreateFont("000000", false),
                        /*Index 1 - Bold Black*/ CreateFont("000000", true),
                        /*Index 2 - Purple*/ CreateFont("660066", false),
                        /*Index 3 - Bold Purple*/ CreateFont("660066", true),
                        /*Index 4 - Red*/ CreateFont("990000", false),
                        /*Index 5 - Bold Red*/ CreateFont("990000", true),
                        /*Index 6 - Orange*/ CreateFont("FF6600", false),
                        /*Index 7 - Bold Orange*/ CreateFont("FF6600", true),
                        /*Index 8 - Blue*/ CreateFont("0066FF", false),
                        /*Index 9 - Bold Blue*/ CreateFont("0066FF", true),
                        /*Index 10 - Green*/ CreateFont("339900", false),
                        /*Index 11 - Bold Green*/ CreateFont("339900", true),
                        /*Index 12 - Bold Black Large*/ CreateFont("000000", true)
                    ),
                    new Fills(
                        /*Index 0 - Default Fill (None)*/ CreateFill(string.Empty, PatternValues.None),
                        /*Index 1 - Default Fill (Gray125)*/ CreateFill(string.Empty, PatternValues.Gray125),
                        /*Index 2 - Dark Gray Fill*/ CreateFill("BBBBBB", PatternValues.Solid),
                        /*Index 3 - Light Gray Fill*/ CreateFill("EEEEEE", PatternValues.Solid),
                        /*Index 4 - Yellow Gray Fill*/ CreateFill("FFCC00", PatternValues.Solid)
                    ),
                    new Borders(
                        /*Index 0 - Default Border (None)*/ CreateBorder(false, false, false, false),
                        /*Index 1 - All Borders*/ CreateBorder(true, true, true, true),
                        /*Index 2 - Top & Bottom Borders*/ CreateBorder(true, false, true, false)
                    ),
                    new CellFormats(
                        /*Index 0 - Black Font, No Fill, No Borders, Wrap Text*/
                        CreateCellFormat(0, 0, 0, leftHorizontal, null, true),
                        /*Index 1 - Black Font, No Fill, No Borders, Horizontally Centered*/
                        CreateCellFormat(0, 0, 0, centerHorizontal, null, false),
                        /*Index 2 - Bold Black Font, Dark Gray Fill, All Borders*/
                        CreateCellFormat(1, 2, 1, null, null, false),
                        /*Index 3 - Bold Black Font, Dark Gray Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(1, 2, 2, centerHorizontal, centerVertical, false),
                        /*Index 4 - Bold Black Font, Dark Gray Fill, All Borders, Centered*/
                        CreateCellFormat(1, 2, 1, centerHorizontal, centerVertical, false),
                        /*Index 5 - Bold Purple Font, Light Gray Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(3, 3, 2, centerHorizontal, centerVertical, false),
                        /*Index 6 - Bold Red Font, Light Gray Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(5, 3, 2, centerHorizontal, centerVertical, false),
                        /*Index 7 - Bold Orange Font, Light Gray Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(7, 3, 2, centerHorizontal, centerVertical, false),
                        /*Index 8 - Bold Blue Font, Light Gray Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(9, 3, 2, centerHorizontal, centerVertical, false),
                        /*Index 9 - Bold Green Font, Light Gray Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(11, 3, 2, centerHorizontal, centerVertical, false),
                        /*Index 10 - Purple Font, No Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(2, 0, 2, centerHorizontal, centerVertical, false),
                        /*Index 11 - Red Font, No Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(4, 0, 2, centerHorizontal, centerVertical, false),
                        /*Index 12 - Orange Font, No Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(6, 0, 2, centerHorizontal, centerVertical, false),
                        /*Index 13 - Blue Font , No Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(8, 0, 2, centerHorizontal, centerVertical, false),
                        /*Index 14 - Green Font, No Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(10, 0, 2, centerHorizontal, centerVertical, false),
                        /*Index 15 - Bold Black Font, Yellow Fill, All Borders, Centered, Wrap Text*/
                        CreateCellFormat(1, 4, 1, centerHorizontal, centerVertical, true),
                        /*Index 16 - Bold Black Font, No Fill, All Borders, Wrap Text*/
                        CreateCellFormat(1, 0, 1, centerHorizontal, centerVertical, true),
                        /*Index 17 - Bold Black Font, Light Gray Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(1, 3, 2, centerHorizontal, centerVertical, false),
                        /*Index 18 - Bold Black Font, No Fill, Top & Bottom Borders, Centered*/
                        CreateCellFormat(0, 0, 2, centerHorizontal, centerVertical, false),
                        /*Index 19 - Bold Black Font, Dark Gray Fill, Top & Bottom Borders, Centered Vertically*/
                        CreateCellFormat(1, 2, 1, null, centerVertical, false),
                        /*Index 20 - Black Font, No Fill, All Borders, Top Aligned, Wrap Text*/
                        CreateCellFormat(0, 0, 1, null, topVertical, true),
                        /*Index 21 - Black Font, No Fill, All Borders, Centered Vertically, Wrap Text*/
                        CreateCellFormat(0, 0, 1, null, centerVertical, true),
                        /*Index 22 - Black Font, No Fill, All Borders, Centered, Wrap Text*/
                        CreateCellFormat(0, 0, 1, centerHorizontal, centerVertical, true),
                        /*Index 23 - Black Font, No Fill, All Borders, Centered Vertically, Right Aligned*/
                        CreateCellFormat(0, 0, 1, rightHorizontal, centerVertical, false),
                        /*Index 24 - Black Font, No Fill, All Borders, Centered Horizontally, Top Aligned, Wrap Text*/
                        CreateCellFormat(0, 0, 1, centerHorizontal, topVertical, true),
                        /*Index 25 - Bold Black Font, No Fill, No Borders, Wrap Text*/
                        CreateCellFormat(1, 0, 0, leftHorizontal, topVertical, false),
                        /*Index 26 - Bold Black Font, Dark Gray Fill, All Borders, Centered, Wrap Text*/
                        CreateCellFormat(1, 2, 1, centerHorizontal, centerVertical, true)
                    )
                );
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to create Excel report Stylesheet.");
                throw exception;
            }
        }

        private Font CreateFont(string fontColor, bool isBold)
        {
            try
            {
                Font font = new Font();
                font.FontSize = new FontSize() {Val = 10};
                font.Color = new Color {Rgb = new HexBinaryValue() {Value = fontColor}};
                font.FontName = new FontName() {Val = "Calibri"};
                if (isBold)
                {
                    font.Bold = new Bold();
                }

                return font;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to create Font.");
                throw exception;
            }
        }

        private Fill CreateFill(string fillColor, PatternValues patternValue)
        {
            try
            {
                Fill fill = new Fill();
                PatternFill patternfill = new PatternFill();
                patternfill.PatternType = patternValue;
                if (!string.IsNullOrWhiteSpace(fillColor))
                {
                    patternfill.ForegroundColor = new ForegroundColor() {Rgb = new HexBinaryValue {Value = fillColor}};
                }

                fill.PatternFill = patternfill;

                return fill;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to create Fill.");
                throw exception;
            }
        }

        private Border CreateBorder(bool topBorderRequired, bool rightBorderRequired, bool bottomBorderRequired,
            bool leftBorderRequired)
        {
            try
            {
                Border border = new Border();
                if (!topBorderRequired && !rightBorderRequired && !bottomBorderRequired && !leftBorderRequired)
                {
                    border.TopBorder = new TopBorder();
                    border.RightBorder = new RightBorder();
                    border.BottomBorder = new BottomBorder();
                    border.LeftBorder = new LeftBorder();
                    border.DiagonalBorder = new DiagonalBorder();
                }
                else
                {
                    if (topBorderRequired)
                    {
                        border.TopBorder = new TopBorder(new Color() {Auto = true}) {Style = BorderStyleValues.Thin};
                    }

                    if (rightBorderRequired)
                    {
                        border.RightBorder = new RightBorder(new Color() {Auto = true})
                            {Style = BorderStyleValues.Thin};
                    }

                    if (bottomBorderRequired)
                    {
                        border.BottomBorder = new BottomBorder(new Color() {Auto = true})
                            {Style = BorderStyleValues.Thin};
                    }

                    if (leftBorderRequired)
                    {
                        border.LeftBorder = new LeftBorder(new Color() {Auto = true}) {Style = BorderStyleValues.Thin};
                    }

                    border.DiagonalBorder = new DiagonalBorder();
                }

                return border;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to create Border.");
                throw exception;
            }
        }

        private CellFormat CreateCellFormat(UInt32Value fontId, UInt32Value fillId, UInt32Value borderId,
            HorizontalAlignmentValues? horizontalAlignment, VerticalAlignmentValues? verticalAlignment, bool wrapText)
        {
            try
            {
                CellFormat cellFormat = new CellFormat();
                Alignment alignment = new Alignment();
                if (horizontalAlignment != null)
                {
                    alignment.Horizontal = horizontalAlignment;
                }

                if (verticalAlignment != null)
                {
                    alignment.Vertical = verticalAlignment;
                }

                alignment.WrapText = wrapText;
                cellFormat.Alignment = alignment;
                cellFormat.FontId = fontId;
                cellFormat.FillId = fillId;
                cellFormat.BorderId = borderId;
                return cellFormat;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to create CellFormat.");
                throw exception;
            }
        }
    }
}