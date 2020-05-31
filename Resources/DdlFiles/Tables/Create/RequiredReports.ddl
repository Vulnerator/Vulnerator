CREATE TABLE IF NOT EXISTS RequiredReports (
    RequiredReport_ID INTEGER PRIMARY KEY,
    DisplayedReportName NVARCHAR (50) NOT NULL,
    ReportType NVARCHAR (50) NOT NULL,
    IsReportEnabled NVARCHAR (5) NOT NULL,
    ReportCategory NVARCHAR (50) NOT NULL
);