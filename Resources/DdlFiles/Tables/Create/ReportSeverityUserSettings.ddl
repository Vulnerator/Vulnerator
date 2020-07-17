CREATE TABLE IF NOT EXISTS ReportSeverityUserSettings (
    ReportSeverityUserSettings_ID INTEGER PRIMARY KEY,
    RequiredReport_ID INTEGER NOT NULL,
    UserName NVARCHAR (50) NOT NULL,
    Severity NVARCHAR (25) NOT NULL,
    IsSelected NVARCHAR (5) NOT NULL,
    FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID),
    UNIQUE (RequiredReport_ID, UserName, Severity) ON CONFLICT IGNORE
);