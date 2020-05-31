CREATE TABLE IF NOT EXISTS ReportSeverityUserSettings (
    ReportSeverityUserSettings_ID INTEGER PRIMARY KEY,
    RequiredReport_ID INTEGER NOT NULL,
    UserName NVARCHAR (50) NOT NULL,
    ReportCatI INTEGER NOT NULL,
    ReportCatII INTEGER NOT NULL,
    ReportCatIII INTEGER NOT NULL,
    ReportCatIV INTEGER NOT NULL,
    FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID),
    UNIQUE (RequiredReport_ID, UserName) ON CONFLICT IGNORE
);