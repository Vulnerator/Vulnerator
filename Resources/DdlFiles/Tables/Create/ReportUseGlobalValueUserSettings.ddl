CREATE TABLE IF NOT EXISTS ReportUseGlobalValueUserSettings (
    ReportUseGlobalValueUserSettings_ID INTEGER PRIMARY KEY ,
    RequiredReport_ID INTEGER NOT NULL,
    UserName NVARCHAR (50) NOT NULL,
    UseGlobalFindingTypeValue NVARCHAR (5) NOT NULL,
    UseGlobalGroupValue NVARCHAR (5) NOT NULL,
    UseGlobalRmfOverrideValue NVARCHAR (5) NOT NULL,
    UseGlobalSeverityValue NVARCHAR (5) NOT NULL,
    UseGlobalStatusValue NVARCHAR (5) NOT NULL,
    FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID),
    UNIQUE (RequiredReport_ID, UserName) ON CONFLICT IGNORE
);