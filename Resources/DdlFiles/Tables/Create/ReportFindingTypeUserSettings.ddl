CREATE TABLE IF NOT EXISTS ReportFindingTypeUserSettings (
    ReportFindingTypeUserSettings_ID INTEGER PRIMARY KEY ,
    RequiredReport_ID INTEGER NOT NULL,
    FindingType_ID INTEGER NOT NULL,
    UserName NVARCHAR (50) NOT NULL,
    IsSelected NVARCHAR (5) NOT NULL,
    FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID),
    FOREIGN KEY (FindingType_ID) REFERENCES FindingTypes(FindingType_ID),
    UNIQUE (RequiredReport_ID, FindingType_ID, UserName) ON CONFLICT IGNORE
);