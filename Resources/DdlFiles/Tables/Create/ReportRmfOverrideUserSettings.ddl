CREATE TABLE IF NOT EXISTS ReportRmfOverrideUserSettings (
    ReportRmfOverrideUserSettings_ID INTEGER PRIMARY KEY ,
    RequiredReport_ID INTEGER NOT NULL,
    Group_ID INTEGER,
    UserName NVARCHAR (50) NOT NULL,
    IsSelected NVARCHAR (5) NOT NULL,
    FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID),
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    UNIQUE (RequiredReport_ID, UserName) ON CONFLICT IGNORE
);