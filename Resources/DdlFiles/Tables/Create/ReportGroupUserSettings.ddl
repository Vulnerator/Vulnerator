CREATE TABLE IF NOT EXISTS ReportGroupUserSettings (
    ReportGroupUserSettings_ID INTEGER PRIMARY KEY ,
    RequiredReport_ID INTEGER NOT NULL,
    Group_ID INTEGER NOT NULL,
    UserName NVARCHAR (50) NOT NULL,
    IsSelected NVARCHAR (5) NOT NULL,
    FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID),
    FOREIGN KEY (Group_ID) REFERENCES FindingTypes(Group_ID),
    UNIQUE (RequiredReport_ID, Group_ID, UserName) ON CONFLICT IGNORE
);