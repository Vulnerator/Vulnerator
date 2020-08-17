CREATE TABLE IF NOT EXISTS RequiredReportUserSelections (
    RequiredReportUserSelection_ID INTEGER PRIMARY KEY ,
    RequiredReport_ID INTEGER NOT NULL ,
    UserName NVARCHAR (100) NOT NULL,
    IsReportSelected NVARCHAR (5) NOT NULL,
    UNIQUE (RequiredReport_ID, UserName) ON CONFLICT IGNORE ,
    FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID)
);