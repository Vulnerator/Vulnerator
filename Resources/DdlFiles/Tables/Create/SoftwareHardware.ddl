CREATE TABLE IF NOT EXISTS SoftwareHardware (
    SoftwareHardware_ID INTEGER PRIMARY KEY,
    Software_ID INTEGER NOT NULL,
    Hardware_ID INTEGER NOT NULL,
    InstallDate DATETIME,
    ReportInAccreditation NVARCHAR (5),
    ApprovedForBaseline NVARCHAR (5),
    BaselineApprover NVARCHAR (50),
    UNIQUE (Software_ID, Hardware_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
    UNIQUE (Software_ID, Hardware_ID) ON CONFLICT IGNORE
);