CREATE TABLE IF NOT EXISTS GroupsCCIs (
    GroupsCCIs_ID INTEGER PRIMARY KEY,
    Group_ID INTEGER NOT NULL,
    CCI_ID INTEGER NOT NULL,
    IsInherited NVARCHAR (5),
    InheritedFrom NVARCHAR (50),
    Inheritable NVARCHAR (5),
    ImplementationStatus NVARCHAR (25),
    ImplementationNotes NVARCHAR (500),
    UNIQUE (Group_ID, CCI_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
);