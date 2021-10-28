CREATE TABLE IF NOT EXISTS Policies (
    Policy_ID               INTEGER PRIMARY KEY,
    Text                    NVARCHAR (MAX),
    Inheritability          NVARCHAR (20) NOT NULL,
    Group_ID                INTEGER NOT NULL,
    NIST_ControlCCI_ID      INTEGER NOT NULL,
    UNIQUE (
        Group_ID,
        NIST_ControlCCI_ID
    ) ON CONFLICT IGNORE,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (NIST_ControlCCI_ID) REFERENCES NIST_ControlsCCIs(NIST_ControlCCI_ID)
);