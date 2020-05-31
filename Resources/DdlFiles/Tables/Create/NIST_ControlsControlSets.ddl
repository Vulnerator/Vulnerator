CREATE TABLE IF NOT EXISTS NIST_ControlsControlSets (
    NIST_ControlsControlSet_ID INTEGER PRIMARY KEY,
    NIST_Control_ID INTEGER NOT NULL,
    ControlSet_ID INTEGER NOT NULL,
    UNIQUE (NIST_Control_ID, ControlSet_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
    FOREIGN KEY (ControlSet_ID) REFERENCES ControlSets(ControlSet_ID)
);