CREATE TABLE IF NOT EXISTS NIST_ControlsCCPs (
    NIST_ControlCCP_ID INTEGER PRIMARY KEY,
    NIST_Control_ID INTEGER NOT NULL,
    CommonControlPackage_ID INTEGER NOT NULL,
    UNIQUE (NIST_Control_ID, CommonControlPackage_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
    FOREIGN KEY (CommonControlPackage_ID) REFERENCES CommonControlPackages(CommonControlPackage_ID)
);