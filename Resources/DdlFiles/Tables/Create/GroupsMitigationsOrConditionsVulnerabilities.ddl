CREATE TABLE IF NOT EXISTS GroupsMitigationsOrConditionsVulnerabilities (
    GroupMitigationOrConditionVulnerability_ID      INTEGER PRIMARY KEY,
    Group_ID                                        INTEGER NOT NULL,
    MitigationOrCondition_ID                        INTEGER NOT NULL,
    Vulnerability_ID                                INTEGER NOT NULL,
    UNIQUE (
            Group_ID,
            MitigationOrCondition_ID,
            Vulnerability_ID
        ) ON CONFLICT IGNORE,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (MitigationOrCondition_ID) REFERENCES MitigationsOrConditions(MitigationOrCondition_ID),
    FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID)
);