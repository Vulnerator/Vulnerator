CREATE TABLE IF NOT EXISTS UniqueFindingsMitigationsOrConditions (
    UniqueFindingsMitigationsOrConditions_ID    INTEGER PRIMARY KEY,
    UniqueFinding_ID                            INTEGER NOT NULL,
    MitigationOrCondition_ID                    INTEGER NOT NULL,
    UNIQUE (
        UniqueFinding_ID,
        MitigationOrCondition_ID
    ) ON CONFLICT IGNORE,
    FOREIGN KEY (UniqueFinding_ID) REFERENCES Groups(UniqueFinding_ID),
    FOREIGN KEY (MitigationOrCondition_ID) REFERENCES MitigationsOrConditions(MitigationOrCondition_ID)
);