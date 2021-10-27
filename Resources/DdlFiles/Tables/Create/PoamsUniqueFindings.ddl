CREATE TABLE IF NOT EXISTS PoamsUniqueFindings (
    PoamUniqueFinding_ID INTEGER PRIMARY KEY,
    Poam_ID INTEGER NOT NULL,
    UniqueFinding_ID INTEGER NOT NULL,
    UNIQUE (
        Poam_ID,
        UniqueFinding_ID
    ) ON CONFLICT IGNORE,
    FOREIGN KEY (Poam_ID) REFERENCES Poams(Poam_ID),
    FOREIGN KEY (UniqueFinding_ID) REFERENCES UniqueFindings(UniqueFinding_ID)
);