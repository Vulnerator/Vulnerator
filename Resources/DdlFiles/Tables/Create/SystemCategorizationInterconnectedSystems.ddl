CREATE TABLE IF NOT EXISTS SystemCategorizationInterconnectedSystems (
    SystemCategorizationInterconnectedSystem_ID INTEGER PRIMARY KEY,
    SystemCategorization_ID INTEGER NOT NULL,
    InterconnectedSystem_ID INTEGER NOT NULL,
    UNIQUE (SystemCategorization_ID, InterconnectedSystem_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
    FOREIGN KEY (InterconnectedSystem_ID) REFERENCES InterconnectedSystems(InterconnectedSystem_ID)
);