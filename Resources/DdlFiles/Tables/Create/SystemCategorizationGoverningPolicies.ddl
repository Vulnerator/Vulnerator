CREATE TABLE IF NOT EXISTS SystemCategorizationGoverningPolicies (
    SystemCategorizationGoverningPolicy_ID INTEGER PRIMARY KEY,
    SystemCategorization_ID INTEGER NOT NULL,
    GoverningPolicy_ID INTEGER NOT NULL,
    UNIQUE (SystemCategorization_ID, GoverningPolicy_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
    FOREIGN KEY (GoverningPolicy_ID) REFERENCES GoverningPolicies(GoverningPolicy_ID)
);