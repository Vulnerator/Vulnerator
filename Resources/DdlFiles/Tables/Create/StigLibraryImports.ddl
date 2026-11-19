CREATE TABLE IF NOT EXISTS StigLibraryImports (
    StigLibraryImport_ID INTEGER PRIMARY KEY,
    ImportedOn           DATETIME NOT NULL,
    Source               NVARCHAR (500),
    Stigs                INTEGER,
    Rules                INTEGER
);
