CREATE TABLE IF NOT EXISTS HardwareIdentifiers (
    HardwareIdentifier_ID INTEGER PRIMARY KEY,
    Hardware_ID INTEGER NOT NULL,
    IdentifierType NVARCHAR (25) NOT NULL,
    IdentifierValue NVARCHAR (500) NOT NULL,
    UNIQUE (IdentifierType, IdentifierValue) ON CONFLICT REPLACE,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID)
);
