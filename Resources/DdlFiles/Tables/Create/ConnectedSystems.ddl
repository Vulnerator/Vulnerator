CREATE TABLE IF NOT EXISTS ConnectedSystems (
    ConnectedSystem_ID INTEGER PRIMARY KEY,
    ConnectedSystemName NVARCHAR (100) NOT NULL,
    IsAuthorized NVARCHAR (5) NOT NULL
);