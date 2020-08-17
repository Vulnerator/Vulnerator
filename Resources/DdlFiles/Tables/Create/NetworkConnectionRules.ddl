CREATE TABLE IF NOT EXISTS NetworkConnectionRules (
    NetworkConnectionRule_ID INTEGER PRIMARY KEY,
    NetworkConnectionName NVARCHAR (50) NOT NULL,
    NetworkConnectionRule NVARCHAR (200) NOT NULL,
    UNIQUE (NetworkConnectionName, NetworkConnectionRule) ON CONFLICT IGNORE
);