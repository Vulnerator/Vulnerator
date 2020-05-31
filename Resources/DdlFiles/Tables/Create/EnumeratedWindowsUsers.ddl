CREATE TABLE IF NOT EXISTS EnumeratedWindowsUsers (
    EnumeratedWindowsUser_ID INTEGER PRIMARY KEY,
    EnumeratedWindowsUserName NVARCHAR (25) NOT NULL,
    IsGuestAccount NVARCHAR (5) NOT NULL,
    IsDomainAccount NVARCHAR (5) NOT NULL,
    IsLocalAccount NVARCHAR (5) NOT NULL,
    UNIQUE (EnumeratedWindowsUserName) ON CONFLICT IGNORE
);