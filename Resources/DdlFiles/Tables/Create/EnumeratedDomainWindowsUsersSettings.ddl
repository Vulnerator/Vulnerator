CREATE TABLE IF NOT EXISTS EnumeratedDomainWindowsUsersSettings (
    EnumeratedDomainWindowsUsersSettings_ID Integer PRIMARY KEY,
    EnumeratedWindowsUser_ID INTEGER NOT NULL,
    WindowsDomainUserSettings_ID INTEGER NOT NULL,
    UNIQUE (
            EnumeratedWindowsUser_ID,
            WindowsDomainUserSettings_ID
        ) ON CONFLICT IGNORE,
    FOREIGN KEY (EnumeratedWindowsUser_ID) REFERENCES EnumeratedWindowsUsers(EnumeratedWindowsUser_ID),
    FOREIGN KEY (WindowsDomainUserSettings_ID) REFERENCES WindowsDomainUserSettings(WindowsDomainUserSettings_ID)
);