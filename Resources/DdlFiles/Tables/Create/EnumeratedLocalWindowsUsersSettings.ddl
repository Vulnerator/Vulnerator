CREATE TABLE IF NOT EXISTS EnumeratedLocalWindowsUsersSettings (
    EnumeratedLocalWindowsUsersSettings_ID INTEGER PRIMARY KEY,
    EnumeratedWindowsUser_ID INTEGER NOT NULL,
    WindowsLocalUserSettings_ID INTEGER NOT NULL,
    UNIQUE (
           EnumeratedWindowsUser_ID,
           WindowsLocalUserSettings_ID
       ) ON CONFLICT IGNORE,
    FOREIGN KEY (EnumeratedWindowsUser_ID) REFERENCES EnumeratedWindowsUsers(EnumeratedWindowsUser_ID),
    FOREIGN KEY (WindowsLocalUserSettings_ID) REFERENCES WindowsLocalUserSettings(WindowsLocalUserSettings_ID)
);