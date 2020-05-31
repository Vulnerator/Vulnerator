CREATE TABLE IF NOT EXISTS HardwareEnumeratedWindowsGroups (
    HardwareEnumeratedWindowGroup_ID INTEGER PRIMARY KEY,
    Hardware_ID INTEGER NOT NULL,
    EnumeratedWindowsGroup_ID INTEGER NOT NULL,
    UNIQUE (Hardware_ID, EnumeratedWindowsGroup_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
    FOREIGN KEY (EnumeratedWindowsGroup_ID) REFERENCES EnumeratedWindowsGroups(EnumeratedWindowsGroup_ID)
);