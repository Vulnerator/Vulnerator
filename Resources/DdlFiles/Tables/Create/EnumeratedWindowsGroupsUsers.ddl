CREATE TABLE IF NOT EXISTS EnumeratedWindowsGroupsUsers (
    EnumeratedWindowsGroup_ID INTEGER NOT NULL,
    EnumeratedWindowsUser_ID INTEGER NOT NULL,
    FOREIGN KEY (EnumeratedWindowsGroup_ID) REFERENCES EnumeratedWindowsGroups(EnumeratedWindowsGroup_ID),
    FOREIGN KEY (EnumeratedWindowsUser_ID) REFERENCES EnumeratedWindowsUsers(EnumeratedWindowsUser_ID)
);