CREATE TABLE IF NOT EXISTS HardwareGroups (
    HardwareGroup_ID INTEGER PRIMARY KEY,
    Hardware_ID INTEGER NOT NULL,
    Group_ID INTEGER NOT NULL,
    UNIQUE (Hardware_ID, Group_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID)
);