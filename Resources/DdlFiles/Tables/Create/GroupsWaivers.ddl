CREATE TABLE IF NOT EXISTS GroupsWaivers (
    GroupWaiver_ID INTEGER PRIMARY KEY,
    Group_ID INTEGER NOT NULL,
    Waiver_ID INTEGER NOT NULL,
    WaiverGrantedDate DATETIME NOT NULL,
    WaiverExpirationDate DATETIME NOT NULL,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (Waiver_ID) REFERENCES Waivers(Waiver_ID)
);