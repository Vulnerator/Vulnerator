CREATE TABLE IF NOT EXISTS GroupsContactsTitles (
    GroupContactTitle_ID INTEGER PRIMARY KEY,
    Group_ID INTEGER NOT NULL,
    Contact_ID INTEGER NOT NULL,
    Title_ID INTEGER NOT NULL,
    UNIQUE (Group_ID, Contact_ID, Title_ID) ON CONFLICT IGNORE ,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID),
    FOREIGN KEY (Title_ID) REFERENCES  Titles(Title_ID)
);