CREATE TABLE IF NOT EXISTS GroupsConnections (
    GroupsConnections_ID INTEGER PRIMARY KEY,
    Group_ID INTEGER NOT NULL,
    Connection_ID INTEGER NOT NULL,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (Connection_ID) REFERENCES Connections(Connection_ID)
);