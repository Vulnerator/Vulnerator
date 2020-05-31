CREATE TABLE IF NOT EXISTS GroupsConnectedSystems (
    GroupsConnectedSystems_ID INTEGER PRIMARY KEY,
    Group_ID INTEGER NOT NULL,
    ConnectedSystem_ID INTEGER NOT NULL,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (ConnectedSystem_ID) REFERENCES ConnectedSystems(ConnectedSystem_ID)
);