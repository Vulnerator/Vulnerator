CREATE TABLE IF NOT EXISTS GroupsOverlays (
    GroupOverlay_ID INTEGER PRIMARY KEY,
    Group_ID INTEGER NOT NULL,
    Overlay_ID INTEGER NOT NULL,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
    FOREIGN KEY (Overlay_ID) REFERENCES Overlays(Overlay_ID)
);