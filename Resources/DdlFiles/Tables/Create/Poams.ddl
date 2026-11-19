CREATE TABLE IF NOT EXISTS Poams (
    Poam_ID     INTEGER PRIMARY KEY,
    Group_ID    INTEGER NOT NULL,
    Status      NVARCHAR (20) NOT NULL,
    CreatedOn   DATE NOT NULL,
    ModifiedOn  DATE NOT NULL,
    FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID)
);