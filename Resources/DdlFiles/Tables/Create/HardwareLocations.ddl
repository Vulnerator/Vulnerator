CREATE TABLE IF NOT EXISTS HardwareLocations (
    HardwareLocation_ID INTEGER PRIMARY KEY,
    Hardware_ID INTEGER NOT NULL,
    Location_ID INTEGER NOT NULL,
    IsBaselineLocation NVARCHAR (5) NOT NULL,
    IsDeploymentLocation NVARCHAR (5) NOT NULL,
    IsTestLocation NVARCHAR (5) NOT NULL,
    UNIQUE (Hardware_ID, Location_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
    FOREIGN KEY (Location_ID) REFERENCES Locations(Location_ID)
);