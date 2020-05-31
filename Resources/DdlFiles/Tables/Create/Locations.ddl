CREATE TABLE IF NOT EXISTS Locations (
    Location_ID INTEGER PRIMARY KEY,
    LocationName NVARCHAR (200) NOT NULL,
    StreetAddressOne NVARCHAR (200) NOT NULL,
    StreeAddressTwo NVARCHAR (200) NOT NULL,
    BuildingNumber NVARCHAR (25),
    FloorNumber INTEGER,
    RoomNumber INTEGER,
    City NVARCHAR (50),
    State NVARCHAR (25),
    Country NVARCHAR (100) NOT NULL,
    ZipCode INTEGER,
    APO_FPO NVARCHAR (200),
    OSS_AccreditationDate DATETIME
);