CREATE TABLE IF NOT EXISTS Boundaries (
    Boundary_ID INTEGER PRIMARY KEY,
    BoundaryName NVARCHAR (50) NOT NULL,
    BoundaryAlternateName NVARCHAR (50),
    BoundaryAcronym NVARCHAR (25),
    BoundaryType NVARCHAR (50) NOT NULL
);