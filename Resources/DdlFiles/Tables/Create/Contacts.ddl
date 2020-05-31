CREATE TABLE IF NOT EXISTS Contacts (
    Contact_ID INTEGER PRIMARY KEY,
    ContactFirstName NVARCHAR (50) NOT NULL,
    ContactLastName NVARCHAR (50) NOT NULL,
    ContactEmail NVARCHAR (100) NOT NULL,
    ContactPhone NVARCHAR (20),
    Organization_ID INTEGER,
    FOREIGN KEY (Organization_ID) REFERENCES Organizations(Organization_ID)
);