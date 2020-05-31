CREATE TABLE IF NOT EXISTS PortServicesSoftware (
    PortServiceSoftware_ID INTEGER PRIMARY KEY,
    PortService_ID INTEGER NOT NULL,
    Software_ID INTEGER NOT NULL,
    UNIQUE (PortService_ID, Software_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (PortService_ID) REFERENCES PortsServices(PortService_ID),
    FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID)
);