CREATE TABLE IF NOT EXISTS Hardware_IP_Addresses (
    Hardware_IP_Address_ID INTEGER PRIMARY KEY,
    Hardware_ID INTEGER NOT NULL,
    IP_Address_ID INTEGER NOT NULL,
    UNIQUE (Hardware_ID, IP_Address_ID) ON CONFLICT IGNORE,
    FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
    FOREIGN KEY (IP_Address_ID) REFERENCES Ip_Addresses(IP_Address_ID)
);