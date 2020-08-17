CREATE TABLE IF NOT EXISTS Connectivity (
    Connectivity_ID INTEGER PRIMARY KEY,
    ConnectivityName NVARCHAR (25) NOT NULL,
    HasOwnCircuit NVARCHAR (5) NOT NULL,
    CommandCommunicationsSecurityDesignatorNumber NVARCHAR (25) NOT NULL,
    CommandCommunicationsSecurityDesignatorLocation NVARCHAR (50) NOT NULL,
    CommandCommunicationsSecurityDesignatorSupport NVARCHAR (2000) NOT NULL
);