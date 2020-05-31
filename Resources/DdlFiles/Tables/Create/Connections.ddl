CREATE TABLE IF NOT EXISTS Connections (
    Connection_ID INTEGER PRIMARY KEY,
    IsInternetConnected NVARCHAR (5),
    IsDODIN_Connected NVARCHAR (5),
    IsDMZ_Connected NVARCHAR (5),
    IsVPN_Connected NVARCHAR (5),
    IsCND_ServiceProvider NVARCHAR (5),
    IsEnterpriseServicesProvider NVARCHAR (5)
);