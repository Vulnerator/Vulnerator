CREATE TABLE IF NOT EXISTS AuthorizationToConnectOrInterim_ATC_PendingItems (
    AuthorizationToConnectOrInterim_ATC_PendingItem_ID     INTEGER PRIMARY KEY,
    AuthorizationToConnectOrInterim_ATC_PendingItem        NVARCHAR(50) NOT NULL,
    AuthorizationToConnectOrInterim_ATC_PendingItemDueDate DATETIME NOT NULL
);