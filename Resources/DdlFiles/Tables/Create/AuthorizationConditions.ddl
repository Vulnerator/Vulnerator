CREATE TABLE IF NOT EXISTS AuthorizationConditions (
    AuthorizationCondition_ID INTEGER PRIMARY KEY,
    AuthorizationCondition NVARCHAR (500) NOT NULL,
    AuthorizationConditionCompletionDate DATETIME NOT NULL,
    AuthorizationConditionIsCompleted INTEGER NOT NULL
);