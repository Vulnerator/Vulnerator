CREATE TABLE IF NOT EXISTS MitigationsOrConditions
(
    MitigationOrCondition_ID  INTEGER PRIMARY KEY,
    ImpactDescription         NVARCHAR(2000),
    PredisposingConditions    NVARCHAR(2000),
    TechnicalMitigation       NVARCHAR(2000),
    ProposedMitigation        NVARCHAR(2000),
    ThreatDescription         NVARCHAR(2000),
    ThreatRelevance           NVARCHAR(10),
    SeverityPervasiveness     NVARCHAR(10),
    Likelihood                NVARCHAR(10),
    Impact                    NVARCHAR(10),
    Risk                      NVARCHAR(10),
    ResidualRisk              NVARCHAR(10),
    ResidualRiskAfterProposed NVARCHAR(10),
    MitigatedStatus           NVARCHAR(25),
    EstimatedCompletionDate   DATETIME,
    ApprovalDate              DATETIME,
    ExpirationDate            DATETIME,
    IsApproved                NVARCHAR(5),
    Approver                  NVARCHAR(100)
);