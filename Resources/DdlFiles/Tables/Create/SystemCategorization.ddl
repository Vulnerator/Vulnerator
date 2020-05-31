CREATE TABLE IF NOT EXISTS SystemCategorization (
    SystemCategorization_ID INTEGER PRIMARY KEY,
    SystemClassification NVARCHAR (25) NOT NULL,
    InformationClassification NVARCHAR (25) NOT NULL,
    InformationReleasability NVARCHAR (25) NOT NULL,
    HasGoverningPolicy NVARCHAR (5) NOT NULL,
    VaryingClearanceRequirements NVARCHAR (5) NOT NULL,
    ClearanceRequirementDescription NVARCHAR (2000),
    HasAggregationImpact NVARCHAR (5) NOT NULL,
    IsJointAuthorization NVARCHAR (5) NOT NULL,
    InvolvesIntelligenceActivities NVARCHAR (5) NOT NULL,
    InvolvesCryptoActivities NVARCHAR (5) NOT NULL,
    InvolvesCommandAndControl NVARCHAR (5) NOT NULL,
    IsMilitaryCritical NVARCHAR (5) NOT NULL,
    IsBusinessInfo NVARCHAR (5) NOT NULL,
    HasExecutiveOrderProtections NVARCHAR (5) NOT NULL,
    IsNss NVARCHAR (5) NOT NULL,
    CategorizationIsApproved NVARCHAR (5) NOT NULL
);