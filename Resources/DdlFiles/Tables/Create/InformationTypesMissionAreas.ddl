CREATE TABLE IF NOT EXISTS InformationTypesMissionAreas (
    InformationType_ID INTEGER NOT NULL,
    MissionArea_ID INTEGER NOT NULL,
    FOREIGN KEY (InformationType_ID) REFERENCES InformationTypes(InformationType_ID),
    FOREIGN KEY (MissionArea_ID) REFERENCES MissionAreas(MissionArea_ID)
);