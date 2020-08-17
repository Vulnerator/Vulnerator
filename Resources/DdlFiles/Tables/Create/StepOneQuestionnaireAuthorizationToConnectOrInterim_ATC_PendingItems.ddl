CREATE TABLE IF NOT EXISTS StepOneQuestionnaireAuthorizationToConnectOrInterim_ATC_PendingItems (
    StepOneQuestionnaireAuthorizationToConnectOrInterim_ATC_PendingItems_ID INTEGER PRIMARY KEY ,
    StepOneQuestionnaire_ID INTEGER NOT NULL ,
    AuthorizationToConnectOrInterim_ATC_PendingItem_ID INTEGER NOT NULL ,
    UNIQUE (StepOneQuestionnaire_ID, AuthorizationToConnectOrInterim_ATC_PendingItem_ID) ON CONFLICT IGNORE ,
    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
    FOREIGN KEY (AuthorizationToConnectOrInterim_ATC_PendingItem_ID) REFERENCES AuthorizationToConnectOrInterim_ATC_PendingItems(AuthorizationToConnectOrInterim_ATC_PendingItem_ID)
);