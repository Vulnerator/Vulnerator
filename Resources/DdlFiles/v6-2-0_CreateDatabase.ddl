PRAGMA user_version = 1;

CREATE TABLE Accessibility (
                               Accessibility_ID INTEGER PRIMARY KEY,
                               LogicalAccess NVARCHAR (25) NOT NULL,
                               PhysicalAccess NVARCHAR (25) NOT NULL,
                               AV_Scan NVARCHAR (25) NOT NULL,
                               DODIN_ConnectionPeriodicity NVARCHAR (25) NOT NULL,
                               FOREIGN KEY (Accessibility_ID) REFERENCES StepOneQuestionnaire(Accessibility_ID)
);

CREATE TABLE AdditionalTestConsiderations (
                                              AdditionalTestConsideration_ID INTEGER PRIMARY KEY,
                                              AdditionalTestConsiderationTitle NVARCHAR (25),
                                              AdditionalTestConsiderationDetails NVARCHAR (1000)
);

CREATE TABLE AuthorizationToConnectOrInterim_ATC_PendingItems (
                                                                  AuthorizationToConnectOrInterim_ATC_PendingItem_ID INTEGER PRIMARY KEY,
                                                                  AuthorizationToConnectOrInterim_ATC_PendingItem NVARCHAR (50) NOT NULL,
                                                                  AuthorizationToConnectOrInterim_ATC_PendingItemDueDate DATE NOT NULL,
                                                                  StepOneQuestionnaire_ID INTEGER NOT NULL,
                                                                  FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID)
);

CREATE TABLE AuthorizationConditions (
                                         AuthorizationCondition_ID INTEGER PRIMARY KEY,
                                         AuthorizationCondition NVARCHAR (500) NOT NULL,
                                         AuthorizationConditionCompletionDate DATE NOT NULL,
                                         AuthorizationConditionIsCompleted INTEGER NOT NULL,
                                         StepOneQuestionnaire_ID INTEGER NOT NULL,
                                         FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID)
);

CREATE TABLE AvailabilityLevels (
                                    AvailabilityLevel_ID INTEGER PRIMARY KEY,
                                    AvailabilityLevel NVARCHAR (25) NOT NULL
);

CREATE TABLE CCIs (
                      CCI_ID INTEGER PRIMARY KEY,
                      CCI_Number NVARCHAR (25) NOT NULL,
                      CCI_Definition NVARCHAR (500) NOT NULL,
                      CCI_Type NVARCHAR (25) NOT NULL,
                      CCI_Status NVARCHAR (25) NOT NULL
);

CREATE TABLE Certifications (
                                Certification_ID INTEGER PRIMARY KEY,
                                CertificationName NVARCHAR (50) NOT NULL
);

CREATE TABLE CommonControlPackages (
                                       CCP_ID INTEGER PRIMARY KEY,
                                       CCP_Name NVARCHAR (100) NOT NULL
);

CREATE TABLE ConfidentialityLevels (
                                       ConfidentialityLevel_ID INTEGER PRIMARY KEY,
                                       ConfidentialityLevel NVARCHAR (25) NOT NULL
);

CREATE TABLE ConnectedSystems (
                                  ConnectedSystem_ID INTEGER PRIMARY KEY,
                                  ConnectedSystemName NVARCHAR (100) NOT NULL,
                                  IsAuthorized INTEGER NOT NULL
);

CREATE TABLE Connections (
                             Connection_ID INTEGER PRIMARY KEY,
                             IsInternetConnected INTEGER,
                             IsDODIN_Connected INTEGER,
                             IsDMZ_Connected INTEGER,
                             IsVPN_Connected INTEGER,
                             IsCND_ServiceProvider INTEGER,
                             IsEnterpriseServicesProvider INTEGER
);

CREATE TABLE Connectivity (
                              Connectivity_ID INTEGER PRIMARY KEY,
                              ConnectivityName NVARCHAR (25) NOT NULL,
                              HasOwnCircuit INTEGER NOT NULL,
                              CommandCommunicationsSecurityDesignatorNumber NVARCHAR (25) NOT NULL,
                              CommandCommunicationsSecurityDesignatorLocation NVARCHAR (50) NOT NULL,
                              CommandCommunicationsSecurityDesignatorSupport NVARCHAR (100) NOT NULL
);

CREATE TABLE Contacts (
                          Contact_ID INTEGER PRIMARY KEY,
                          ContactFirstName NVARCHAR (50) NOT NULL,
                          ContactLastName NVARCHAR (50) NOT NULL,
                          ContactEmail NVARCHAR (50) NOT NULL,
                          ContactPhone NVARCHAR (20),
                          ContactTitle NVARCHAR (50),
                          Organization_ID INTEGER,
                          FOREIGN KEY (Organization_ID) REFERENCES Organizations(Organization_ID)
);

CREATE TABLE ContactsCertifications (
                                        ContactsCertifications_ID INTEGER PRIMARY KEY,
                                        Contact_ID INTEGER NOT NULL,
                                        Certification_ID INTEGER NOT NULL,
                                        UNIQUE (Contact_ID, Certification_ID) ON CONFLICT IGNORE,
                                        FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID),
                                        FOREIGN KEY (Certification_ID) REFERENCES Certifications(Certification_ID)
);

CREATE TABLE ControlApplicabilityAssessment (
                                                CAA_ID INTEGER PRIMARY KEY,
                                                CAA_Name NVARCHAR (50) NOT NULL
);

CREATE TABLE ControlSelection (
                                  ControlSelection_ID INTEGER PRIMARY KEY,
                                  IsTierOneApplied INTEGER NOT NULL,
                                  TierOneAppliedJustification NVARCHAR (50) NOT NULL,
                                  IsTierTwoApplied INTEGER NOT NULL,
                                  TierTwoAppliedJustification NVARCHAR (50) NOT NULL,
                                  IsTierThreeApplied INTEGER NOT NULL,
                                  TierThreeAppliedJustification NVARCHAR (50) NOT NULL,
                                  IsCNSS_1253_Applied INTEGER NOT NULL,
                                  CNSS_1253_AppliedJustification NVARCHAR (50) NOT NULL,
                                  IsSpaceApplied INTEGER NOT NULL,
                                  SpaceAppliedJustification NVARCHAR (50) NOT NULL,
                                  IsCDS_Applied INTEGER NOT NULL,
                                  CDS_AppliedJustification NVARCHAR (50),
                                  IsIntelligenceApplied INTEGER NOT NULL,
                                  IntelligenceAppliedJustification NVARCHAR (50) NOT NULL,
                                  IsClassifiedApplied INTEGER NOT NULL,
                                  ClassifiedAppliedJustification NVARCHAR (50) NOT NULL,
                                  IsOtherApplied INTEGER NOT NULL,
                                  OtherAppliedJustification NVARCHAR (50) NOT NULL,
                                  AreCompensatingControlsApplied INTEGER NOT NULL,
                                  CompensatingControlsAppliedJustification NVARCHAR (50) NOT NULL,
                                  HasNA_BaselineControls INTEGER NOT NULL,
                                  NA_BaselineControlsAppliedJustification NVARCHAR (100) NOT NULL,
                                  AreBaselineControlsModified INTEGER NOT NULL,
                                  BaselineIsModifiedJustification NVARCHAR (100) NOT NULL,
                                  IsBaselineRiskModified INTEGER NOT NULL,
                                  BaselineRiskIsModificationJustification NVARCHAR (100) NOT NULL,
                                  IsBaselineScopeApproved INTEGER NOT NULL,
                                  BaselineScopeIsApprovedJustification NVARCHAR (100) NOT NULL,
                                  AreInheritableControlsDefined INTEGER NOT NULL,
                                  InheritableControlsAreDefinedJustification NVARCHAR (100) NOT NULL
);

CREATE TABLE ControlSets (
                             ControlSet_ID INTEGER PRIMARY KEY,
                             ControlSetName NVARCHAR (50) NOT NULL
);

CREATE TABLE CustomTestCases (
                                 CustomTestCase_ID INTEGER PRIMARY KEY,
                                 TestCaseName NVARCHAR (25) NOT NULL,
                                 TestCaseDescription NVARCHAR (500) NOT NULL,
                                 TestCaseBackground NVARCHAR (500) NOT NULL,
                                 TestCaseClassification NVARCHAR (25) NOT NULL,
                                 TestCaseSeverity NVARCHAR (25) NOT NULL,
                                 TestCaseAssessmentProcedure NVARCHAR (500) NOT NULL,
                                 TestCase_CCI NVARCHAR (25) NOT NULL,
                                 TestCase_NIST_Control NVARCHAR (25) NOT NULL
);

CREATE TABLE DADMS_Networks (
                                DADMS_Network_ID INTEGER PRIMARY KEY,
                                DADMS_NetworkName NVARCHAR (50) NOT NULL
);

CREATE TABLE EncryptionTechniques (
                                      EncryptionTechnique_ID INTEGER PRIMARY KEY,
                                      EncryptionTechnique NVARCHAR (100) NOT NULL,
                                      KeyManagement NVARCHAR (500) NOT NULL
);

CREATE TABLE EntranceCriteria (
                                  EntranceCriteria_ID INTEGER PRIMARY KEY,
                                  EntranceCriteria NVARCHAR (100) NOT NULL
);

CREATE TABLE EnumeratedDomainUsersSettings (
                                               EnumeratedDomainUsersSettings_ID Integer PRIMARY KEY,
                                               EnumeratedWindowsUser_ID INTEGER NOT NULL,
                                               WindowsDomainUserSettings_ID INTEGER NOT NULL,
                                               UNIQUE (
                                                       EnumeratedWindowsUser_ID,
                                                       WindowsDomainUserSettings_ID
                                                   ) ON CONFLICT IGNORE,
                                               FOREIGN KEY (EnumeratedWindowsUser_ID) REFERENCES EnumeratedWindowsUsers(EnumeratedWindowsUser_ID),
                                               FOREIGN KEY (WindowsDomainUserSettings_ID) REFERENCES WindowsDomainUserSettings(WindowsDomainUserSettings_ID)
);

CREATE TABLE EnumeratedLocalWindowsUsersSettings (
                                                     EnumeratedLocalWindowsUsersSettings_ID INTEGER PRIMARY KEY,
                                                     EnumeratedWindowsUser_ID INTEGER NOT NULL,
                                                     WindowsLocalUserSettings_ID INTEGER NOT NULL,
                                                     UNIQUE (
                                                             EnumeratedWindowsUser_ID,
                                                             WindowsLocalUserSettings_ID
                                                         ) ON CONFLICT IGNORE,
                                                     FOREIGN KEY (EnumeratedWindowsUser_ID) REFERENCES EnumeratedWindowsUsers(EnumeratedWindowsUser_ID),
                                                     FOREIGN KEY (WindowsLocalUserSettings_ID) REFERENCES WindowsLocalUserSettings(WindowsLocalUserSettings_ID)
);

CREATE TABLE EnumeratedWindowsGroups (
                                         EnumeratedWindowsGroup_ID INTEGER PRIMARY KEY,
                                         EnumeratedWindowsGroupName NVARCHAR (50) NOT NULL
);

CREATE TABLE EnumeratedWindowsGroupsUsers (
                                              EnumeratedWindowsGroup_ID INTEGER NOT NULL,
                                              EnumeratedWindowsUser_ID INTEGER NOT NULL,
                                              FOREIGN KEY (EnumeratedWindowsGroup_ID) REFERENCES EnumeratedWindowsGroups(EnumeratedWindowsGroup_ID),
                                              FOREIGN KEY (EnumeratedWindowsUser_ID) REFERENCES EnumeratedWindowsUsers(EnumeratedWindowsUser_ID)
);

CREATE TABLE EnumeratedWindowsUsers (
                                        EnumeratedWindowsUser_ID INTEGER PRIMARY KEY,
                                        EnumeratedWindowsUserName NVARCHAR (25) NOT NULL,
                                        IsGuestAccount NVARCHAR (5) NOT NULL,
                                        IsDomainAccount NVARCHAR (5) NOT NULL,
                                        IsLocalAccount NVARCHAR (5) NOT NULL,
                                        UNIQUE (EnumeratedWindowsUserName) ON CONFLICT IGNORE
);

CREATE TABLE ExitCriteria (
                              ExitCriteria_ID INTEGER PRIMARY KEY,
                              ExitCriteria NVARCHAR (100) NOT NULL
);

CREATE TABLE ExternalSecurityServices (
                                          ExternalSecurityServices_ID INTEGER PRIMARY KEY,
                                          ExternalSecurityService NVARCHAR (50) NOT NULL,
                                          ServiceDescription NVARCHAR (500) NOT NULL,
                                          SecurityRequirementsDescription NVARCHAR (500) NOT NULL,
                                          RiskDetermination NVARCHAR (100) NOT NULL
);

CREATE TABLE FindingTypes (
                              FindingType_ID INTEGER PRIMARY KEY,
                              FindingType NVARCHAR (25) NOT NULL
);

CREATE TABLE GoverningPolicies (
                                   GoverningPolicy_ID INTEGER PRIMARY KEY,
                                   GoverningPolicyName NVARCHAR (50)
);

CREATE TABLE Groups (
                        Group_ID INTEGER PRIMARY KEY,
                        GroupName NVARCHAR (50) NOT NULL UNIQUE ON CONFLICT IGNORE,
                        GroupAcronym NVARCHAR (25),
                        GroupTier INTEGER NOT NULL,
                        IsAccreditation NVARCHAR (5),
                        Accreditation_eMASS_ID NVARCHAR (25),
                        IsPlatform NVARCHAR (5),
                        Organization_ID INTEGER,
                        ConfidentialityLevel_ID INTEGER,
                        IntegrityLevel_ID INTEGER,
                        AvailabilityLevel_ID INTEGER,
                        SystemCategorization_ID INTEGER,
                        AccreditationVersion NVARCHAR (25),
                        CybersafeGrade CHAR (1),
                        FISCAM_Applies NVARCHAR (5),
                        ControlSelection_ID INTEGER,
                        HasForeignNationals NVARCHAR (5),
                        SystemType NVARCHAR (25),
                        RDTE_Zone CHAR (1),
                        StepOneQuestionnaire_ID INTEGER,
                        SecurityAssessmentProcedure_ID INTEGER,
                        PIT_Determination_ID INTEGER,
                        InformationSystemOwner_ID INTEGER,
                        FOREIGN KEY (ConfidentialityLevel_ID) REFERENCES ConfidentialityLevels(ConfidentialityLevel_ID),
                        FOREIGN KEY (IntegrityLevel_ID) REFERENCES IntegrityLevels(IntegrityLevel_ID),
                        FOREIGN KEY (AvailabilityLevel_ID) REFERENCES AvailabilityLevels(AvailabilityLevel_ID),
                        FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
                        FOREIGN KEY (ControlSelection_ID) REFERENCES ControlSelection(ControlSelection_ID),
                        FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
                        FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                        FOREIGN KEY (PIT_Determination_ID) REFERENCES PIT_Determination(PIT_Determination_ID),
                        FOREIGN KEY (Organization_ID) REFERENCES Organizations(Organization_ID),
                        FOREIGN KEY (InformationSystemOwner_ID) REFERENCES Contacts(Contact_ID)
);

CREATE TABLE GroupsCCIs (
                            GroupsCCIs_ID INTEGER PRIMARY KEY,
                            Group_ID INTEGER NOT NULL,
                            CCI_ID INTEGER NOT NULL,
                            IsInherited NVARCHAR (5),
                            InheritedFrom NVARCHAR (50),
                            Inheritable NVARCHAR (5),
                            ImplementationStatus NVARCHAR (25),
                            ImplementationNotes NVARCHAR (500),
                            UNIQUE (Group_ID, CCI_ID) ON CONFLICT IGNORE,
                            FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
                            FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
);

CREATE TABLE GroupsConnectedSystems (
                                        GroupsConnectedSystems_ID INTEGER PRIMARY KEY,
                                        Group_ID INTEGER NOT NULL,
                                        ConnectedSystem_ID INTEGER NOT NULL,
                                        FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
                                        FOREIGN KEY (ConnectedSystem_ID) REFERENCES ConnectedSystems(ConnectedSystem_ID)
);

CREATE TABLE GroupsConnections (
                                   GroupsConnections_ID INTEGER PRIMARY KEY,
                                   Group_ID INTEGER NOT NULL,
                                   Connection_ID INTEGER NOT NULL,
                                   FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
                                   FOREIGN KEY (Connection_ID) REFERENCES Connections(Connection_ID)
);

CREATE TABLE GroupsContacts (
                                GroupContact_ID INTEGER PRIMARY KEY,
                                Group_ID INTEGER NOT NULL,
                                Contact_ID INTEGER NOT NULL,
                                FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
                                FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
);

CREATE TABLE GroupsIATA_Standards (
                                      Group_ID INTEGER NOT NULL,
                                      IATA_Standard_ID INTEGER NOT NULL,
                                      FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
                                      FOREIGN KEY (IATA_Standard_ID) REFERENCES IATA_Standards(IATA_Standard_ID)
);

CREATE TABLE GroupsMitigationsOrConditions (
                                               GroupMitigationOrCondition_ID INTEGER PRIMARY KEY,
                                               MitigationOrCondition_ID INTEGER NOT NULL,
                                               Group_ID INTEGER NOT NULL,
                                               Vulnerability_ID INTEGER NOT NULL,
                                               UNIQUE (
                                                       MitigationOrCondition_ID,
                                                       Group_ID,
                                                       Vulnerability_ID
                                                   ) ON CONFLICT IGNORE,
                                               FOREIGN KEY (MitigationOrCondition_ID) REFERENCES MitigationsOrConditions(MitigationOrCondition_ID),
                                               FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
                                               FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID)
);

CREATE TABLE GroupsOverlays (
                                GroupOverlay_ID INTEGER PRIMARY KEY,
                                Group_ID INTEGER NOT NULL,
                                Overlay_ID INTEGER NOT NULL,
                                FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
                                FOREIGN KEY (Overlay_ID) REFERENCES Overlays(Overlay_ID)
);

CREATE TABLE GroupsWaivers (
                               GroupWaiver_ID INTEGER PRIMARY KEY,
                               Group_ID INTEGER NOT NULL,
                               Waiver_ID INTEGER NOT NULL,
                               WaiverGrantedDate DATE NOT NULL,
                               WaiverExpirationDate DATE NOT NULL,
                               FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID),
                               FOREIGN KEY (Waiver_ID) REFERENCES Waivers(Waiver_ID)
);

CREATE TABLE Hardware (
                          Hardware_ID INTEGER PRIMARY KEY,
                          DisplayedHostName NVARCHAR (50),
                          DiscoveredHostName NVARCHAR (50),
                          FQDN NVARCHAR (100),
                          NetBIOS NVARCHAR (100),
                          ScanIP NVARCHAR (25),
                          Found21745 NVARCHAR (5),
                          Found26917 NVARCHAR (5),
                          IsVirtualServer NVARCHAR (5),
                          NIAP_Level NVARCHAR (25),
                          Manufacturer NVARCHAR (25),
                          ModelNumber NVARCHAR (50),
                          IsIA_Enabled NVARCHAR (5),
                          SerialNumber NVARCHAR (50),
                          Role NVARCHAR (25),
                          LifecycleStatus_ID INTEGER,
                          OS NVARCHAR (100),
                          FOREIGN KEY (LifecycleStatus_ID) REFERENCES LifecycleStatuses(LifecycleStatus_ID),
                          UNIQUE (ScanIP, DiscoveredHostName, FQDN, NetBIOS) ON CONFLICT IGNORE
);

CREATE TABLE HardwareContacts (
                                  HardwareContact_ID INTEGER PRIMARY KEY,
                                  Hardware_ID INTEGER NOT NULL,
                                  Contact_ID INTEGER NOT NULL,
                                  FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                  FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
);

CREATE TABLE HardwareEnumeratedWindowsGroups (
                                                 HardwareEnumeratedWindowGroup_ID INTEGER PRIMARY KEY,
                                                 Hardware_ID INTEGER NOT NULL,
                                                 Group_ID INTEGER NOT NULL,
                                                 UNIQUE (Hardware_ID, Group_ID) ON CONFLICT IGNORE,
                                                 FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                                 FOREIGN KEY (Group_ID) REFERENCES EnumeratedWindowsGroups(EnumeratedWindowsGroup_ID)
);

CREATE TABLE HardwareGroups (
                                HardwareGroup_ID INTEGER PRIMARY KEY,
                                Hardware_ID INTEGER NOT NULL,
                                Group_ID INTEGER NOT NULL,
                                UNIQUE (Hardware_ID, Group_ID) ON CONFLICT IGNORE,
                                FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID)
);

CREATE TABLE Hardware_IP_Addresses (
                                       Hardware_IP_Address_ID INTEGER PRIMARY KEY,
                                       Hardware_ID INTEGER NOT NULL,
                                       IP_Address_ID INTEGER NOT NULL,
                                       UNIQUE (Hardware_ID, IP_Address_ID) ON CONFLICT IGNORE,
                                       FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                       FOREIGN KEY (IP_Address_ID) REFERENCES Ip_Addresses(IP_Address_ID)
);

CREATE TABLE HardwareLocation (
                                  HardwareLocation_ID INTEGER PRIMARY KEY,
                                  Hardware_ID INTEGER NOT NULL,
                                  Location_ID INTEGER NOT NULL,
                                  IsBaselineLocation NVARCHAR (5) NOT NULL,
                                  IsDeploymentLocation NVARCHAR (5) NOT NULL,
                                  IsTestLocation NVARCHAR (5) NOT NULL,
                                  UNIQUE (Hardware_ID, Location_ID) ON CONFLICT IGNORE,
                                  FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                  FOREIGN KEY (Location_ID) REFERENCES Locations(Location_ID)
);

CREATE TABLE Hardware_MAC_Addresses (
                                        Hardware_MAC_Address_ID INTEGER PRIMARY KEY,
                                        Hardware_ID INTEGER NOT NULL,
                                        MAC_Address_ID INTEGER NOT NULL,
                                        UNIQUE (Hardware_ID, MAC_Address_ID) ON CONFLICT IGNORE,
                                        FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                        FOREIGN KEY (MAC_Address_ID) REFERENCES MAC_Addresses(MAC_Address_ID)
);

CREATE TABLE HardwarePortsProtocols (
                                        HardwarePortsProtocols_ID INTEGER PRIMARY KEY,
                                        Hardware_ID INTEGER NOT NULL,
                                        PortsProtocols_ID INTEGER NOT NULL,
                                        ReportInAccreditation NVARCHAR (5),
                                        DiscoveredService NVARCHAR (25),
                                        DisplayService NVARCHAR (50),
                                        Direction NVARCHAR (25),
                                        BoundariesCrossed NVARCHAR (25),
                                        DoD_Compliant NVARCHAR (5),
                                        Classification NVARCHAR (25),
                                        UNIQUE (
                                                     Hardware_ID,
                                                     PortsProtocols_ID,
                                                     DiscoveredService
                                            ) ON CONFLICT IGNORE,
                                        FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                        FOREIGN KEY (PortsProtocols_ID) REFERENCES PortsProtocols(PortsProtocols_ID)
);

CREATE TABLE IA_Controls (
                             IA_Control_ID INTEGER PRIMARY KEY,
                             IA_ControlNumber NVARCHAR (10) NOT NULL,
                             Impact NVARCHAR (10) NOT NULL,
                             IA_ControlSubjectArea NVARCHAR (50) NOT NULL,
                             IA_ControlName NVARCHAR (100) NOT NULL,
                             IA_ControlDescription NVARCHAR (250) NOT NULL,
                             IA_ControlThreatVulnerabilityCountermeasures NVARCHAR (2000) NOT NULL,
                             IA_ControlGeneralImplementationGuidance NVARCHAR (2000) NOT NULL,
                             IA_ControlSystemSpecificGuidanceResources NVARCHAR (2000) NOT NULL
);

CREATE TABLE IATA_Standards (
                                IATA_Standard_ID INTEGER PRIMARY KEY,
                                IATA_StandardTitle NVARCHAR (50) NOT NULL,
                                IATA_StandardDescription NVARCHAR (1000) NOT NULL
);

CREATE TABLE ImpactAdjustments (
                                   ImpactAdjustment_ID INTEGER PRIMARY KEY,
                                   AdjustedConfidentiality NVARCHAR (25) NOT NULL,
                                   AdjustedIntegrity NVARCHAR (25) NOT NULL,
                                   AdjustedAvailability NVARCHAR (25) NOT NULL,
                                   FOREIGN KEY (ImpactAdjustment_ID) REFERENCES SystemCategorizationInformationTypes(ImpactAdjustment_ID)
);

CREATE TABLE InformationTypes (
                                  InformationType_ID INTEGER PRIMARY KEY,
                                  InfoTypeId NVARCHAR (25) NOT NULL,
                                  InfoTypeName NVARCHAR (50) NOT NULL,
                                  BaselineConfidentiality NVARCHAR,
                                  BaselineIntegrity NVARCHAR,
                                  BaselineAvailability NVARCHAR,
                                  EnhancedConfidentiality NVARCHAR,
                                  EnhancedIntegrity NVARCHAR,
                                  EnhancedAvailability NVARCHAR
);

CREATE TABLE InformationTypesMissionAreas (
                                              InformationType_ID INTEGER NOT NULL,
                                              MissionArea_ID INTEGER NOT NULL,
                                              FOREIGN KEY (InformationType_ID) REFERENCES InformationTypes(InformationType_ID),
                                              FOREIGN KEY (MissionArea_ID) REFERENCES MissionAreas(MissionArea_ID)
);

CREATE TABLE IntegrityLevels (
                                 IntegrityLevel_ID INTEGER PRIMARY KEY,
                                 IntegrityLevel NVARCHAR (25) NOT NULL
);

CREATE TABLE InterconnectedSystems (
                                       InterconnectedSystem_ID INTEGER PRIMARY KEY,
                                       InterconnectedSystemName NVARCHAR (50) NOT NULL
);

CREATE TABLE IP_Addresses (
                              IP_Address_ID INTEGER PRIMARY KEY,
                              IP_Address NVARCHAR (25) NOT NULL UNIQUE ON CONFLICT IGNORE
);

CREATE TABLE JointAuthorizationOrganizations (
                                                 JointOrganization_ID INTEGER PRIMARY KEY,
                                                 JointOrganizationName NVARCHAR (50) NOT NULL
);

CREATE TABLE LifecycleStatuses (
                                   LifecycleStatus_ID INTEGER PRIMARY KEY,
                                   LifecycleStatus NVARCHAR (25) NOT NULL
);

CREATE TABLE Limitations (
                             Limitation_ID INTEGER PRIMARY KEY,
                             LimitationSummary NVARCHAR (100) NOT NULL,
                             LimitationBackground NVARCHAR (500) NOT NULL,
                             LimitationDetails NVARCHAR (500) NOT NULL,
                             IsTestException NVARCHAR (5) NOT NULL
);

CREATE TABLE Locations (
                           Location_ID INTEGER PRIMARY KEY,
                           LocationName NVARCHAR (50) NOT NULL,
                           StreetAddressOne NVARCHAR (50) NOT NULL,
                           StreeAddressTwo NVARCHAR (50) NOT NULL,
                           BuildingNumber NVARCHAR (25),
                           FloorNumber INTEGER,
                           RoomNumber INTEGER,
                           City NVARCHAR (25),
                           State NVARCHAR (25),
                           Country NVARCHAR (25) NOT NULL,
                           ZipCode INTEGER,
                           APO_FPO NVARCHAR (50),
                           OSS_AccreditationDate DATE,
                           IsBaselineLocationGlobal NVARCHAR (5),
                           IsDeploymentLocationGlobal NVARCHAR (5),
                           IsTestLocationGlobal NVARCHAR (5)
);

CREATE TABLE MAC_Addresses (
                               MAC_Address_ID INTEGER PRIMARY KEY,
                               MAC_Address NVARCHAR (50) NOT NULL UNIQUE ON CONFLICT IGNORE
);

CREATE TABLE MissionAreas (
                              MissionArea_ID INTEGER PRIMARY KEY,
                              MissionArea NVARCHAR (25) NOT NULL
);

CREATE TABLE MitigationsOrConditions (
                                         MitigationOrCondition_ID INTEGER PRIMARY KEY,
                                         ImpactDescription NVARCHAR (2000),
                                         PredisposingConditions NVARCHAR (2000),
                                         TechnicalMitigation NVARCHAR (2000),
                                         ProposedMitigation NVARCHAR (2000),
                                         ThreatRelevance NVARCHAR (10),
                                         SeverityPervasiveness NVARCHAR (10),
                                         Likelihood NVARCHAR (10),
                                         Impact NVARCHAR (10),
                                         Risk NVARCHAR (10),
                                         ResidualRisk NVARCHAR (10),
                                         ResidualRiskAfterProposed NVARCHAR (10),
                                         MitigatedStatus NVARCHAR (25),
                                         EstimatedCompletionDate DATE,
                                         ApprovalDate DATE,
                                         ExpirationDate DATE,
                                         IsApproved NVARCHAR (5),
                                         Approver NVARCHAR (100)
);

CREATE TABLE NetworkConnectionRules (
                                        NetworkConnectionRule_ID INTEGER PRIMARY KEY,
                                        NetworkConnectionName NVARCHAR (25) NOT NULL,
                                        NetworkConnectionRule NVARCHAR (100) NOT NULL,
                                        UNIQUE (NetworkConnectionName, NetworkConnectionRule) ON CONFLICT IGNORE 
);

CREATE TABLE NIST_Controls (
                               NIST_Control_ID INTEGER PRIMARY KEY,
                               ControlFamily NVARCHAR (25) NOT NULL,
                               ControlNumber INTEGER NOT NULL,
                               ControlEnhancement INTEGER,
                               ControlTitle NVARCHAR (50) NOT NULL,
                               ControlText NVARCHAR (500) NOT NULL,
                               SupplementalGuidance NVARCHAR (500) NOT NULL,
                               MonitoringFrequency NVARCHAR (10)
);

CREATE TABLE NIST_Controls_IATA_Standards (
                                              NIST_ControlIATA_Standard_ID INTEGER PRIMARY KEY,
                                              NIST_Control_ID INTEGER NOT NULL,
                                              IATA_Standard_ID INTEGER NOT NULL,
                                              UNIQUE (NIST_Control_ID, IATA_Standard_ID) ON CONFLICT IGNORE,
                                              FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                              FOREIGN KEY (IATA_Standard_ID) REFERENCES IATA_Standards(IATA_Standard_ID)
);

CREATE TABLE NIST_ControlsAvailabilityLevels (
                                                 NIST_ControlAvailabilityLevel_ID INTEGER PRIMARY KEY,
                                                 NIST_Control_ID INTEGER NOT NULL,
                                                 AvailabilityLevel_ID INTEGER NOT NULL,
                                                 NSS_SystemsOnly NVARCHAR (10) NOT NULL,
                                                 UNIQUE (NIST_Control_ID, AvailabilityLevel_ID) ON CONFLICT IGNORE,
                                                 FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                                 FOREIGN KEY (AvailabilityLevel_ID) REFERENCES AvailabilityLevels(AvailabilityLevel_ID)
);

CREATE TABLE NIST_ControlsCCIs (
                                   NIST_ControlCCI_ID INTEGER PRIMARY KEY,
                                   NIST_Control_ID INTEGER NOT NULL,
                                   CCI_ID INTEGER NOT NULL,
                                   DOD_AssessmentProcedureMapping NVARCHAR (10),
                                   ControlIndicator NVARCHAR (25) NOT NULL,
                                   ImplementationGuidance NVARCHAR(1000) NOT NULL,
                                   AssessmentProcedureText NVARCHAR(1000) NOT NULL,
                                   UNIQUE (NIST_Control_ID, CCI_ID) ON CONFLICT IGNORE,
                                   FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                   FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
);

CREATE TABLE NIST_ControlsCAAs (
                                   NIST_ControlCAA_ID INTEGER PRIMARY KEY,
                                   NIST_Control_ID INTEGER NOT NULL,
                                   CAA_ID INTEGER NOT NULL,
                                   LegacyDifficulty NVARCHAR (10) NOT NULL,
                                   Applicability NVARCHAR (25) NOT NULL,
                                   UNIQUE (NIST_Control_ID, CAA_ID) ON CONFLICT IGNORE,
                                   FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                   FOREIGN KEY (CAA_ID) REFERENCES ControlApplicabilityAssessment(CAA_ID)
);

CREATE TABLE NIST_ControlsConfidentialityLevels (
                                                    NIST_ControlConfidentialityLevel_ID INTEGER PRIMARY KEY,
                                                    NIST_Control_ID INTEGER NOT NULL,
                                                    ConfidentialityLevel_ID INTEGER NOT NULL,
                                                    NSS_Systems_Only NVARCHAR (10) NOT NULL,
                                                    UNIQUE (NIST_Control_ID, ConfidentialityLevel_ID) ON CONFLICT IGNORE,
                                                    FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                                    FOREIGN KEY (ConfidentialityLevel_ID) REFERENCES ConfidentialityLevels(ConfidentialityLevel_ID)
);

CREATE TABLE NIST_ControlsControlSets (
                                          NIST_ControlsControlSet_ID INTEGER PRIMARY KEY,
                                          NIST_Control_ID INTEGER NOT NULL,
                                          ControlSet_ID INTEGER NOT NULL,
                                          UNIQUE (NIST_Control_ID, ControlSet_ID) ON CONFLICT IGNORE,
                                          FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                          FOREIGN KEY (ControlSet_ID) REFERENCES ControlSets(ControlSet_ID)
);

CREATE TABLE NIST_ControlsCCPs (
                                   NIST_ControlCCP_ID INTEGER PRIMARY KEY,
                                   NIST_Control_ID INTEGER NOT NULL,
                                   CCP_ID INTEGER NOT NULL,
                                   UNIQUE (NIST_Control_ID, CCP_ID) ON CONFLICT IGNORE,
                                   FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                   FOREIGN KEY (CCP_ID) REFERENCES CommonControlPackages(CCP_ID)
);

CREATE TABLE NIST_ControlsIntegrityLevels (
                                              NIST_ControlIntegrityLevel_ID INTEGER PRIMARY KEY,
                                              NIST_Control_ID INTEGER NOT NULL,
                                              IntegrityLevel_ID INTEGER NOT NULL,
                                              NSS_Systems_Only NVARCHAR (10) NOT NULL,
                                              UNIQUE (NIST_Control_ID, IntegrityLevel_ID) ON CONFLICT IGNORE,
                                              FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                              FOREIGN KEY (IntegrityLevel_ID) REFERENCES IntegrityLevels(IntegrityLevel_ID)
);

CREATE TABLE NIST_ControlsOverlays (
                                       NIST_ControlOverlay_ID INTEGER PRIMARY KEY,
                                       NIST_Control_ID INTEGER NOT NULL,
                                       Overlay_ID INTEGER NOT NULL,
                                       UNIQUE (NIST_Control_ID, Overlay_ID) ON CONFLICT IGNORE,
                                       FOREIGN KEY (NIST_Control_ID) REFERENCES NIST_Controls(NIST_Control_ID),
                                       FOREIGN KEY (Overlay_ID) REFERENCES Overlays(Overlay_ID)
);

CREATE TABLE Organizations (
                               Organization_ID INTEGER PRIMARY KEY,
                               OrganizationName NVARCHAR (100) NOT NULL,
                               OrganizationAcronym NVARCHAR (100)
);

CREATE TABLE Overlays (
                          Overlay_ID INTEGER PRIMARY KEY,
                          OverlayName NVARCHAR (25) NOT NULL
);

CREATE TABLE PIT_Determination (
                                   PIT_Determination_ID INTEGER PRIMARY KEY,
                                   ReceivesInfo NVARCHAR (5) NOT NULL,
                                   TransmitsInfo NVARCHAR (5) NOT NULL,
                                   ProcessesInfo NVARCHAR (5) NOT NULL,
                                   StoresInfo NVARCHAR (5) NOT NULL,
                                   DisplaysInfo NVARCHAR (5) NOT NULL,
                                   EmbeddedInSpecialPurpose NVARCHAR (5) NOT NULL,
                                   IsDedicatedSpecialPurposeSystem NVARCHAR (5) NOT NULL,
                                   IsEssentialSpecialPurposeSystem NVARCHAR (5) NOT NULL,
                                   PerformsGeneralServices NVARCHAR (5) NOT NULL,
                                   IsFireControlOrTargetingSystem NVARCHAR (5),
                                   IsMissileSystem NVARCHAR (5),
                                   IsGunSystem NVARCHAR (5),
                                   IsTorpedo NVARCHAR (5),
                                   IsActiveElectronicsWarfareSystem NVARCHAR (5),
                                   IsLauncher NVARCHAR (5),
                                   IsDecoySystem NVARCHAR (5),
                                   IsVehicle NVARCHAR (5),
                                   IsTank NVARCHAR (5),
                                   IsArtillery NVARCHAR (5),
                                   IsManDeployableWeapon NVARCHAR (5),
                                   IsFlightSimulator NVARCHAR (5),
                                   IsBridgeSimulator NVARCHAR (5),
                                   IsClassroomNetworkOther NVARCHAR (5),
                                   IsEmbeddedTacticalTrainerAndSimulator NVARCHAR (5),
                                   IsBuiltInTestOrMaintenanceEquipment NVARCHAR (5),
                                   IsPortableTestOrMaintenanceEquipment NVARCHAR (5),
                                   IsBuiltInCalibrationEquipment NVARCHAR (5),
                                   IsPortableCalibrationEquipment NVARCHAR (5),
                                   IsRDTE_Network NVARCHAR (5),
                                   IsRDTE_SystemConnectedToRDTE_Network NVARCHAR (5),
                                   IsMedicalImaging NVARCHAR (5),
                                   IsMedicalMonitoring NVARCHAR (5),
                                   IsShipOrAircraftControlSystem NVARCHAR (5),
                                   IsIntegratedBridgeSystem NVARCHAR (5),
                                   IsElectronicChart NVARCHAR (5),
                                   IsGPS NVARCHAR (5),
                                   IsWSN NVARCHAR (5),
                                   IsInterialNavigation NVARCHAR (5),
                                   IsDeadReckoningDevice NVARCHAR (5),
                                   IsRealTimeAccessControlSystem NVARCHAR (5),
                                   IsHVAC_System NVARCHAR (5),
                                   IsRealTimeSecurityMonitoringSystem NVARCHAR (5),
                                   IsSCADA_System NVARCHAR (5),
                                   IsUtilitiesEngineeringManagement NVARCHAR (5),
                                   IsMeteringAndControl NVARCHAR (5),
                                   IsMechanicalMonitoring NVARCHAR (5),
                                   IsDamageControlMonitoring NVARCHAR (5),
                                   IsVoiceCommunicationSystem NVARCHAR (5),
                                   IsSatelliteCommunitcationSystem NVARCHAR (5),
                                   IsTacticalCommunication NVARCHAR (5),
                                   IsISDN_VTC_System NVARCHAR (5),
                                   IsInterrigatorOrTransponder NVARCHAR (5),
                                   IsCommandAndControlOfForces NVARCHAR (5),
                                   IsCombatIdentificationAndClassification NVARCHAR (5),
                                   IsRealTimeTrackManagement NVARCHAR (5),
                                   IsForceOrders NVARCHAR (5),
                                   IsTroopMovement NVARCHAR (5),
                                   IsEngagementCoordination NVARCHAR (5),
                                   IsWarFightingDisplay NVARCHAR (5),
                                   IsInputOutputConsole NVARCHAR (5),
                                   IsRADAR_System NVARCHAR (5),
                                   IsActiveOrPassiveAcousticSensor NVARCHAR (5),
                                   IsVisualOrImagingSensor NVARCHAR (5),
                                   IsRemoteVehicle NVARCHAR (5),
                                   IsPassiveElectronicWarfareSensor NVARCHAR (5),
                                   IsISR_Sensor NVARCHAR (5),
                                   IsNationalSensor NVARCHAR (5),
                                   IsNavigationAndControlSensor NVARCHAR (5),
                                   IsElectronicWarfare NVARCHAR (5),
                                   IsIntelligence NVARCHAR (5),
                                   IsEnvironmental NVARCHAR (5),
                                   IsAcoustic NVARCHAR (5),
                                   IsGeographic NVARCHAR (5),
                                   IsTacticalDecisionAid NVARCHAR (5),
                                   OtherSystemTypeDescription NVARCHAR (100)
);

CREATE TABLE PortsProtocols (
                                PortsProtocols_ID INTEGER PRIMARY KEY,
                                Port INTEGER NOT NULL,
                                Protocol NVARCHAR (25) NOT NULL,
                                UNIQUE (Port, Protocol) ON CONFLICT IGNORE
);


CREATE TABLE PortServices (
                              PortService_ID INTEGER PRIMARY KEY,
                              PortServiceName NVARCHAR (100) NOT NULL UNIQUE ON CONFLICT IGNORE,
                              PortServiceAcronym NVARCHAR (50),
                              PortsProtocols_ID INTEGER NOT NULL,
                              UNIQUE (PortServiceName, PortsProtocols_ID) ON CONFLICT IGNORE,
                              FOREIGN KEY (PortsProtocols_ID) REFERENCES PortsProtocols(PortsProtocols_ID)
);

CREATE TABLE PortServicesSoftware (
                                      PortServiceSoftware_ID INTEGER PRIMARY KEY,
                                      PortService_ID INTEGER NOT NULL,
                                      Software_ID INTEGER NOT NULL,
                                      UNIQUE (PortService_ID, Software_ID) ON CONFLICT IGNORE,
                                      FOREIGN KEY (PortService_ID) REFERENCES PortServices(PortService_ID),
                                      FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID)
);


CREATE TABLE RelatedDocuments (
                                  RelatedDocument_ID INTEGER PRIMARY KEY,
                                  RelatedDocumentName NVARCHAR (50) NOT NULL,
                                  RelationshipDescription NVARCHAR (100) NOT NULL
);

CREATE TABLE RelatedTesting (
                                RelatedTesting_ID INTEGER PRIMARY KEY,
                                TestTitle NVARCHAR (50) NOT NULL,
                                DateConducted DATE NOT NULL,
                                RelatedSystemTested NVARCHAR (50) NOT NULL,
                                ResponsibleOrganization NVARCHAR (100) NOT NULL,
                                TestingImpact NVARCHAR (500) NOT NULL
);

CREATE TABLE ResponsibilityRoles (
                                     Role_ID INTEGER PRIMARY KEY,
                                     RoleTitle NVARCHAR (25) NOT NULL
);

CREATE TABLE SecurityAssessmentProcedures (
                      SecurityAssessmentProcedure_ID INTEGER PRIMARY KEY,
                      Scope NVARCHAR (50) NOT NULL,
                      TestConfiguration NVARCHAR (2000) NOT NULL,
                      LogisticsSupport NVARCHAR (1000) NOT NULL,
                      Security NVARCHAR (1000) NOT NULL,
                      Group_ID INTEGER NOT NULL ,
                      FOREIGN KEY (Group_ID) REFERENCES Groups(Group_ID)
);

CREATE TABLE SecurityAssessmentProcedureAdditionalTestConsiderations (
                                                  SecurityAssessmentProcedureAdditionalTestConsiderations_ID INTEGER PRIMARY KEY,
                                                  SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                                  AdditionalTestConsideration_ID INTEGER NOT NULL,
                                                  UNIQUE (SecurityAssessmentProcedure_ID, AdditionalTestConsideration_ID) ON CONFLICT IGNORE,
                                                  FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                                  FOREIGN KEY (AdditionalTestConsideration_ID) REFERENCES AdditionalTestConsiderations(AdditionalTestConsideration_ID)
);

CREATE TABLE SecurityAssessmentProcedureCustomTestCases (
                                     SecurityAssessmentProcedureCustomTestCase_ID INTEGER PRIMARY KEY,
                                     SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                     CustomTestCase_ID INTEGER NOT NULL,
                                     UNIQUE (SecurityAssessmentProcedure_ID, CustomTestCase_ID) ON CONFLICT IGNORE,
                                     FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                     FOREIGN KEY (CustomTestCase_ID) REFERENCES CustomTestCases(CustomTestCase_ID)
);

CREATE TABLE SecurityAssessmentProcedureEntranceCriteria (
                                      SecurityAssessmentProcedureEntranceCriteria_ID INTEGER PRIMARY KEY,
                                      SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                      EntranceCriteria_ID INTEGER NOT NULL,
                                      UNIQUE (SecurityAssessmentProcedure_ID, EntranceCriteria_ID) ON CONFLICT IGNORE,
                                      FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                      FOREIGN KEY (EntranceCriteria_ID) REFERENCES EntranceCriteria(EntranceCriteria_ID)
);

CREATE TABLE SecurityAssessmentProcedureExitCriteria (
                                  SecurityAssessmentProcedureExitCriteria_ID INTEGER PRIMARY KEY,
                                  SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                  ExitCriteria_ID INTEGER NOT NULL,
                                  UNIQUE (SecurityAssessmentProcedure_ID, ExitCriteria_ID) ON CONFLICT IGNORE,
                                  FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                  FOREIGN KEY (ExitCriteria_ID) REFERENCES ExitCriteria(ExitCriteria_ID)
);

CREATE TABLE SecurityAssessmentProcedureLimitiations (
                                  SecurityAssessmentProcedureLimitation_ID INTEGER PRIMARY KEY,
                                  SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                  Limitation_ID INTEGER NOT NULL,
                                  UNIQUE (SecurityAssessmentProcedure_ID, Limitation_ID) ON CONFLICT IGNORE,
                                  FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                  FOREIGN KEY (Limitation_ID) REFERENCES Limitations(Limitation_ID)
);

CREATE TABLE SecurityAssessmentProcedureRelatedDocuments (
                                      SecurityAssessmentProcedureRelatedDocuments_ID INTEGER PRIMARY KEY,
                                      SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                      RelatedDocument_ID INTEGER NOT NULL,
                                      UNIQUE (SecurityAssessmentProcedure_ID, RelatedDocument_ID) ON CONFLICT IGNORE,
                                      FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                      FOREIGN KEY (RelatedDocument_ID) REFERENCES RelatedDocuments(RelatedDocument_ID)
);

CREATE TABLE SecurityAssessmentProcedureRelatedTesting (
                                    SecurityAssessmentProcedureRelatedTesting_ID INTEGER PRIMARY KEY,
                                    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                    RelatedTesting_ID INTEGER NOT NULL,
                                    UNIQUE (SecurityAssessmentProcedure_ID, RelatedTesting_ID) ON CONFLICT IGNORE,
                                    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                    FOREIGN KEY (RelatedTesting_ID) REFERENCES RelatedTesting(RelatedTesting_ID)
);

CREATE TABLE SecurityAssessmentProcedureTestReferences (
                                    SecurityAssessmentProcedureTestReference_ID INTEGER PRIMARY KEY,
                                    SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                    TestReference_ID INTEGER NOT NULL,
                                    UNIQUE (SecurityAssessmentProcedure_ID, TestReference_ID) ON CONFLICT IGNORE,
                                    FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                    FOREIGN KEY (TestReference_ID) REFERENCES TestReferences(TestReference_ID)
);

CREATE TABLE SecurityAssessmentProcedureTestScheduleItems (
                                       SecurityAssessmentProcedureTestScheduleItem_ID INTEGER PRIMARY KEY,
                                       SecurityAssessmentProcedure_ID INTEGER NOT NULL,
                                       TestScheduleItem_ID INTEGER NOT NULL,
                                       UNIQUE (SecurityAssessmentProcedure_ID, TestScheduleItem_ID) ON CONFLICT IGNORE,
                                       FOREIGN KEY (SecurityAssessmentProcedure_ID) REFERENCES SecurityAssessmentProcedures(SecurityAssessmentProcedure_ID),
                                       FOREIGN KEY (TestScheduleItem_ID) REFERENCES TestScheduleItems(TestScheduleItem_ID)
);

CREATE TABLE SCAP_Scores (
                            SCAP_Score_ID INTEGER PRIMARY KEY,
                            Score INTEGER NOT NULL,
                            Hardware_ID INTEGER NOT NULL,
                            FindingSourceFile_ID INTEGER NOT NULL,
                            VulnerabilitySource_ID INTEGER NOT NULL,
                            ScanDate DATE NOT NULL,
                            UNIQUE (
                                    Hardware_ID,
                                    FindingSourceFile_ID,
                                    VulnerabilitySource_ID
                                ) ON CONFLICT IGNORE,
                            FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                            FOREIGN KEY (FindingSourceFile_ID) REFERENCES UniqueFindingsSourceFiles(FindingSourceFile_ID),
                            FOREIGN KEY (VulnerabilitySource_ID) REFERENCES VulnerabilitySources(VulnerabilitySource_ID)
);

CREATE TABLE Software (
                          Software_ID INTEGER PRIMARY KEY,
                          DiscoveredSoftwareName NVARCHAR (50) NOT NULL UNIQUE ON CONFLICT IGNORE,
                          DisplayedSoftwareName NVARCHAR (100) NOT NULL,
                          SoftwareAcronym NVARCHAR (25),
                          SoftwareVersion NVARCHAR (25),
                          Function NVARCHAR (500),
                          DADMS_ID NVARCHAR (25),
                          DADMS_Disposition NVARCHAR (25),
                          DADMS_LDA DATE,
                          HasCustomCode NVARCHAR (5),
                          IA_OrIA_Enabled NVARCHAR (5),
                          IsOS_OrFirmware NVARCHAR (5),
                          FAM_Accepted NVARCHAR (5),
                          ExternallyAuthorized NVARCHAR (5),
                          ReportInAccreditationGlobal NVARCHAR (5),
                          ApprovedForBaselineGlobal NVARCHAR (5),
                          BaselineApproverGlobal NVARCHAR (50),
                          Instance NVARCHAR (25)
);

CREATE TABLE Software_DADMS_Networks (
                                         Software_DADMS_Network_ID INTEGER PRIMARY KEY,
                                         Software_ID INTEGER NOT NULL,
                                         DADMS_Network_ID INTEGER NOT NULL,
                                         UNIQUE (Software_ID, DADMS_Network_ID) ON CONFLICT IGNORE,
                                         FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
                                         FOREIGN KEY (DADMS_Network_ID) REFERENCES DADMS_Networks(DADMS_Network_ID)
);

CREATE TABLE SoftwareContacts (
                                  SoftwareContact_ID INTEGER PRIMARY KEY,
                                  Software_ID INTEGER NOT NULL,
                                  Contact_ID INTEGER NOT NULL,
                                  UNIQUE (Software_ID, Contact_ID) ON CONFLICT IGNORE,
                                  FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
                                  FOREIGN KEY (Contact_ID) REFERENCES Contacts(Contact_ID)
);

CREATE TABLE SoftwareHardware (
                                  SoftwareHardware_ID INTEGER PRIMARY KEY,
                                  Software_ID INTEGER NOT NULL,
                                  Hardware_ID INTEGER NOT NULL,
                                  InstallDate DATE NOT NULL,
                                  ReportInAccreditation NVARCHAR (5),
                                  ApprovedForBaseline NVARCHAR (5),
                                  BaselineApprover NVARCHAR (50),
                                  UNIQUE (Software_ID, Hardware_ID) ON CONFLICT IGNORE,
                                  FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
                                  FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                  UNIQUE (Software_ID, Hardware_ID) ON CONFLICT IGNORE
);

CREATE TABLE StepOneQuestionnaire (
                                      StepOneQuestionnaire_ID INTEGER PRIMARY KEY,
                                      SystemDescription NVARCHAR (2000) NOT NULL,
                                      MissionDescription NVARCHAR (2000) NOT NULL,
                                      CONOPS_Statement NVARCHAR (2000) NOT NULL,
                                      IsTypeAuthorization NVARCHAR (5) NOT NULL,
                                      DITPR_DON_Number INTEGER NOT NULL,
                                      AuthorizationToConnectOrInterim_ATC_GrantedDate DATE NOT NULL,
                                      AuthorizationToConnectOrInterim_ATC_ExpirationDate DATE NOT NULL,
                                      AuthorizationToConnectOrInterim_ATC_CND_ServiceProvider NVARCHAR (25),
                                      SecurityPlanApprovalStatus NVARCHAR (25) NOT NULL,
                                      SecurityPlanApprovalDate DATE,
                                      AuthorizationStatus NVARCHAR (25) NOT NULL,
                                      HasAuthorizationDocumentation INTEGER NOT NULL,
                                      AssessmentCompletionDate DATE,
                                      AuthorizationDate DATE,
                                      AuthorizationTerminationDate DATE,
                                      MissionCriticality NVARCHAR (25) NOT NULL,
                                      GoverningMissionArea NVARCHAR (25) NOT NULL,
                                      DOD_Component NVARCHAR (25) NOT NULL,
                                      ACQ_Category NVARCHAR (25) NOT NULL,
                                      ACQ_Phase NVARCHAR (25) NOT NULL,
                                      SoftwareCategory NVARCHAR (25) NOT NULL,
                                      SystemOwnershipAndControl NVARCHAR (50) NOT NULL,
                                      OtherInformation NVARCHAR (2000),
                                      RMF_Activity NVARCHAR (25) NOT NULL,
                                      Accessibility_ID INTEGER NOT NULL,
                                      Overview_ID INTEGER NOT NULL,
                                      PortsProtocolsRegistrationNumber NVARCHAR (25) NOT NULL,
                                      AuthorizationInformation_ID INTEGER NOT NULL,
                                      IsSecurityReviewCompleted NVARCHAR (5) NOT NULL,
                                      SecurityReviewDate DATE,
                                      IsContingencyPlanRequired NVARCHAR (5) NOT NULL,
                                      ContingencyPlanTested NVARCHAR (5),
                                      ContingencyPlanTestDate DATE,
                                      IsPIA_Required NVARCHAR (5) NOT NULL,
                                      PIA_Date DATE,
                                      RegistrationType NVARCHAR (25) NOT NULL,
                                      InformationSystemOwner_ID INTEGER NOT NULL,
                                      SystemType NVARCHAR (100) NOT NULL,
                                      DVS_Site NVARCHAR (100),
                                      IsPrivacyActNoticeRequired NVARCHAR (5) NOT NULL,
                                      Is_eAuthenticationRiskAssessmentRequired NVARCHAR (5) NOT NULL,
                                      eAuthenticationRiskAssessmentDate DATE,
                                      IsReportableToFISMA NVARCHAR (5) NOT NULL,
                                      IsReportableToERS NVARCHAR (5) NOT NULL,
                                      SystemEnterpriseArchitecture NVARCHAR (2000) NOT NULL,
                                      AuthorizationToConnectOrInterim_ATC_ID INTEGER,
                                      NIST_ControlSet NVARCHAR (50) NOT NULL,
                                      FOREIGN KEY (InformationSystemOwner_ID) REFERENCES Contacts(Contact_ID)
);

CREATE TABLE StepOneQuestionnaireConnectivity (
                                                  StepOneQuestionnaireConnectivity_ID INTEGER PRIMARY KEY,
                                                  StepOneQuestionnaire_ID INTEGER NOT NULL,
                                                  Connectivity_ID INTEGER NOT NULL,
                                                  UNIQUE (StepOneQuestionnaire_ID, Connectivity_ID) ON CONFLICT IGNORE,
                                                  FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
                                                  FOREIGN KEY (Connectivity_ID) REFERENCES Connectivity(Connectivity_ID)
);

CREATE TABLE StepOneQuestionnaire_ExternalSecurityServices (
                                                               StepOneQuestionnaire_ID INTEGER NOT NULL,
                                                               ExternalSecurityServices_ID INTEGER NOT NULL,
                                                               FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
                                                               FOREIGN KEY (ExternalSecurityServices_ID) REFERENCES ExternalSecurityServices(ExternalSecurityServices_ID)
);

CREATE TABLE StepOneQuestionnaireEncryptionTechniques (
                                                          StepOneQuestionnaire_ExternalSecurityService INTEGER PRIMARY KEY,
                                                          StepOneQuestionnaire_ID INTEGER NOT NULL,
                                                          EncryptionTechnique_ID INTEGER NOT NULL,
                                                          UNIQUE (StepOneQuestionnaire_ID, EncryptionTechnique_ID) ON CONFLICT IGNORE,
                                                          FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
                                                          FOREIGN KEY (EncryptionTechnique_ID) REFERENCES EncryptionTechniques(EncryptionTechnique_ID)
);

CREATE TABLE StepOneQuestionnaireNetworkConnectionRules (
                                                            StepOneQuestionnaireNetworkConnectionRule_ID INTEGER PRIMARY KEY,
                                                            StepOneQuestionnaire_ID INTEGER NOT NULL,
                                                            NetworkConnectionRule_ID INTEGER NOT NULL,
                                                            UNIQUE (
                                                                    StepOneQuestionnaire_ID,
                                                                    NetworkConnectionRule_ID
                                                                ) ON CONFLICT IGNORE,
                                                            FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
                                                            FOREIGN KEY (NetworkConnectionRule_ID) REFERENCES NetworkConnectionRules(NetworkConnectionRule_ID)
);

CREATE TABLE StepOneQuestionnaireUserCategories (
                                                    StepOneQuestionnaireUserCategory_ID INTEGER PRIMARY KEY,
                                                    StepOneQuestionnaire_ID INTEGER NOT NULL,
                                                    UserCategory_ID INTEGER NOT NULL,
                                                    UNIQUE (StepOneQuestionnaire_ID, UserCategory_ID) ON CONFLICT IGNORE,
                                                    FOREIGN KEY (StepOneQuestionnaire_ID) REFERENCES StepOneQuestionnaire(StepOneQuestionnaire_ID),
                                                    FOREIGN KEY (UserCategory_ID) REFERENCES UserCategories(UserCategory_ID)
);

CREATE TABLE SystemCategorization (
                                      SystemCategorization_ID INTEGER PRIMARY KEY,
                                      SystemClassification NVARCHAR (25) NOT NULL,
                                      InformationClassification NVARCHAR (25) NOT NULL,
                                      InformationReleasability NVARCHAR (25) NOT NULL,
                                      HasGoverningPolicy NVARCHAR (5) NOT NULL,
                                      VaryingClearanceRequirements NVARCHAR (5) NOT NULL,
                                      ClearanceRequirementDescription NVARCHAR (500),
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

CREATE TABLE SystemCategorizationGoverningPolicies (
                                                       SystemCategorizationGoverningPolicy_ID INTEGER PRIMARY KEY,
                                                       SystemCategorization_ID INTEGER NOT NULL,
                                                       GoverningPolicy_ID INTEGER NOT NULL,
                                                       UNIQUE (SystemCategorization_ID, GoverningPolicy_ID) ON CONFLICT IGNORE,
                                                       FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
                                                       FOREIGN KEY (GoverningPolicy_ID) REFERENCES GoverningPolicies(GoverningPolicy_ID)
);

CREATE TABLE SystemCategorizationInformationTypes (
                                                      SystemCategorizationInformationType_ID INTEGER NOT NULL,
                                                      SystemCategorization_ID INTEGER NOT NULL,
                                                      Description NVARCHAR (500) NOT NULL,
                                                      InformationType_ID INTEGER NOT NULL,
                                                      ImpactAdjustment_ID INTEGER NOT NULL,
                                                      UNIQUE (SystemCategorization_ID, InformationType_ID) ON CONFLICT IGNORE,
                                                      FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
                                                      FOREIGN KEY (InformationType_ID) REFERENCES InformationTypes(InformationType_ID),
                                                      FOREIGN KEY (ImpactAdjustment_ID) REFERENCES ImpactAdjustments(ImpactAdjustment_ID)
);

CREATE TABLE SystemCategorizationInterconnectedSystems (
                                                           SystemCategorizationInterconnectedSystem_ID INTEGER PRIMARY KEY,
                                                           SystemCategorization_ID INTEGER NOT NULL,
                                                           InterconnectedSystem_ID INTEGER NOT NULL,
                                                           UNIQUE (SystemCategorization_ID, InterconnectedSystem_ID) ON CONFLICT IGNORE,
                                                           FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
                                                           FOREIGN KEY (InterconnectedSystem_ID) REFERENCES InterconnectedSystems(InterconnectedSystem_ID)
);

CREATE TABLE SystemCategorizationJointOrganizations (
                                                        SystemCategorizationJointOrganization_ID INTEGER PRIMARY KEY,
                                                        SystemCategorization_ID INTEGER NOT NULL,
                                                        JointOrganization_ID INTEGER NOT NULL,
                                                        UNIQUE (SystemCategorization_ID, JointOrganization_ID) ON CONFLICT IGNORE,
                                                        FOREIGN KEY (SystemCategorization_ID) REFERENCES SystemCategorization(SystemCategorization_ID),
                                                        FOREIGN KEY (JointOrganization_ID) REFERENCES JointAuthorizationOrganizations(JointOrganization_ID)
);

CREATE TABLE TestReferences (
                                TestReference_ID INTEGER PRIMARY KEY,
                                TestReferenceName NVARCHAR (100)
);

CREATE TABLE TestScheduleItems (
                                   TestScheduleItem_ID INTEGER PRIMARY KEY,
                                   TestEvent NVARCHAR (100),
                                   TestScheduleCategory NVARCHAR (25) NOT NULL,
                                   DurationInDays INTEGER NOT NULL
);

CREATE TABLE UniqueFindings (
                                UniqueFinding_ID INTEGER PRIMARY KEY,
                                InstanceIdentifier NVARCHAR(50),
                                ToolGeneratedOutput NVARCHAR,
                                Comments NVARCHAR,
                                FindingDetails NVARCHAR,
                                FirstDiscovered DATE NOT NULL,
                                LastObserved DATE NOT NULL,
                                DeltaAnalysisRequired NVARCHAR (5) NOT NULL,
                                FindingType_ID INTEGER NOT NULL,
                                FindingSourceFile_ID INTEGER NOT NULL,
                                Status NVARCHAR (25) NOT NULL,
                                Vulnerability_ID INTEGER NOT NULL,
                                Hardware_ID INTEGER,
                                Software_ID INTEGER,
                                SeverityOverride NVARCHAR (25),
                                SeverityOverrideJustification NVARCHAR (2000),
                                TechnologyArea NVARCHAR (100),
                                WebDB_Site NVARCHAR(500),
                                WebDB_Instance NVARCHAR(100),
                                Classification NVARCHAR (25),
                                CVSS_EnvironmentalScore NVARCHAR (5),
                                CVSS_EnvironmentalVector NVARCHAR (25),
                                MitigationOrCondition_ID INTEGER,
                                FOREIGN KEY (FindingType_ID) REFERENCES FindingTypes(FindingType_ID),
                                FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
                                FOREIGN KEY (Hardware_ID) REFERENCES Hardware(Hardware_ID),
                                FOREIGN KEY (Software_ID) REFERENCES Software(Software_ID),
                                FOREIGN KEY (FindingSourceFile_ID) REFERENCES UniqueFindingsSourceFiles(FindingSourceFile_ID),
                                FOREIGN KEY (MitigationOrCondition_ID) REFERENCES MitigationsOrConditions(MitigationOrCondition_ID),
                                UNIQUE (
                                        InstanceIdentifier,
                                        Hardware_ID,
                                        Software_ID,
                                        Vulnerability_ID
                                    ) ON CONFLICT IGNORE
);

CREATE TABLE UniqueFindingsSourceFiles (
                                           FindingSourceFile_ID INTEGER PRIMARY KEY,
                                           FindingSourceFileName NVARCHAR (500) NOT NULL UNIQUE ON CONFLICT IGNORE
);

CREATE TABLE UserCategories (
                                UserCategory_ID INTEGER PRIMARY KEY,
                                UserCategory NVARCHAR (25)
);

CREATE TABLE VulnerabilitiesCCIs (
                                     VulnerabilityCCI_ID INTEGER PRIMARY KEY,
                                     Vulnerability_ID INTEGER NOT NULL,
                                     CCI_ID INTEGER NOT NULL,
                                     UNIQUE (Vulnerability_ID, CCI_ID) ON CONFLICT IGNORE,
                                     FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
                                     FOREIGN KEY (CCI_ID) REFERENCES CCIs(CCI_ID)
);

CREATE TABLE Vulnerabilities_IA_Controls (
                                             Vulnerability_IA_Control_ID INTEGER PRIMARY KEY,
                                             Vulnerability_ID INTEGER NOT NULL,
                                             IA_Control_ID INTEGER NOT NULL,
                                             UNIQUE (Vulnerability_ID, IA_Control_ID) ON CONFLICT IGNORE,
                                             FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
                                             FOREIGN KEY (IA_Control_ID) REFERENCES IA_Controls(IA_Control_ID)
);

CREATE TABLE Vulnerabilities (
                                 Vulnerability_ID INTEGER PRIMARY KEY,
                                 UniqueVulnerabilityIdentifier NVARCHAR (50) UNIQUE ON CONFLICT IGNORE NOT NULL,
                                 VulnerabilityGroup_ID NVARCHAR (25),
                                 VulnerabilityGroupTitle NVARCHAR (100),
                                 SecondaryVulnerabilityIdentifier NVARCHAR (25),
                                 VulnerabilityFamilyOrClass NVARCHAR (100),
                                 VulnerabilityVersion NVARCHAR (25),
                                 VulnerabilityRelease NVARCHAR (25),
                                 VulnerabilityTitle NVARCHAR (100) NOT NULL,
                                 VulnerabilityDescription NVARCHAR,
                                 RiskStatement NVARCHAR,
                                 FixText NVARCHAR,
                                 PublishedDate DATE,
                                 ModifiedDate DATE,
                                 FixPublishedDate DATE,
                                 RawRisk NVARCHAR (25) NOT NULL,
                                 CVSS_BaseScore NVARCHAR (5),
                                 CVSS_BaseVector NVARCHAR (25),
                                 CVSS_TemporalScore NVARCHAR (5),
                                 CVSS_TemporalVector NVARCHAR (25),
                                 CheckContent NVARCHAR (2000),
                                 FalsePositives NVARCHAR (2000),
                                 FalseNegatives NVARCHAR (2000),
                                 Documentable NVARCHAR (5),
                                 Mitigations NVARCHAR (2000),
                                 MitigationControl NVARCHAR (2000),
                                 PotentialImpacts NVARCHAR (2000),
                                 ThirdPartyTools NVARCHAR (500),
                                 SecurityOverrideGuidance NVARCHAR (2000),
                                 Overflow NVARCHAR (2000),
                                 IsActive NVARCHAR (5)
);

CREATE TABLE VulnerabilitiesRoleResponsibilities (
                                                     VulnerabilityRoleResponsibility_ID INTEGER PRIMARY KEY,
                                                     Vulnerability_ID INTEGER NOT NULL,
                                                     Role_ID INTEGER NOT NULL,
                                                     UNIQUE (Vulnerability_ID, Role_ID) ON CONFLICT IGNORE,
                                                     FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
                                                     FOREIGN KEY (Role_ID) REFERENCES ResponsibilityRoles(Role_ID)
);

CREATE TABLE VulnerabilitiesVulnerabilitySources (
                                                     VulnerabilityVulnerabilitySource_ID INTEGER PRIMARY KEY,
                                                     Vulnerability_ID INTEGER NOT NULL,
                                                     VulnerabilitySource_ID INTEGER NOT NULL,
                                                     UNIQUE (Vulnerability_ID, VulnerabilitySource_ID) ON CONFLICT IGNORE,
                                                     FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
                                                     FOREIGN KEY (VulnerabilitySource_ID) REFERENCES VulnerabilitySources(VulnerabilitySource_ID)
);

CREATE TABLE VulnerabilitiesVulnerabilityReferences (
                                                        VulnerabilityVulnerabilityReference_ID INTEGER PRIMARY KEY,
                                                        Vulnerability_ID INTEGER NOT NULL,
                                                        Reference_ID INTEGER NOT NULL,
                                                        UNIQUE (Vulnerability_ID, Reference_ID) ON CONFLICT IGNORE,
                                                        FOREIGN KEY (Vulnerability_ID) REFERENCES Vulnerabilities(Vulnerability_ID),
                                                        FOREIGN KEY (Reference_ID) REFERENCES VulnerabilityReferences(Reference_ID)
);

CREATE TABLE VulnerabilityReferences (
                                         Reference_ID INTEGER PRIMARY KEY,
                                         Reference NVARCHAR (50),
                                         ReferenceType NVARCHAR (10),
                                         UNIQUE (Reference, ReferenceType) ON CONFLICT IGNORE
);

CREATE TABLE VulnerabilitySources (
                                      VulnerabilitySource_ID INTEGER PRIMARY KEY,
                                      SourceName NVARCHAR (100) NOT NULL,
                                      SourceSecondaryIdentifier NVARCHAR (100),
                                      VulnerabilitySourceFileName NVARCHAR (500),
                                      SourceDescription NVARCHAR (2000),
                                      SourceVersion NVARCHAR (25) NOT NULL,
                                      SourceRelease NVARCHAR (25) NOT NULL,
                                      UNIQUE (SourceName, SourceVersion, SourceRelease) ON CONFLICT IGNORE
);

CREATE TABLE Waivers (
                         Waiver_ID INTEGER PRIMARY KEY,
                         WaiverName NVARCHAR (100) NOT NULL
);

CREATE TABLE WindowsDomainUserSettings (
                                           WindowsDomainUserSettings_ID INTEGER PRIMARY KEY,
                                           WindowsDomainUserIsDisabled NVARCHAR (5) NOT NULL,
                                           WindowsDomainUserIsDisabledAutomatically NVARCHAR (5) NOT NULL,
                                           WindowsDomainUserCantChangePW NVARCHAR (5) NOT NULL,
                                           WindowsDomainUserNeverChangedPW NVARCHAR (5) NOT NULL,
                                           WindowsDomainUserNeverLoggedOn NVARCHAR (5) NOT NULL,
                                           WindowsDomainUserPW_NeverExpires NVARCHAR (5) NOT NULL
);

CREATE TABLE WindowsLocalUserSettings (
                                          WindowsLocalUserSettings_ID INTEGER PRIMARY KEY,
                                          WindowsLocalUserIsDisabled NVARCHAR (5) NOT NULL,
                                          WindowsLocalUserIsDisabledAutomatically NVARCHAR (5) NOT NULL,
                                          WindowsLocalUserCantChangePW NVARCHAR (5) NOT NULL,
                                          WindowsLocalUserNeverChangedPW NVARCHAR (5) NOT NULL,
                                          WindowsLocalUserNeverLoggedOn NVARCHAR (5) NOT NULL,
                                          WindowsLocalUserPW_NeverExpires NVARCHAR (5) NOT NULL
);

CREATE TABLE RequiredReports (
                                 RequiredReport_ID INTEGER PRIMARY KEY,
                                 DisplayedReportName NVARCHAR (50) NOT NULL,
                                 ReportType NVARCHAR (10) NOT NULL,
                                 IsReportEnabled NVARCHAR (5) NOT NULL,
                                 IsReportSelected NVARCHAR (5) NOT NULL,
                                 ReportCategory NVARCHAR (50) NOT NULL
);

CREATE TABLE ReportFindingTypes (
                                    RequiredReport_ID INTEGER NOT NULL,
                                    FindingType_ID INTEGER NOT NULL,
                                    UserName NVARCHAR (50) NOT NULL,
                                    FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID),
                                    FOREIGN KEY (FindingType_ID) REFERENCES FindingTypes(FindingType_ID),
                                    UNIQUE (RequiredReport_ID, FindingType_ID, UserName) ON CONFLICT IGNORE
);

CREATE TABLE ReportSeverities (
                                  RequiredReport_ID INTEGER NOT NULL,
                                  UserName NVARCHAR (50) NOT NULL,
                                  ReportCatI INTEGER NOT NULL,
                                  ReportCatII INTEGER NOT NULL,
                                  ReportCatIII INTEGER NOT NULL,
                                  ReportCatIV INTEGER NOT NULL,
                                  FOREIGN KEY (RequiredReport_ID) REFERENCES RequiredReports(RequiredReport_ID),
                                  UNIQUE (RequiredReport_ID, UserName) ON CONFLICT IGNORE
);

INSERT INTO
    Groups
VALUES
(
    NULL,
    'All',
    NULL,
    1,
    'False',
    NULL,
    'False',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    'False',
    NULL,
    'False',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
);

INSERT INTO
    FindingTypes
VALUES
(NULL, 'ACAS');

INSERT INTO
    FindingTypes
VALUES
(NULL, 'Fortify');

INSERT INTO
    FindingTypes
VALUES
(NULL, 'CKL');

INSERT INTO
    FindingTypes
VALUES
(NULL, 'XCCDF');

INSERT INTO
    FindingTypes
VALUES
(NULL, 'WASSP');

INSERT INTO
    AvailabilityLevels
VALUES
(NULL, 'High');

INSERT INTO
    AvailabilityLevels
VALUES
(NULL, 'Moderate');

INSERT INTO
    AvailabilityLevels
VALUES
(NULL, 'Low');

INSERT INTO
    ConfidentialityLevels
VALUES
(NULL, 'High');

INSERT INTO
    ConfidentialityLevels
VALUES
(NULL, 'Moderate');

INSERT INTO
    ConfidentialityLevels
VALUES
(NULL, 'Low');

INSERT INTO
    IntegrityLevels
VALUES
(NULL, 'High');

INSERT INTO
    IntegrityLevels
VALUES
(NULL, 'Moderate');

INSERT INTO
    IntegrityLevels
VALUES
(NULL, 'Low');

INSERT INTO
    Overlays
VALUES
(NULL, 'Classified');

INSERT INTO
    Overlays
VALUES
(NULL, 'CDS Access');

INSERT INTO
    Overlays
VALUES
(NULL, 'CDS Multilevel');

INSERT INTO
    Overlays
VALUES
(NULL, 'CDS Transfer');

INSERT INTO
    Overlays
VALUES
(NULL, 'Intelligence A');

INSERT INTO
    Overlays
VALUES
(NULL, 'Intelligence B');

INSERT INTO
    Overlays
VALUES
(NULL, 'Intelligence C');

INSERT INTO
    Overlays
VALUES
(NULL, 'NC3');

INSERT INTO
    Overlays
VALUES
(NULL, 'Privacy Low');

INSERT INTO
    Overlays
VALUES
(NULL, 'Privacy High');

INSERT INTO
    Overlays
VALUES
(NULL, 'Privacy Moderate');

INSERT INTO
    Overlays
VALUES
(NULL, 'Privacy PHI');

INSERT INTO
    Overlays
VALUES
(NULL, 'Space');

INSERT INTO
    LifecycleStatuses
VALUES
(NULL, 'Uncategorized');

INSERT INTO
    LifecycleStatuses
VALUES
(NULL, 'Pending');

INSERT INTO
    LifecycleStatuses
VALUES
(NULL, 'Active');

INSERT INTO
    LifecycleStatuses
VALUES
(NULL, 'Decommissioned');

INSERT INTO
    RequiredReports
VALUES
(
    NULL,
    'Excel Summary',
    'Excel',
    'True',
    'True',
    'Vulnerability Management'
);

INSERT INTO
    RequiredReports
VALUES
(
    NULL,
    'POA&M / RAR',
    'Excel',
    'True',
    'True',
    'Vulnerability Management'
);

INSERT INTO
    RequiredReports
VALUES
(
    NULL,
    'SCAP & STIG Discrepancies',
    'Excel',
    'True',
    'True',
    'Vulnerability Management'
);

INSERT INTO
    RequiredReports
VALUES
(
    NULL,
    'Vulnerability Deep Dive (By Finding Type)',
    'Excel',
    'True',
    'True',
    'Vulnerability Management'
);

INSERT INTO
    RequiredReports
VALUES
(
    NULL,
    'Test Plan',
    'Excel',
    'True',
    'True',
    'Vulnerability Management'
);

INSERT INTO
    RequiredReports
VALUES
(
    NULL,
    'OS Breakdown',
    'Excel',
    'False',
    'False',
    'Configuration Management'
);

INSERT INTO
    RequiredReports
VALUES
(
    NULL,
    'User Breakdown',
    'Excel',
    'False',
    'False',
    'Configuration Management'
);

INSERT INTO
    RequiredReports
VALUES
(
    NULL,
    'PDF Summary',
    'PDF',
    'False',
    'False',
    'Vulnerability Management'
);