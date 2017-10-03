using System.Data.Entity;
using System.Data.SQLite;
using Vulnerator.Model.Entity;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseContext : DbContext
    {
        public virtual DbSet<Accessibility> Accessibilities { get; set; }
        public virtual DbSet<Accreditation> Accreditations { get; set; }
        public virtual DbSet<AccreditationsNistControl> AccreditationsNistControls { get; set; }
        public virtual DbSet<AdditionalTestConsideration> AdditionalTestConsiderations { get; set; }
        public virtual DbSet<ATC_IATC> ATC_IATC { get; set; }
        public virtual DbSet<ATC_IATC_PendingItems> ATC_IATC_PendingItems { get; set; }
        public virtual DbSet<AuthorizationCondition> AuthorizationConditions { get; set; }
        public virtual DbSet<AuthorizationInformation> AuthorizationInformations { get; set; }
        public virtual DbSet<AvailabilityLevel> AvailabilityLevels { get; set; }
        public virtual DbSet<Building> Buildings { get; set; }
        public virtual DbSet<Business> Businesses { get; set; }
        public virtual DbSet<CalibrationSystem> CalibrationSystems { get; set; }
        public virtual DbSet<Category> Categories { get; set; }
        public virtual DbSet<CCI> CCIs { get; set; }
        public virtual DbSet<Certification> Certifications { get; set; }
        public virtual DbSet<CombatSystem> CombatSystems { get; set; }
        public virtual DbSet<CommonControlPackage> CommonControlPackages { get; set; }
        public virtual DbSet<CommunicationSystem> CommunicationSystems { get; set; }
        public virtual DbSet<ConfidentialityLevel> ConfidentialityLevels { get; set; }
        public virtual DbSet<ConnectedSystem> ConnectedSystems { get; set; }
        public virtual DbSet<Connection> Connections { get; set; }
        public virtual DbSet<Connectivity> Connectivities { get; set; }
        public virtual DbSet<Contact> Contacts { get; set; }
        public virtual DbSet<ControlApplicabilityAssessment> ControlApplicabilityAssessments { get; set; }
        public virtual DbSet<ControlSelection> ControlSelections { get; set; }
        public virtual DbSet<ControlSet> ControlSets { get; set; }
        public virtual DbSet<CustomTestCas> CustomTestCases { get; set; }
        public virtual DbSet<DADMS_Networks> DADMS_Networks { get; set; }
        public virtual DbSet<DiagnosticTestingSystem> DiagnosticTestingSystems { get; set; }
        public virtual DbSet<DitprDonNumber> DitprDonNumbers { get; set; }
        public virtual DbSet<EncryptionTechnique> EncryptionTechniques { get; set; }
        public virtual DbSet<EntranceCriteria> EntranceCriterias { get; set; }
        public virtual DbSet<EnumeratedWindowsGroup> EnumeratedWindowsGroups { get; set; }
        public virtual DbSet<EnumeratedWindowsUser> EnumeratedWindowsUsers { get; set; }
        public virtual DbSet<ExitCriteria> ExitCriterias { get; set; }
        public virtual DbSet<ExternalSecurityService> ExternalSecurityServices { get; set; }
        public virtual DbSet<FindingType> FindingTypes { get; set; }
        public virtual DbSet<FISMA> FISMAs { get; set; }
        public virtual DbSet<GoverningPolicy> GoverningPolicies { get; set; }
        public virtual DbSet<Group> Groups { get; set; }
        public virtual DbSet<Hardware> Hardwares { get; set; }
        public virtual DbSet<Hardware_PPS> Hardware_PPS { get; set; }
        public virtual DbSet<IA_Controls> IA_Controls { get; set; }
        public virtual DbSet<IATA_Standards> IATA_Standards { get; set; }
        public virtual DbSet<ImpactAdjustment> ImpactAdjustments { get; set; }
        public virtual DbSet<InformationType> InformationTypes { get; set; }
        public virtual DbSet<IntegrityLevel> IntegrityLevels { get; set; }
        public virtual DbSet<InterconnectedSystem> InterconnectedSystems { get; set; }
        public virtual DbSet<IP_Addresses> IP_Addresses { get; set; }
        public virtual DbSet<JointAuthorizationOrganization> JointAuthorizationOrganizations { get; set; }
        public virtual DbSet<LifecycleStatus> LifecycleStatuses { get; set; }
        public virtual DbSet<Limitation> Limitations { get; set; }
        public virtual DbSet<Location> Locations { get; set; }
        public virtual DbSet<MAC_Addresses> MAC_Addresses { get; set; }
        public virtual DbSet<MedicalTechnology> MedicalTechnologies { get; set; }
        public virtual DbSet<MissionArea> MissionAreas { get; set; }
        public virtual DbSet<MitigationsOrCondition> MitigationsOrConditions { get; set; }
        public virtual DbSet<NavigationTransportationSystem> NavigationTransportationSystems { get; set; }
        public virtual DbSet<NetworkConnectionRule> NetworkConnectionRules { get; set; }
        public virtual DbSet<NistControl> NistControls { get; set; }
        public virtual DbSet<NssQuestionnaire> NssQuestionnaires { get; set; }
        public virtual DbSet<Organization> Organizations { get; set; }
        public virtual DbSet<Overlay> Overlays { get; set; }
        public virtual DbSet<Overview> Overviews { get; set; }
        public virtual DbSet<PIT_Determination> PIT_Determination { get; set; }
        public virtual DbSet<PP> PPS { get; set; }
        public virtual DbSet<RelatedDocument> RelatedDocuments { get; set; }
        public virtual DbSet<RelatedTesting> RelatedTestings { get; set; }
        public virtual DbSet<ReportCategory> ReportCategories { get; set; }
        public virtual DbSet<RequiredReport> RequiredReports { get; set; }
        public virtual DbSet<ResearchWeaponsSystem> ResearchWeaponsSystems { get; set; }
        public virtual DbSet<ResponsibilityRole> ResponsibilityRoles { get; set; }
        public virtual DbSet<SAP> SAPs { get; set; }
        public virtual DbSet<ScapScore> ScapScores { get; set; }
        public virtual DbSet<Sensor> Sensors { get; set; }
        public virtual DbSet<Software> Softwares { get; set; }
        public virtual DbSet<SpecialPurposeConsole> SpecialPurposeConsoles { get; set; }
        public virtual DbSet<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
        public virtual DbSet<SystemCategorization> SystemCategorizations { get; set; }
        public virtual DbSet<SystemType> SystemTypes { get; set; }
        public virtual DbSet<TacticalSupportDatabas> TacticalSupportDatabases { get; set; }
        public virtual DbSet<TestReference> TestReferences { get; set; }
        public virtual DbSet<TestScheduleItem> TestScheduleItems { get; set; }
        public virtual DbSet<Title> Titles { get; set; }
        public virtual DbSet<TrainingSimulationSystem> TrainingSimulationSystems { get; set; }
        public virtual DbSet<UniqueFinding> UniqueFindings { get; set; }
        public virtual DbSet<UniqueFindingsSourceFile> UniqueFindingsSourceFiles { get; set; }
        public virtual DbSet<UserCategory> UserCategories { get; set; }
        public virtual DbSet<UtilityDistribution> UtilityDistributions { get; set; }
        public virtual DbSet<Vulnerability> Vulnerabilities { get; set; }
        public virtual DbSet<VulnerabilityReference> VulnerabilityReferences { get; set; }
        public virtual DbSet<VulnerabilitySource> VulnerabilitySources { get; set; }
        public virtual DbSet<Waiver> Waivers { get; set; }
        public virtual DbSet<WeaponsSystem> WeaponsSystems { get; set; }
        public virtual DbSet<WindowsDomainUserSetting> WindowsDomainUserSettings { get; set; }
        public virtual DbSet<WindowsLocalUserSetting> WindowsLocalUserSettings { get; set; }
        public virtual DbSet<AccreditationsWaiver> AccreditationsWaivers { get; set; }
        public virtual DbSet<HardwareLocation> HardwareLocations { get; set; }
        public virtual DbSet<InformationSystemOwner> InformationSystemOwners { get; set; }
        public virtual DbSet<NistControlsAvailabilityLevel> NistControlsAvailabilityLevels { get; set; }
        public virtual DbSet<NistControlsCAA> NistControlsCAAs { get; set; }
        public virtual DbSet<NistControlsCCI> NistControlsCCIs { get; set; }
        public virtual DbSet<NistControlsConfidentialityLevel> NistControlsConfidentialityLevels { get; set; }
        public virtual DbSet<NistControlsIntegrityLevel> NistControlsIntegrityLevels { get; set; }
        public virtual DbSet<SoftwareHardware> SoftwareHardwares { get; set; }
        public virtual DbSet<SystemCategorizationInformationType> SystemCategorizationInformationTypes { get; set; }

        public DatabaseContext() : base(DatabaseBuilder.sqliteConnection, false)
        { }

        private static string ConnectionString()
        {
            SQLiteConnectionStringBuilder sqliteConnectionStringBuilder = new SQLiteConnectionStringBuilder()
            {  DataSource = Properties.Settings.Default.Database.Split(';')[0] };
            return sqliteConnectionStringBuilder.ToString();
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Accreditation>()
                .Property(e => e.CybersafeGrade)
                .IsFixedLength()
                .IsUnicode(false);

            modelBuilder.Entity<Accreditation>()
                .Property(e => e.RDTE_Zone)
                .IsFixedLength()
                .IsUnicode(false);

            modelBuilder.Entity<Accreditation>()
                .HasMany(e => e.AccreditationsNistControls)
                .WithRequired(e => e.Accreditation)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Accreditation>()
                .HasMany(e => e.AccreditationsWaivers)
                .WithRequired(e => e.Accreditation)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<AdditionalTestConsideration>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.AdditionalTestConsiderations)
                .Map(m => m.ToTable("SAP_AdditionalTestConsiderations").MapLeftKey("Consideration_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<ATC_IATC_PendingItems>()
                .HasMany(e => e.ATC_IATC)
                .WithMany(e => e.ATC_IATC_PendingItems)
                .Map(m => m.ToTable("ATC_IATC_ATC_IATC_PendingItems").MapLeftKey("ATC_IATC_PendingItem_ID").MapRightKey("ATC_ID"));

            modelBuilder.Entity<AuthorizationCondition>()
                .HasMany(e => e.AuthorizationInformations)
                .WithMany(e => e.AuthorizationConditions)
                .Map(m => m.ToTable("AuthorizationInformation_AuthorizationConditions").MapLeftKey("AuthorizationCondition_ID").MapRightKey("AuthorizationInformation_ID"));

            modelBuilder.Entity<AvailabilityLevel>()
                .HasMany(e => e.Accreditations)
                .WithRequired(e => e.AvailabilityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<AvailabilityLevel>()
                .HasMany(e => e.NistControlsAvailabilityLevels)
                .WithRequired(e => e.AvailabilityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Category>()
                .HasMany(e => e.TestScheduleItems)
                .WithRequired(e => e.Category)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<CCI>()
                .HasMany(e => e.NistControlsCCIs)
                .WithRequired(e => e.CCI)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<CCI>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.CCIs)
                .Map(m => m.ToTable("VulnerabilitiesCCIs").MapLeftKey("CCI_ID").MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<CommonControlPackage>()
                .HasMany(e => e.NistControls)
                .WithMany(e => e.CommonControlPackages)
                .Map(m => m.ToTable("NistControlsCCPs").MapLeftKey("CCP_ID").MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<ConfidentialityLevel>()
                .HasMany(e => e.Accreditations)
                .WithRequired(e => e.ConfidentialityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<ConfidentialityLevel>()
                .HasMany(e => e.NistControlsConfidentialityLevels)
                .WithRequired(e => e.ConfidentialityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<ConnectedSystem>()
                .HasMany(e => e.Accreditations)
                .WithMany(e => e.ConnectedSystems)
                .Map(m => m.ToTable("AccreditationsConnectedSystems").MapLeftKey("ConnectedSystem_ID").MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<Connection>()
                .HasMany(e => e.Accreditations)
                .WithMany(e => e.Connections)
                .Map(m => m.ToTable("AccreditationsConnections").MapLeftKey("Connection_ID").MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<Connectivity>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.Connectivities)
                .Map(m => m.ToTable("StepOneQuestionnaire_Connectivity").MapLeftKey("Connectivity_ID").MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.InformationSystemOwners)
                .WithRequired(e => e.Contact)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Accreditations)
                .WithMany(e => e.Contacts)
                .Map(m => m.ToTable("AccreditationsContacts").MapLeftKey("Contact_ID").MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Groups)
                .WithMany(e => e.Contacts)
                .Map(m => m.ToTable("GroupsContacts").MapLeftKey("Contact_ID").MapRightKey("Group_ID"));

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.Contacts)
                .Map(m => m.ToTable("HardwareContacts").MapLeftKey("Contact_ID").MapRightKey("Hardware_ID"));

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Certifications)
                .WithMany(e => e.Contacts)
                .Map(m => m.ToTable("ContactsCertifications").MapLeftKey("Contact_ID").MapRightKey("Certification_ID"));

            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Softwares)
                .WithMany(e => e.Contacts)
                .Map(m => m.ToTable("SoftwareContacts").MapLeftKey("Contact_ID").MapRightKey("Software_ID"));

            modelBuilder.Entity<ControlApplicabilityAssessment>()
                .HasMany(e => e.NistControlsCAAs)
                .WithRequired(e => e.ControlApplicabilityAssessment)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<ControlSet>()
                .HasMany(e => e.NistControls)
                .WithMany(e => e.ControlSets)
                .Map(m => m.ToTable("NistControlsControlSets").MapLeftKey("ControlSet_ID").MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<CustomTestCas>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.CustomTestCases)
                .Map(m => m.ToTable("SAP_CustomTestCases").MapLeftKey("CustomTestCase_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<DADMS_Networks>()
                .HasMany(e => e.Softwares)
                .WithMany(e => e.DADMS_Networks)
                .Map(m => m.ToTable("Software_DADMS_Networks").MapLeftKey("DADMS_Network_ID").MapRightKey("Software_ID"));

            modelBuilder.Entity<DitprDonNumber>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.DitprDonNumbers)
                .Map(m => m.ToTable("StepOneQuestionnaire_DitprDonNumbers").MapLeftKey("DITPR_DON_Number_ID").MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<EncryptionTechnique>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.EncryptionTechniques)
                .Map(m => m.ToTable("StepOneQuestionnaireEncryptionTechniques").MapLeftKey("EncryptionTechnique_ID").MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<EntranceCriteria>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.EntranceCriterias)
                .Map(m => m.ToTable("SAP_EntranceCriteria").MapLeftKey("EntranceCriteria_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<EnumeratedWindowsGroup>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.EnumeratedWindowsGroups)
                .Map(m => m.ToTable("HardwareEnumeratedWindowsGroups").MapLeftKey("Group_ID").MapRightKey("Hardware_ID"));

            modelBuilder.Entity<EnumeratedWindowsUser>()
                .HasMany(e => e.EnumeratedWindowsGroups)
                .WithMany(e => e.EnumeratedWindowsUsers)
                .Map(m => m.ToTable("EnumeratedWindowsGroupsUsers").MapLeftKey("User_ID").MapRightKey("Group_ID"));

            modelBuilder.Entity<ExitCriteria>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.ExitCriterias)
                .Map(m => m.ToTable("SAP_ExitCriteria").MapLeftKey("ExitCriteria_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<ExternalSecurityService>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.ExternalSecurityServices)
                .Map(m => m.ToTable("StepOneQuestionnaire_ExternalSecurityServices").MapLeftKey("ExternalSecurityServices_ID").MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<FindingType>()
                .HasMany(e => e.UniqueFindings)
                .WithRequired(e => e.FindingType)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<GoverningPolicy>()
                .HasMany(e => e.SystemCategorizations)
                .WithMany(e => e.GoverningPolicies)
                .Map(m => m.ToTable("SystemCategorizationGoverningPolicies").MapLeftKey("GoverningPolicy_ID").MapRightKey("SystemCategorization_ID"));

            modelBuilder.Entity<Group>()
                .HasMany(e => e.MitigationsOrConditions)
                .WithMany(e => e.Groups)
                .Map(m => m.ToTable("Groups_MitigationsOrConditions").MapLeftKey("Group_ID").MapRightKey("MitigationOrCondition_ID"));

            modelBuilder.Entity<Group>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.Groups)
                .Map(m => m.ToTable("HardwareGroups").MapLeftKey("Group_ID").MapRightKey("Hardware_ID"));

            modelBuilder.Entity<Hardware>()
                .HasMany(e => e.Hardware_PPS)
                .WithRequired(e => e.Hardware)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Hardware>()
                .HasMany(e => e.HardwareLocations)
                .WithRequired(e => e.Hardware)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Hardware>()
                .HasMany(e => e.ScapScores)
                .WithRequired(e => e.Hardware)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Hardware>()
                .HasMany(e => e.SoftwareHardwares)
                .WithRequired(e => e.Hardware)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<IA_Controls>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.IA_Controls)
                .Map(m => m.ToTable("Vulnerabilities_IA_Controls").MapLeftKey("IA_Control_ID").MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<IATA_Standards>()
                .HasMany(e => e.Accreditations)
                .WithMany(e => e.IATA_Standards)
                .Map(m => m.ToTable("Accreditations_IATA_Standards").MapLeftKey("IATA_Standard_ID").MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<IATA_Standards>()
                .HasMany(e => e.NistControls)
                .WithMany(e => e.IATA_Standards)
                .Map(m => m.ToTable("NistControls_IATA_Standards").MapLeftKey("IATA_Standard_ID").MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<InformationType>()
                .HasMany(e => e.SystemCategorizationInformationTypes)
                .WithRequired(e => e.InformationType)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<IntegrityLevel>()
                .HasMany(e => e.Accreditations)
                .WithRequired(e => e.IntegrityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<IntegrityLevel>()
                .HasMany(e => e.NistControlsIntegrityLevels)
                .WithRequired(e => e.IntegrityLevel)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<InterconnectedSystem>()
                .HasMany(e => e.SystemCategorizations)
                .WithMany(e => e.InterconnectedSystems)
                .Map(m => m.ToTable("SystemCategorizationInterconnectedSystems").MapLeftKey("InterconnectedSystem_ID").MapRightKey("SystemCategorization_ID"));

            modelBuilder.Entity<IP_Addresses>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.IP_Addresses)
                .Map(m => m.ToTable("HardwareIpAddresses").MapLeftKey("IP_Address_ID").MapRightKey("Hardware_ID"));

            modelBuilder.Entity<JointAuthorizationOrganization>()
                .HasMany(e => e.SystemCategorizations)
                .WithMany(e => e.JointAuthorizationOrganizations)
                .Map(m => m.ToTable("SystemCategorizationJointOrganizations").MapLeftKey("JointOrganization_ID").MapRightKey("SystemCategorization_ID"));

            modelBuilder.Entity<Limitation>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.Limitations1)
                .Map(m => m.ToTable("SAP_Limitiations").MapLeftKey("Limitation_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<Location>()
                .HasMany(e => e.HardwareLocations)
                .WithRequired(e => e.Location)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<MAC_Addresses>()
                .HasMany(e => e.Hardwares)
                .WithMany(e => e.MAC_Addresses)
                .Map(m => m.ToTable("HardwareMacAddresses").MapLeftKey("MAC_Address_ID").MapRightKey("Hardware_ID"));

            modelBuilder.Entity<MissionArea>()
                .HasMany(e => e.InformationTypes)
                .WithMany(e => e.MissionAreas)
                .Map(m => m.ToTable("InformationTypesMissionAreas").MapLeftKey("MissionArea_ID").MapRightKey("InformationType_ID"));

            modelBuilder.Entity<NetworkConnectionRule>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.NetworkConnectionRules)
                .Map(m => m.ToTable("StepOneQuestionnaireNetworkConnectionRules").MapLeftKey("NetworkConnectionRule_ID").MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<NistControl>()
                .HasMany(e => e.AccreditationsNistControls)
                .WithRequired(e => e.NistControl)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<NistControl>()
                .HasMany(e => e.NistControlsAvailabilityLevels)
                .WithRequired(e => e.NistControl)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<NistControl>()
                .HasMany(e => e.NistControlsCAAs)
                .WithRequired(e => e.NistControl)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<NistControl>()
                .HasMany(e => e.NistControlsCCIs)
                .WithRequired(e => e.NistControl)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<NistControl>()
                .HasMany(e => e.NistControlsConfidentialityLevels)
                .WithRequired(e => e.NistControl)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<NistControl>()
                .HasMany(e => e.NistControlsIntegrityLevels)
                .WithRequired(e => e.NistControl)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<NssQuestionnaire>()
                .HasMany(e => e.SystemCategorizations)
                .WithRequired(e => e.NssQuestionnaire)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Organization>()
                .HasMany(e => e.Contacts)
                .WithRequired(e => e.Organization)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Overlay>()
                .HasMany(e => e.Accreditations)
                .WithMany(e => e.Overlays)
                .Map(m => m.ToTable("AccreditationsOverlays").MapLeftKey("Overlay_ID").MapRightKey("Accreditation_ID"));

            modelBuilder.Entity<Overlay>()
                .HasMany(e => e.NistControls)
                .WithMany(e => e.Overlays)
                .Map(m => m.ToTable("NistControlsOverlays").MapLeftKey("Overlay_ID").MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<PP>()
                .HasMany(e => e.Hardware_PPS)
                .WithRequired(e => e.PP)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<RelatedDocument>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.RelatedDocuments)
                .Map(m => m.ToTable("SAP_RelatedDocuments").MapLeftKey("RelatedDocument_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<RelatedTesting>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.RelatedTestings)
                .Map(m => m.ToTable("SAP_RelatedTesting").MapLeftKey("RelatedTesting_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<ReportCategory>()
                .HasMany(e => e.RequiredReports)
                .WithRequired(e => e.ReportCategory)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<ResponsibilityRole>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.ResponsibilityRoles)
                .Map(m => m.ToTable("Vulnerabilities_RoleResponsibilities").MapLeftKey("Role_ID").MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<Software>()
                .HasMany(e => e.SoftwareHardwares)
                .WithRequired(e => e.Software)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<StepOneQuestionnaire>()
                .HasMany(e => e.Accreditations)
                .WithRequired(e => e.StepOneQuestionnaire)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<SystemCategorization>()
                .HasMany(e => e.Accreditations)
                .WithRequired(e => e.SystemCategorization)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<SystemCategorization>()
                .HasMany(e => e.SystemCategorizationInformationTypes)
                .WithRequired(e => e.SystemCategorization)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<SystemType>()
                .HasMany(e => e.Overviews)
                .WithRequired(e => e.SystemType)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<TestReference>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.TestReferences)
                .Map(m => m.ToTable("SAP_TestReferences").MapLeftKey("TestReference_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<TestScheduleItem>()
                .HasMany(e => e.SAPs)
                .WithMany(e => e.TestScheduleItems)
                .Map(m => m.ToTable("SAP_TestScheduleItems").MapLeftKey("TestScheduleItem_ID").MapRightKey("SAP_ID"));

            modelBuilder.Entity<Title>()
                .HasMany(e => e.Contacts)
                .WithRequired(e => e.Title)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<UniqueFindingsSourceFile>()
                .HasMany(e => e.UniqueFindings)
                .WithRequired(e => e.UniqueFindingsSourceFile)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<UserCategory>()
                .HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.UserCategories)
                .Map(m => m.ToTable("StepOneQuestionnaireUserCategories").MapLeftKey("UserCategory_ID").MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<Vulnerability>()
                .HasMany(e => e.UniqueFindings)
                .WithRequired(e => e.Vulnerability)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<VulnerabilityReference>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.VulnerabilityReferences)
                .Map(m => m.ToTable("Vulnerabilities_VulnerabilityReferences").MapLeftKey("Reference_ID").MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<VulnerabilitySource>()
                .HasMany(e => e.ScapScores)
                .WithRequired(e => e.VulnerabilitySource)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<VulnerabilitySource>()
                .HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.VulnerabilitySources)
                .Map(m => m.ToTable("Vulnerabilities_VulnerabilitySources").MapLeftKey("Vulnerability_Source_ID").MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<Waiver>()
                .HasMany(e => e.AccreditationsWaivers)
                .WithRequired(e => e.Waiver)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<WindowsDomainUserSetting>()
                .HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.WindowsDomainUserSettings)
                .Map(m => m.ToTable("EnumeratedDomainUsersSettings").MapLeftKey("Domain_Settings_ID").MapRightKey("User_ID"));

            modelBuilder.Entity<WindowsLocalUserSetting>()
                .HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.WindowsLocalUserSettings)
                .Map(m => m.ToTable("EnumeratedLocalWindowsUsersSettings").MapLeftKey("Local_Settings_ID").MapRightKey("User_ID"));
        }
    }
}
