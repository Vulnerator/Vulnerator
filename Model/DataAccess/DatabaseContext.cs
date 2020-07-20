using System.Data.Entity;
using System.Data.SQLite;
using Vulnerator.Model.Entity;
using Vulnerator.Properties;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext() : base(DatabaseBuilder.sqliteConnection, false)
        {
        }

        public virtual DbSet<AdditionalTestConsideration> AdditionalTestConsiderations { get; set; }
        public virtual DbSet<AuthorizationCondition> AuthorizationConditions { get; set; }

        public virtual DbSet<AuthorizationToConnectOrInterim_ATC_PendingItem>
            AuthorizationToConnectOrInterim_ATC_PendingItems { get; set; }

        public virtual DbSet<AvailabilityLevel> AvailabilityLevels { get; set; }
        public virtual DbSet<Boundary> Boundaries { get; set; }
        public virtual DbSet<CCI> CCIs { get; set; }
        public virtual DbSet<Certification> Certifications { get; set; }
        public virtual DbSet<CommonControlPackage> CommonControlPackages { get; set; }
        public virtual DbSet<ConfidentialityLevel> ConfidentialityLevels { get; set; }
        public virtual DbSet<ConnectedSystem> ConnectedSystems { get; set; }
        public virtual DbSet<Connection> Connections { get; set; }
        public virtual DbSet<Connectivity> Connectivities { get; set; }
        public virtual DbSet<Contact> Contacts { get; set; }
        public virtual DbSet<ControlApplicabilityAssessment> ControlApplicabilityAssessments { get; set; }
        public virtual DbSet<ControlSelection> ControlSelections { get; set; }
        public virtual DbSet<ControlSet> ControlSets { get; set; }
        public virtual DbSet<CustomTestCase> CustomTestCases { get; set; }
        public virtual DbSet<DADMS_Network> DADMS_Networks { get; set; }
        public virtual DbSet<EncryptionTechnique> EncryptionTechniques { get; set; }
        public virtual DbSet<EntranceCriteria> EntranceCriterias { get; set; }
        public virtual DbSet<EnumeratedWindowsGroup> EnumeratedWindowsGroups { get; set; }
        public virtual DbSet<EnumeratedWindowsUser> EnumeratedWindowsUsers { get; set; }
        public virtual DbSet<ExitCriteria> ExitCriterias { get; set; }
        public virtual DbSet<ExternalSecurityService> ExternalSecurityServices { get; set; }
        public virtual DbSet<FindingType> FindingTypes { get; set; }
        public virtual DbSet<GoverningPolicy> GoverningPolicies { get; set; }
        public virtual DbSet<Group> Groups { get; set; }
        public virtual DbSet<GroupMitigationOrConditionVulnerability> GroupsMitigationsOrConditionsVulnerabilities
        {
            get;
            set;
        }
        public virtual DbSet<Hardware> Hardwares { get; set; }
        public virtual DbSet<HardwarePortProtocolService> HardwarePortsProtocolsServices { get; set; }
        public virtual DbSet<HardwareSoftwarePortProtocolServiceBoundary> HardwarePortsProtocolsServicesBoundaries { get; set; }
        public virtual DbSet<HardwareSoftwarePortProtocolService> HardwareSoftwarePortProtocolServices { get; set; }
        public virtual DbSet<IA_Control> IA_Controls { get; set; }
        public virtual DbSet<IATA_Standard> IATA_Standards { get; set; }
        public virtual DbSet<ImpactAdjustment> ImpactAdjustments { get; set; }
        public virtual DbSet<InformationType> InformationTypes { get; set; }
        public virtual DbSet<IntegrityLevel> IntegrityLevels { get; set; }
        public virtual DbSet<InterconnectedSystem> InterconnectedSystems { get; set; }
        public virtual DbSet<IP_Address> IP_Addresses { get; set; }
        public virtual DbSet<JointAuthorizationOrganization> JointAuthorizationOrganizations { get; set; }
        public virtual DbSet<LifecycleStatus> LifecycleStatuses { get; set; }
        public virtual DbSet<Limitation> Limitations { get; set; }
        public virtual DbSet<Location> Locations { get; set; }
        public virtual DbSet<MAC_Address> MAC_Addresses { get; set; }
        public virtual DbSet<MissionArea> MissionAreas { get; set; }
        public virtual DbSet<MitigationOrCondition> MitigationsOrConditions { get; set; }
        public virtual DbSet<NetworkConnectionRule> NetworkConnectionRules { get; set; }
        public virtual DbSet<NIST_Control> NIST_Controls { get; set; }
        public virtual DbSet<NIST_ControlCCI> NIST_ControlsCCIs { get; set; }
        public virtual DbSet<Organization> Organizations { get; set; }
        public virtual DbSet<Overlay> Overlays { get; set; }
        public virtual DbSet<PIT_Determination> PIT_Determinations { get; set; }
        public virtual DbSet<PortProtocolService> PortsProtocolsServices { get; set; }
        public virtual DbSet<RelatedDocument> RelatedDocuments { get; set; }
        public virtual DbSet<RelatedTesting> RelatedTestings { get; set; }
        public virtual DbSet<ReportFindingTypeUserSettings> ReportFindingTypeUserSettings { get; set; }
        public virtual DbSet<ReportGroupUserSettings> ReportGroupUserSettings { get; set; }
        public virtual DbSet<ReportSeverityUserSettings> ReportSeverityUserSettings { get; set; }
        public virtual DbSet<ReportStatusUserSettings> ReportStatusUserSettings { get; set; }
        public virtual DbSet<RequiredReportUserSelection> RequiredReportUserSelections { get; set; }
        public virtual DbSet<RequiredReport> RequiredReports { get; set; }
        public virtual DbSet<ResponsibilityRole> ResponsibilityRoles { get; set; }
        public virtual DbSet<SecurityAssessmentProcedure> SecurityAssessmentProcedures { get; set; }
        public virtual DbSet<SCAP_Score> SCAP_Scores { get; set; }
        public virtual DbSet<Software> Softwares { get; set; }
        public virtual DbSet<SoftwareHardware> SoftwareHardwares { get; set; }
        public virtual DbSet<StepOneQuestionnaire> StepOneQuestionnaires { get; set; }
        public virtual DbSet<SystemCategorization> SystemCategorizations { get; set; }
        public virtual DbSet<TestReference> TestReferences { get; set; }
        public virtual DbSet<TestScheduleItem> TestScheduleItems { get; set; }
        public virtual DbSet<Title> Titles { get; set; }
        public virtual DbSet<UniqueFinding> UniqueFindings { get; set; }
        public virtual DbSet<UniqueFindingSourceFile> UniqueFindingsSourceFiles { get; set; }
        public virtual DbSet<UserCategory> UserCategories { get; set; }
        public virtual DbSet<Vulnerability> Vulnerabilities { get; set; }
        public virtual DbSet<VulnerabilityReference> VulnerabilityReferences { get; set; }
        public virtual DbSet<VulnerabilitySource> VulnerabilitySources { get; set; }
        public virtual DbSet<Waiver> Waivers { get; set; }
        public virtual DbSet<WindowsDomainUserSetting> WindowsDomainUserSettings { get; set; }
        public virtual DbSet<WindowsLocalUserSetting> WindowsLocalUserSettings { get; set; }

        private static string ConnectionString()
        {
            SQLiteConnectionStringBuilder sqliteConnectionStringBuilder = new SQLiteConnectionStringBuilder
                {DataSource = Settings.Default.Database.Split(';')[0]};
            return sqliteConnectionStringBuilder.ToString();
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Contact>()
                .HasMany(e => e.Certifications)
                .WithMany(e => e.Contacts)
                .Map(e => e.ToTable("ContactsCertifications")
                    .MapLeftKey("Contact_ID")
                    .MapRightKey("Certification_ID"));

            modelBuilder.Entity<Certification>()
                .HasMany(e => e.Contacts)
                .WithMany(e => e.Certifications)
                .Map(e => e.ToTable("ContactsCertifications")
                    .MapLeftKey("Certification_ID")
                    .MapRightKey("Contact_ID"));

            modelBuilder.Entity<Contact>().HasOptional(e => e.Organization).WithMany(e => e.Contacts);

            modelBuilder.Entity<Organization>()
                .HasMany(e => e.Contacts)
                .WithOptional(e => e.Organization);

            modelBuilder.Entity<CustomTestCase>().HasRequired(e => e.CCI).WithMany(e => e.CustomTestCases);

            modelBuilder.Entity<CCI>().HasMany(e => e.CustomTestCases).WithRequired(e => e.CCI);

            modelBuilder.Entity<EnumeratedWindowsUser>().HasMany(e => e.WindowsDomainUserSettings)
                .WithMany(e => e.EnumeratedWindowsUsers)
                .Map(e => e.ToTable("EnumeratedDomainWindowsUsersSettings")
                    .MapLeftKey("EnumeratedWindowsUser_ID")
                    .MapRightKey("WindowsDomainUserSettings_ID"));

            modelBuilder.Entity<WindowsDomainUserSetting>().HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.WindowsDomainUserSettings)
                .Map(e => e.ToTable("EnumeratedDomainWindowsUsersSettings")
                    .MapLeftKey("WindowsDomainUserSettings_ID")
                    .MapRightKey("EnumeratedWindowsUser_ID"));

            modelBuilder.Entity<EnumeratedWindowsUser>().HasMany(e => e.WindowsLocalUserSettings)
                .WithMany(e => e.EnumeratedWindowsUsers)
                .Map(e => e.ToTable("EnumeratedLocalWindowsUsersSettings")
                    .MapLeftKey("EnumeratedWindowsUser_ID")
                    .MapRightKey("WindowsLocalUserSettings_ID"));

            modelBuilder.Entity<WindowsLocalUserSetting>().HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.WindowsLocalUserSettings)
                .Map(e => e.ToTable("EnumeratedLocalWindowsUsersSettings")
                    .MapLeftKey("WindowsLocalUserSettings_ID")
                    .MapRightKey("EnumeratedWindowsUser_ID"));

            modelBuilder.Entity<EnumeratedWindowsUser>().HasMany(e => e.EnumeratedWindowsGroups)
                .WithMany(e => e.EnumeratedWindowsUsers)
                .Map(e => e.ToTable("EnumeratedWindowsGroupsUsers")
                    .MapLeftKey("EnumeratedWindowsUser_ID")
                    .MapRightKey("EnumeratedWindowsGroup_ID"));

            modelBuilder.Entity<EnumeratedWindowsGroup>().HasMany(e => e.EnumeratedWindowsUsers)
                .WithMany(e => e.EnumeratedWindowsGroups)
                .Map(e => e.ToTable("EnumeratedWindowsGroupsUsers")
                    .MapLeftKey("EnumeratedWindowsGroup_ID")
                    .MapRightKey("EnumeratedWindowsUser_ID"));

            modelBuilder.Entity<Group>().HasOptional(e => e.ConfidentialityLevel).WithMany(e => e.Groups);

            modelBuilder.Entity<ConfidentialityLevel>().HasMany(e => e.Groups)
                .WithOptional(e => e.ConfidentialityLevel);

            modelBuilder.Entity<Group>().HasOptional(e => e.IntegrityLevel).WithMany(e => e.Groups);

            modelBuilder.Entity<IntegrityLevel>().HasMany(e => e.Groups)
                .WithOptional(e => e.IntegrityLevel);

            modelBuilder.Entity<Group>().HasOptional(e => e.AvailabilityLevel).WithMany(e => e.Groups);

            modelBuilder.Entity<AvailabilityLevel>().HasMany(e => e.Groups)
                .WithOptional(e => e.AvailabilityLevel);

            modelBuilder.Entity<Group>().HasOptional(e => e.SystemCategorization).WithRequired(e => e.Group);

            modelBuilder.Entity<SystemCategorization>().HasRequired(e => e.Group)
                .WithOptional(e => e.SystemCategorization);

            modelBuilder.Entity<Group>().HasOptional(e => e.ControlSelection).WithRequired(e => e.Group);

            modelBuilder.Entity<ControlSelection>().HasRequired(e => e.Group)
                .WithOptional(e => e.ControlSelection);

            modelBuilder.Entity<Group>().HasOptional(e => e.StepOneQuestionnaire).WithRequired(e => e.Group);

            modelBuilder.Entity<StepOneQuestionnaire>().HasRequired(e => e.Group)
                .WithOptional(e => e.StepOneQuestionnaire);

            modelBuilder.Entity<Group>().HasOptional(e => e.SecurityAssessmentProcedure).WithRequired(e => e.Group);

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasRequired(e => e.Group)
                .WithOptional(e => e.SecurityAssessmentProcedure);

            modelBuilder.Entity<Group>().HasOptional(e => e.PIT_Determination).WithRequired(e => e.Group);

            modelBuilder.Entity<PIT_Determination>().HasRequired(e => e.Group)
                .WithOptional(e => e.PIT_Determination);

            modelBuilder.Entity<Group>().HasOptional(e => e.Organization).WithRequired(e => e.Group);

            modelBuilder.Entity<Organization>().HasRequired(e => e.Group)
                .WithOptional(e => e.Organization);

            modelBuilder.Entity<Group>().HasMany(e => e.CCIs).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsCCIs")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("CCI_ID"));

            modelBuilder.Entity<CCI>().HasMany(e => e.Groups).WithMany(e => e.CCIs)
                .Map(e => e.ToTable("GroupsCCIs")
                    .MapLeftKey("CCI_ID")
                    .MapRightKey("Group_ID"));

            modelBuilder.Entity<Group>().HasMany(e => e.ConnectedSystems).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsConnectedSystems")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("ConnectedSystem_ID"));

            modelBuilder.Entity<ConnectedSystem>().HasMany(e => e.Groups).WithMany(e => e.ConnectedSystems)
                .Map(e => e.ToTable("GroupsConnectedSystems")
                    .MapLeftKey("ConnectedSystem_ID")
                    .MapRightKey("Group_ID"));

            modelBuilder.Entity<Group>().HasMany(e => e.Connections).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsConnections")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("Connection_ID"));

            modelBuilder.Entity<Connection>().HasMany(e => e.Groups).WithMany(e => e.Connections)
                .Map(e => e.ToTable("GroupsConnections")
                    .MapLeftKey("Connection_ID")
                    .MapRightKey("Group_ID"));

            // TODO: GroupsContactsTitles

            modelBuilder.Entity<Group>().HasMany(e => e.IATA_Standards).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsIATA_Standards")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("IATA_Standard_ID"));

            modelBuilder.Entity<IATA_Standard>().HasMany(e => e.Groups).WithMany(e => e.IATA_Standards)
                .Map(e => e.ToTable("GroupsIATA_Standards")
                    .MapLeftKey("IATA_Standard_ID")
                    .MapRightKey("Group_ID"));

            modelBuilder.Entity<Group>().HasMany(e => e.Overlays).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsOverlays")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("Overlay_ID"));

            modelBuilder.Entity<Overlay>().HasMany(e => e.Groups).WithMany(e => e.Overlays)
                .Map(e => e.ToTable("GroupsOverlays")
                    .MapLeftKey("Overlay_ID")
                    .MapRightKey("Group_ID"));

            modelBuilder.Entity<Group>().HasMany(e => e.Waivers).WithMany(e => e.Groups)
                .Map(e => e.ToTable("GroupsWaivers")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("Waiver_ID"));

            modelBuilder.Entity<Waiver>().HasMany(e => e.Groups).WithMany(e => e.Waivers)
                .Map(e => e.ToTable("GroupsWaivers")
                    .MapLeftKey("Waiver_ID")
                    .MapRightKey("Group_ID"));
            
            modelBuilder.Entity<GroupMitigationOrConditionVulnerability>().HasRequired(e => e.Group)
                .WithMany(e => e.GroupsMitigationsOrConditionsVulnerabilities);

            modelBuilder.Entity<Group>().HasMany(e => e.GroupsMitigationsOrConditionsVulnerabilities)
                .WithRequired(e => e.Group);
            
            modelBuilder.Entity<GroupMitigationOrConditionVulnerability>().HasRequired(e => e.Vulnerability)
                .WithMany(e => e.GroupsMitigationsOrConditionsVulnerabilities);

            modelBuilder.Entity<Vulnerability>().HasMany(e => e.GroupsMitigationsOrConditionsVulnerabilities)
                .WithRequired(e => e.Vulnerability);
            
            modelBuilder.Entity<GroupMitigationOrConditionVulnerability>().HasRequired(e => e.MitigationOrCondition)
                .WithMany(e => e.GroupsMitigationsOrConditionsVulnerabilities);

            modelBuilder.Entity<MitigationOrCondition>().HasMany(e => e.GroupsMitigationsOrConditionsVulnerabilities)
                .WithRequired(e => e.MitigationOrCondition);

            modelBuilder.Entity<Hardware>().HasOptional(e => e.LifecycleStatus).WithMany(e => e.Hardwares);

            modelBuilder.Entity<LifecycleStatus>().HasMany(e => e.Hardwares).WithOptional(e => e.LifecycleStatus);

            modelBuilder.Entity<Hardware>().HasMany(e => e.Contacts).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwareContacts")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("Contact_ID"));

            modelBuilder.Entity<Contact>().HasMany(e => e.Hardwares).WithMany(e => e.Contacts)
                .Map(e => e.ToTable("HardwareContacts")
                    .MapLeftKey("Contact_ID")
                    .MapRightKey("Hardware_ID"));

            modelBuilder.Entity<Hardware>().HasMany(e => e.EnumeratedWindowsGroups).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwareEnumeratedWindowsGroups")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("EnumeratedWindowsGroup_ID"));

            modelBuilder.Entity<EnumeratedWindowsGroup>().HasMany(e => e.Hardwares)
                .WithMany(e => e.EnumeratedWindowsGroups)
                .Map(e => e.ToTable("HardwareEnumeratedWindowsGroups")
                    .MapLeftKey("EnumeratedWindowsGroup_ID")
                    .MapRightKey("Hardware_ID"));

            modelBuilder.Entity<Hardware>().HasMany(e => e.Groups).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwareGroups")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("Group_ID"));

            modelBuilder.Entity<Group>().HasMany(e => e.Hardwares).WithMany(e => e.Groups)
                .Map(e => e.ToTable("HardwareGroups")
                    .MapLeftKey("Group_ID")
                    .MapRightKey("Hardware_ID"));

            modelBuilder.Entity<Hardware>().HasMany(e => e.IP_Addresses).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("Hardware_IP_Addresses")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("IP_Address_ID"));

            modelBuilder.Entity<IP_Address>().HasMany(e => e.Hardwares).WithMany(e => e.IP_Addresses)
                .Map(e => e.ToTable("Hardware_IP_Addresses")
                    .MapLeftKey("IP_Address_ID")
                    .MapRightKey("Hardware_ID"));

            modelBuilder.Entity<Hardware>().HasMany(e => e.MAC_Addresses).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("Hardware_MAC_Addresses")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("MAC_Address_ID"));

            modelBuilder.Entity<MAC_Address>().HasMany(e => e.Hardwares).WithMany(e => e.MAC_Addresses)
                .Map(e => e.ToTable("Hardware_MAC_Addresses")
                    .MapLeftKey("MAC_Address_ID")
                    .MapRightKey("Hardware_ID"));

            modelBuilder.Entity<Hardware>().HasMany(e => e.Locations).WithMany(e => e.Hardwares)
                .Map(e => e.ToTable("HardwareLocation")
                    .MapLeftKey("Hardware_ID")
                    .MapRightKey("Location_ID"));

            modelBuilder.Entity<Location>().HasMany(e => e.Hardwares).WithMany(e => e.Locations)
                .Map(e => e.ToTable("HardwareLocation")
                    .MapLeftKey("Location_ID")
                    .MapRightKey("Hardware_ID"));

            modelBuilder.Entity<HardwarePortProtocolService>().HasRequired(e => e.Hardware).WithMany(e => e.HardwarePortsProtocolsServices);

            modelBuilder.Entity<Hardware>().HasMany(e => e.HardwarePortsProtocolsServices).WithRequired(e => e.Hardware);

            modelBuilder.Entity<HardwarePortProtocolService>().HasRequired(e => e.PortProtocolService).WithMany(e => e.HardwarePortsProtocolsServices);

            modelBuilder.Entity<PortProtocolService>().HasMany(e => e.HardwarePortsProtocolsServices).WithRequired(e => e.PortProtocolService);

            modelBuilder.Entity<HardwarePortProtocolService>().HasMany(e => e.HardwareSoftwarePortsProtocolsServices)
                .WithRequired(e => e.HardwarePortProtocolService);

            modelBuilder.Entity<HardwareSoftwarePortProtocolService>().HasRequired(e => e.HardwarePortProtocolService)
                .WithMany(e => e.HardwareSoftwarePortsProtocolsServices);

            modelBuilder.Entity<Software>().HasMany(e => e.HardwareSoftwarePortsProtocolsServices)
                .WithRequired(e => e.Software);

            modelBuilder.Entity<HardwareSoftwarePortProtocolService>().HasRequired(e => e.Software)
                .WithMany(e => e.HardwareSoftwarePortsProtocolsServices);

            modelBuilder.Entity<HardwareSoftwarePortProtocolServiceBoundary>().HasRequired(e => e.Boundary)
                .WithMany(e => e.HardwareSoftwarePortsProtocolsServicesBoundaries);

            modelBuilder.Entity<Boundary>().HasMany(e => e.HardwareSoftwarePortsProtocolsServicesBoundaries)
                .WithRequired(e => e.Boundary);

            modelBuilder.Entity<HardwareSoftwarePortProtocolServiceBoundary>().HasRequired(e => e.HardwareSoftwarePortProtocolService)
                .WithMany(e => e.HardwareSoftwarePortsProtocolsServicesBoundaries);

            modelBuilder.Entity<HardwareSoftwarePortProtocolService>().HasMany(e => e.HardwareSoftwarePortsProtocolsServicesBoundaries)
                .WithRequired(e => e.HardwareSoftwarePortProtocolService);

            modelBuilder.Entity<InformationType>().HasMany(e => e.MissionAreas).WithMany(e => e.InformationTypes)
                .Map(e => e.ToTable("InformationTypesMissionAreas")
                    .MapLeftKey("InformationType_ID")
                    .MapRightKey("MissionArea_ID"));

            modelBuilder.Entity<MissionArea>().HasMany(e => e.InformationTypes).WithMany(e => e.MissionAreas)
                .Map(e => e.ToTable("InformationTypesMissionAreas")
                    .MapLeftKey("MissionArea_ID")
                    .MapRightKey("InformationType_ID"));

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.IATA_Standards).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_Controls_IATA_Standards")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("IATA_Standard_ID"));

            modelBuilder.Entity<IATA_Standard>().HasMany(e => e.NIST_Controls).WithMany(e => e.IATA_Standards)
                .Map(e => e.ToTable("NIST_Controls_IATA_Standards")
                    .MapLeftKey("IATA_Standard_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.AvailabilityLevels).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsAvailabilityLevels")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("AvailabilityLevel_ID"));

            modelBuilder.Entity<AvailabilityLevel>().HasMany(e => e.NIST_Controls).WithMany(e => e.AvailabilityLevels)
                .Map(e => e.ToTable("NIST_ControlsAvailabilityLevels")
                    .MapLeftKey("AvailabilityLevel_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<NIST_ControlCCI>().HasRequired(e => e.NIST_Control).WithMany(e => e.NIST_ControlsCCIs);

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.NIST_ControlsCCIs).WithRequired(e => e.NIST_Control);

            modelBuilder.Entity<NIST_ControlCCI>().HasRequired(e => e.CCI).WithMany(e => e.NIST_ControlsCCIs);

            modelBuilder.Entity<CCI>().HasMany(e => e.NIST_ControlsCCIs).WithRequired(e => e.CCI);

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.ControlApplicabilityAssessments)
                .WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsCAAs")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("ControlApplicabilityAssessment_ID"));

            modelBuilder.Entity<ControlApplicabilityAssessment>().HasMany(e => e.NIST_Controls)
                .WithMany(e => e.ControlApplicabilityAssessments)
                .Map(e => e.ToTable("NIST_ControlsCAAs")
                    .MapLeftKey("ControlApplicabilityAssessment_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.ConfidentialityLevels).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsConfidentialityLevels")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("ConfidentialityLevel_ID"));

            modelBuilder.Entity<ConfidentialityLevel>().HasMany(e => e.NIST_Controls)
                .WithMany(e => e.ConfidentialityLevels)
                .Map(e => e.ToTable("NIST_ControlsConfidentialityLevels")
                    .MapLeftKey("ConfidentialityLevel_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.ControlSets).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsControlSets")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("ControlSet_ID"));

            modelBuilder.Entity<ControlSet>().HasMany(e => e.NIST_Controls).WithMany(e => e.ControlSets)
                .Map(e => e.ToTable("NIST_ControlsControlSets")
                    .MapLeftKey("ControlSet_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.CommonControlPackages).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsCCPs")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("CommonControlPackage_ID"));

            modelBuilder.Entity<CommonControlPackage>().HasMany(e => e.NIST_Controls)
                .WithMany(e => e.CommonControlPackages)
                .Map(e => e.ToTable("NIST_ControlsCCPs")
                    .MapLeftKey("CommonControlPackage_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.IntegrityLevels).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsIntegrityLevels")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("IntegrityLevel_ID"));

            modelBuilder.Entity<IntegrityLevel>().HasMany(e => e.NIST_Controls).WithMany(e => e.IntegrityLevels)
                .Map(e => e.ToTable("NIST_ControlsIntegrityLevels")
                    .MapLeftKey("IntegrityLevel_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<NIST_Control>().HasMany(e => e.Overlays).WithMany(e => e.NIST_Controls)
                .Map(e => e.ToTable("NIST_ControlsOverlays")
                    .MapLeftKey("NIST_Control_ID")
                    .MapRightKey("Overlay_ID"));

            modelBuilder.Entity<Overlay>().HasMany(e => e.NIST_Controls).WithMany(e => e.Overlays)
                .Map(e => e.ToTable("NIST_ControlsOverlays")
                    .MapLeftKey("Overlay_ID")
                    .MapRightKey("NIST_Control_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.AdditionalTestConsiderations)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresAdditionalTestConsiderations")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("AdditionalTestConsideration_ID"));

            modelBuilder.Entity<AdditionalTestConsideration>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.AdditionalTestConsiderations)
                .Map(e => e.ToTable("SecurityAssessmentProceduresAdditionalTestConsiderations")
                    .MapLeftKey("AdditionalTestConsideration_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.CustomTestCases)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresCustomTestCases")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("CustomTestCase_ID"));

            modelBuilder.Entity<CustomTestCase>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.CustomTestCases)
                .Map(e => e.ToTable("SecurityAssessmentProceduresCustomTestCases")
                    .MapLeftKey("CustomTestCase_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.EntranceCriterias)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresEntranceCriteria")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("EntranceCriteria_ID"));

            modelBuilder.Entity<EntranceCriteria>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.EntranceCriterias)
                .Map(e => e.ToTable("SecurityAssessmentProceduresEntranceCriteria")
                    .MapLeftKey("EntranceCriteria_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.ExitCriterias)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresExitCriteria")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("ExitCriteria_ID"));

            modelBuilder.Entity<ExitCriteria>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.ExitCriterias)
                .Map(e => e.ToTable("SecurityAssessmentProceduresExitCriteria")
                    .MapLeftKey("ExitCriteria_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.Limitations)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresLimitiations")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("Limitation_ID"));

            modelBuilder.Entity<Limitation>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.Limitations)
                .Map(e => e.ToTable("SecurityAssessmentProceduresLimitiations")
                    .MapLeftKey("Limitation_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.RelatedDocuments)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresRelatedDocuments")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("RelatedDocument_ID"));

            modelBuilder.Entity<RelatedDocument>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.RelatedDocuments)
                .Map(e => e.ToTable("SecurityAssessmentProceduresRelatedDocuments")
                    .MapLeftKey("RelatedDocument_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.RelatedTestings)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresRelatedTesting")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("RelatedTesting_ID"));

            modelBuilder.Entity<RelatedTesting>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.RelatedTestings)
                .Map(e => e.ToTable("SecurityAssessmentProceduresRelatedTesting")
                    .MapLeftKey("RelatedTesting_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.TestReferences)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresTestReferences")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("TestReference_ID"));

            modelBuilder.Entity<TestReference>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.TestReferences)
                .Map(e => e.ToTable("SecurityAssessmentProceduresTestReferences")
                    .MapLeftKey("TestReference_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SecurityAssessmentProcedure>().HasMany(e => e.TestScheduleItems)
                .WithMany(e => e.SecurityAssessmentProcedures)
                .Map(e => e.ToTable("SecurityAssessmentProceduresTestScheduleItems")
                    .MapLeftKey("SecurityAssessmentProcedure_ID")
                    .MapRightKey("TestScheduleItem_ID"));

            modelBuilder.Entity<TestScheduleItem>().HasMany(e => e.SecurityAssessmentProcedures)
                .WithMany(e => e.TestScheduleItems)
                .Map(e => e.ToTable("SecurityAssessmentProceduresTestScheduleItems")
                    .MapLeftKey("TestScheduleItem_ID")
                    .MapRightKey("SecurityAssessmentProcedure_ID"));

            modelBuilder.Entity<SCAP_Score>().HasRequired(e => e.Hardware).WithMany(e => e.SCAP_Scores);

            modelBuilder.Entity<Hardware>().HasMany(e => e.SCAP_Scores).WithRequired(e => e.Hardware);

            modelBuilder.Entity<SCAP_Score>().HasRequired(e => e.UniqueFindingSourceFile)
                .WithOptional(e => e.SCAP_Score);

            modelBuilder.Entity<UniqueFindingSourceFile>().HasOptional(e => e.SCAP_Score)
                .WithRequired(e => e.UniqueFindingSourceFile);

            modelBuilder.Entity<SCAP_Score>().HasRequired(e => e.VulnerabilitySource)
                .WithMany(e => e.SCAP_Scores);

            modelBuilder.Entity<VulnerabilitySource>().HasMany(e => e.SCAP_Scores)
                .WithRequired(e => e.VulnerabilitySource);

            modelBuilder.Entity<Software>().HasMany(e => e.DADMS_Networks).WithMany(e => e.Softwares)
                .Map(e => e.ToTable("SoftwareDADMS_Networks")
                    .MapLeftKey("Software_ID")
                    .MapRightKey("DADMS_Network_ID"));

            modelBuilder.Entity<DADMS_Network>().HasMany(e => e.Softwares).WithMany(e => e.DADMS_Networks)
                .Map(e => e.ToTable("SoftwareDADMS_Networks")
                    .MapLeftKey("DADMS_Network_ID")
                    .MapRightKey("Software_ID"));

            modelBuilder.Entity<Software>().HasMany(e => e.Contacts).WithMany(e => e.Softwares)
                .Map(e => e.ToTable("SoftwareContacts")
                    .MapLeftKey("Software_ID")
                    .MapRightKey("Contact_ID"));

            modelBuilder.Entity<Contact>().HasMany(e => e.Softwares).WithMany(e => e.Contacts)
                .Map(e => e.ToTable("SoftwareContacts")
                    .MapLeftKey("Contact_ID")
                    .MapRightKey("Software_ID"));

            modelBuilder.Entity<SoftwareHardware>().HasRequired(e => e.Hardware)
                .WithMany(e => e.SoftwareHardwares);

            modelBuilder.Entity<Hardware>().HasMany(e => e.SoftwareHardwares)
                .WithRequired(e => e.Hardware);

            modelBuilder.Entity<SoftwareHardware>().HasRequired(e => e.Software)
                .WithMany(e => e.SoftwareHardwares);

            modelBuilder.Entity<Software>().HasMany(e => e.SoftwareHardwares)
                .WithRequired(e => e.Software);

            modelBuilder.Entity<StepOneQuestionnaire>().HasOptional(e => e.BaselineLocation);

            modelBuilder.Entity<StepOneQuestionnaire>().HasMany(e => e.AuthorizationConditions)
                .WithMany(e => e.StepOneQuestionnaires)
                .Map(e => e.ToTable("StepOneQuestionnaireAuthorizationConditions")
                    .MapLeftKey("StepOneQuestionnaire_ID")
                    .MapRightKey("AuthorizationCondition_ID"));

            modelBuilder.Entity<AuthorizationCondition>().HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.AuthorizationConditions)
                .Map(e => e.ToTable("StepOneQuestionnaireAuthorizationConditions")
                    .MapLeftKey("AuthorizationCondition_ID")
                    .MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<StepOneQuestionnaire>().HasMany(e => e.AuthorizationToConnectOrInterim_ATC_PendingItems)
                .WithMany(e => e.StepOneQuestionnaires)
                .Map(e => e.ToTable("StepOneQuestionnaireAuthorizationToConnectOrInterim_ATC_PendingItems")
                    .MapLeftKey("StepOneQuestionnaire_ID")
                    .MapRightKey("AuthorizationToConnectOrInterim_ATC_PendingItem_ID"));

            modelBuilder.Entity<AuthorizationToConnectOrInterim_ATC_PendingItem>().HasMany(e => e.StepOneQuestionnaires)
                .WithMany(e => e.AuthorizationToConnectOrInterim_ATC_PendingItems)
                .Map(e => e.ToTable("StepOneQuestionnaireAuthorizationToConnectOrInterim_ATC_PendingItems")
                    .MapLeftKey("AuthorizationToConnectOrInterim_ATC_PendingItem_ID")
                    .MapRightKey("StepOneQuestionnaire_ID"));

            modelBuilder.Entity<StepOneQuestionnaire>().HasMany(e => e.Connectivities)
                .WithMany(e => e.StepOneQuestionnaires)
                .Map(e => e.ToTable("StepOneQuestionnaireConnectivity")
                    .MapLeftKey("StepOneQuestionnaire_ID")
                    .MapRightKey("Connectivity_ID"));

            modelBuilder.Entity<StepOneQuestionnaire>().HasMany(e => e.ExternalSecurityServices)
                .WithMany(e => e.StepOneQuestionnaires)
                .Map(e => e.ToTable("StepOneQuestionnaireExternalSecurityServices")
                    .MapLeftKey("StepOneQuestionnaire_ID")
                    .MapRightKey("ExternalSecurityServices_ID"));

            modelBuilder.Entity<StepOneQuestionnaire>().HasMany(e => e.EncryptionTechniques)
                .WithMany(e => e.StepOneQuestionnaires)
                .Map(e => e.ToTable("StepOneQuestionnaireEncryptionTechniques")
                    .MapLeftKey("StepOneQuestionnaire_ID")
                    .MapRightKey("EncryptionTechnique_ID"));

            modelBuilder.Entity<StepOneQuestionnaire>().HasMany(e => e.DeploymentLocations)
                .WithMany(e => e.StepOneQuestionnaires)
                .Map(e => e.ToTable("StepOneQuestionnaireDeploymentLocations")
                    .MapLeftKey("StepOneQuestionnaire_ID")
                    .MapRightKey("Location_ID"));

            modelBuilder.Entity<StepOneQuestionnaire>().HasMany(e => e.NetworkConnectionRules)
                .WithMany(e => e.StepOneQuestionnaires)
                .Map(e => e.ToTable("StepOneQuestionnaireNetworkConnectionRules")
                    .MapLeftKey("StepOneQuestionnaire_ID")
                    .MapRightKey("NetworkConnectionRule_ID"));

            modelBuilder.Entity<StepOneQuestionnaire>().HasMany(e => e.UserCategories)
                .WithMany(e => e.StepOneQuestionnaires)
                .Map(e => e.ToTable("StepOneQuestionnaireUserCategories")
                    .MapLeftKey("StepOneQuestionnaire_ID")
                    .MapRightKey("UserCategory_ID"));


            modelBuilder.Entity<SystemCategorization>().HasMany(e => e.GoverningPolicies)
                .WithMany(e => e.SystemCategorizations)
                .Map(e => e.ToTable("SystemCategorizationGoverningPolicies")
                    .MapLeftKey("SystemCategorization_ID")
                    .MapRightKey("GoverningPolicy_ID"));

            // TODO: SystemCategorizationInformationTypesImpactAdjustments

            modelBuilder.Entity<SystemCategorization>().HasMany(e => e.InterconnectedSystems)
                .WithMany(e => e.SystemCategorizations)
                .Map(e => e.ToTable("SystemCategorizationInterconnectedSystems")
                    .MapLeftKey("SystemCategorization_ID")
                    .MapRightKey("InterconnectedSystem_ID"));

            modelBuilder.Entity<SystemCategorization>().HasMany(e => e.JointAuthorizationOrganizations)
                .WithMany(e => e.SystemCategorizations)
                .Map(e => e.ToTable("SystemCategorizationJointAuthorizationOrganizations")
                    .MapLeftKey("SystemCategorization_ID")
                    .MapRightKey("JointAuthorizationOrganization_ID"));

            modelBuilder.Entity<UniqueFinding>().HasRequired(e => e.FindingType).WithMany(e => e.UniqueFindings);

            modelBuilder.Entity<FindingType>().HasMany(e => e.UniqueFindings).WithRequired(e => e.FindingType);

            modelBuilder.Entity<UniqueFinding>().HasRequired(e => e.Vulnerability).WithMany(e => e.UniqueFindings);

            modelBuilder.Entity<Vulnerability>().HasMany(e => e.UniqueFindings).WithRequired(e => e.Vulnerability);

            modelBuilder.Entity<UniqueFinding>().HasOptional(e => e.Hardware).WithMany(e => e.UniqueFindings);

            modelBuilder.Entity<Hardware>().HasMany(e => e.UniqueFindings).WithOptional(e => e.Hardware);

            modelBuilder.Entity<UniqueFinding>().HasOptional(e => e.Software).WithMany(e => e.UniqueFindings);

            modelBuilder.Entity<Software>().HasMany(e => e.UniqueFindings).WithOptional(e => e.Software);

            modelBuilder.Entity<UniqueFinding>().HasRequired(e => e.UniqueFindingSourceFile)
                .WithMany(e => e.UniqueFindings);

            modelBuilder.Entity<UniqueFindingSourceFile>().HasMany(e => e.UniqueFindings)
                .WithRequired(e => e.UniqueFindingSourceFile);

            modelBuilder.Entity<UniqueFinding>().HasOptional(e => e.MitigationOrCondition).WithMany();

            modelBuilder.Entity<Vulnerability>().HasMany(e => e.CCIs).WithMany(e => e.Vulnerabilities)
                .Map(e => e.ToTable("VulnerabilitiesCCIs")
                    .MapLeftKey("Vulnerability_ID")
                    .MapRightKey("CCI_ID"));

            modelBuilder.Entity<CCI>().HasMany(e => e.Vulnerabilities).WithMany(e => e.CCIs)
                .Map(e => e.ToTable("VulnerabilitiesCCIs")
                    .MapLeftKey("CCI_ID")
                    .MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<Vulnerability>().HasMany(e => e.IA_Controls).WithMany(e => e.Vulnerabilities)
                .Map(e => e.ToTable("VulnerabilitiesIA_Controls")
                    .MapLeftKey("Vulnerability_ID")
                    .MapRightKey("IA_Control_ID"));

            modelBuilder.Entity<IA_Control>().HasMany(e => e.Vulnerabilities).WithMany(e => e.IA_Controls)
                .Map(e => e.ToTable("VulnerabilitiesIA_Controls")
                    .MapLeftKey("IA_Control_ID")
                    .MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<Vulnerability>().HasMany(e => e.ResponsibilityRoles).WithMany(e => e.Vulnerabilities)
                .Map(e => e.ToTable("VulnerabilitiesResponsibilityRoles")
                    .MapLeftKey("Vulnerability_ID")
                    .MapRightKey("Role_ID"));

            modelBuilder.Entity<ResponsibilityRole>().HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.ResponsibilityRoles)
                .Map(e => e.ToTable("VulnerabilitiesResponsibilityRoles")
                    .MapLeftKey("Role_ID")
                    .MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<Vulnerability>().HasMany(e => e.VulnerabilitySources).WithMany(e => e.Vulnerabilities)
                .Map(e => e.ToTable("VulnerabilitiesVulnerabilitySources")
                    .MapLeftKey("Vulnerability_ID")
                    .MapRightKey("VulnerabilitySource_ID"));

            modelBuilder.Entity<VulnerabilitySource>().HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.VulnerabilitySources)
                .Map(e => e.ToTable("VulnerabilitiesVulnerabilitySources")
                    .MapLeftKey("VulnerabilitySource_ID")
                    .MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<Vulnerability>().HasMany(e => e.VulnerabilityReferences)
                .WithMany(e => e.Vulnerabilities)
                .Map(e => e.ToTable("VulnerabilitiesVulnerabilityReferences")
                    .MapLeftKey("Vulnerability_ID")
                    .MapRightKey("Reference_ID"));

            modelBuilder.Entity<VulnerabilityReference>().HasMany(e => e.Vulnerabilities)
                .WithMany(e => e.VulnerabilityReferences)
                .Map(e => e.ToTable("VulnerabilitiesVulnerabilityReferences")
                    .MapLeftKey("Reference_ID")
                    .MapRightKey("Vulnerability_ID"));

            modelBuilder.Entity<RequiredReportUserSelection>().HasRequired(e => e.RequiredReport)
                .WithMany(e => e.RequiredReportUserSelections);

            modelBuilder.Entity<RequiredReport>().HasMany(e => e.RequiredReportUserSelections)
                .WithRequired(e => e.RequiredReport);

            modelBuilder.Entity<ReportFindingTypeUserSettings>().HasRequired(e => e.RequiredReport)
                .WithMany(e => e.ReportFindingTypeUserSettings);

            modelBuilder.Entity<RequiredReport>().HasMany(e => e.ReportFindingTypeUserSettings)
                .WithRequired(e => e.RequiredReport);

            modelBuilder.Entity<ReportFindingTypeUserSettings>().HasRequired(e => e.RequiredReport)
                .WithMany(e => e.ReportFindingTypeUserSettings);

            modelBuilder.Entity<RequiredReport>().HasMany(e => e.ReportGroupUserSettings)
                .WithRequired(e => e.RequiredReport);

            modelBuilder.Entity<ReportGroupUserSettings>().HasRequired(e => e.RequiredReport)
                .WithMany(e => e.ReportGroupUserSettings);

            modelBuilder.Entity<FindingType>().HasMany(e => e.ReportFindingTypeUserSettings)
                .WithRequired(e => e.FindingType);

            modelBuilder.Entity<ReportSeverityUserSettings>().HasRequired(e => e.RequiredReport)
                .WithMany(e => e.ReportSeverityUserSettings);

            modelBuilder.Entity<RequiredReport>().HasMany(e => e.ReportSeverityUserSettings)
                .WithRequired(e => e.RequiredReport);

            modelBuilder.Entity<ReportStatusUserSettings>().HasRequired(e => e.RequiredReport)
                .WithMany(e => e.ReportStatusUserSettings);

            modelBuilder.Entity<RequiredReport>().HasMany(e => e.ReportStatusUserSettings)
                .WithRequired(e => e.RequiredReport);
        }
    }
}