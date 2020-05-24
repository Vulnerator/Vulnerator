using System.ComponentModel;

namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class PIT_Determination : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public PIT_Determination()
        {
            Groups = new HashSet<Group>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PIT_Determination_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string RecievesInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string TransmitsInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string ProcessesInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string StoresInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string DisplaysInfo { get; set; }

        [Required]
        [StringLength(5)]
        public string EmbeddedInSpecialPurpose { get; set; }

        [Required]
        [StringLength(5)]
        public string IsDedicatedSpecialPurposeSystem { get; set; }

        [Required]
        [StringLength(5)]
        public string IsEssentialSpecialPurposeSystem { get; set; }

        [Required]
        [StringLength(5)]
        public string PerformsGeneralServices { get; set; }
        
        [StringLength(5)]
        public string IsFireControlOrTargetingSystem { get; set; }
        
        [StringLength(5)]
        public string IsMissileSystem { get; set; }
        
        [StringLength(5)]
        public string IsGunSystem { get; set; }
        
        [StringLength(5)]
        public string IsTorpedo { get; set; }
        
        [StringLength(5)]
        public string IsActiveElectronicsWarfareSystem { get; set; }
        
        [StringLength(5)]
        public string IsLauncher { get; set; }
        
        [StringLength(5)]
        public string IsDecoySystem { get; set; }
        
        [StringLength(5)]
        public string IsVehicle { get; set; }
        
        [StringLength(5)]
        public string IsTank { get; set; }
        
        [StringLength(5)]
        public string IsArtillery { get; set; }
        
        [StringLength(5)]
        public string IsManDeployableWeapon { get; set; }
        
        [StringLength(5)]
        public string IsFlightSimulator { get; set; }
        
        [StringLength(5)]
        public string IsBridgeSimulator { get; set; }
        
        [StringLength(5)]
        public string IsClassroomNetworkOther { get; set; }
        
        [StringLength(5)]
        public string IsEmbeddedTacticalTrainerAndSimulator { get; set; }
        
        [StringLength(5)]
        public string IsBuiltInTestOrMaintenanceEquipment { get; set; }
        
        [StringLength(5)]
        public string IsPortableTestOrMaintenanceEquipment { get; set; }
        
        [StringLength(5)]
        public string IsBuiltInCalibrationEquipment { get; set; }
        
        [StringLength(5)]
        public string IsPortableCalibrationEquipment { get; set; }
        
        [StringLength(5)]
        public string IsRDTE_Network { get; set; }
        
        [StringLength(5)]
        public string IsRDTE_SystemConnectedToRDTE_Network { get; set; }
        
        [StringLength(5)]
        public string IsMedicalImaging { get; set; }
        
        [StringLength(5)]
        public string IsMedicalMonitoring { get; set; }
        
        [StringLength(5)]
        public string IsShipOrAircraftControlSystem { get; set; }
        
        [StringLength(5)]
        public string IsIntegratedBridgeSystem { get; set; }
        
        [StringLength(5)]
        public string IsElectronicChart { get; set; }
        
        [StringLength(5)]
        public string IsGPS { get; set; }
        
        [StringLength(5)]
        public string IsWSN { get; set; }
        
        [StringLength(5)]
        public string IsInterialNavigation { get; set; }
        
        [StringLength(5)]
        public string IsDeadReckoningDevice { get; set; }
        
        [StringLength(5)]
        public string IsRealTimeAccessControlSystem { get; set; }
        
        [StringLength(5)]
        public string IsHVAC_System { get; set; }
        
        [StringLength(5)]
        public string IsRealTimeSecurityMonitoringSystem { get; set; }
        
        [StringLength(5)]
        public string IsSCADA_System { get; set; }
        
        [StringLength(5)]
        public string IsUtilitiesEngineeringManagement { get; set; }
        
        [StringLength(5)]
        public string IsMeteringAndControl { get; set; }
        
        [StringLength(5)]
        public string IsMechanicalMonitoring { get; set; }
        
        [StringLength(5)]
        public string IsDamageControlMonitoring { get; set; }
        
        [StringLength(5)]
        public string IsVoiceCommunicationSystem { get; set; }
        
        [StringLength(5)]
        public string IsSatelliteCommunitcationSystem { get; set; }
        
        [StringLength(5)]
        public string IsTacticalCommunication { get; set; }
        
        [StringLength(5)]
        public string IsISDN_VTC_System { get; set; }
        
        [StringLength(5)]
        public string IsInterrigatorOrTransponder { get; set; }
        
        [StringLength(5)]
        public string IsCommandAndControlOfForces { get; set; }
        
        [StringLength(5)]
        public string IsCombatIdentificationAndClassification { get; set; }
        
        [StringLength(5)]
        public string IsRealTimeTrackManagement { get; set; }
        
        [StringLength(5)]
        public string IsForceOrders { get; set; }
        
        [StringLength(5)]
        public string IsTroopMovement { get; set; }
        
        [StringLength(5)]
        public string IsEngagementCoordination { get; set; }
        
        [StringLength(5)]
        public string IsWarFightingDisplay { get; set; }
        
        [StringLength(5)]
        public string IsInputOutputConsole { get; set; }
        
        [StringLength(5)]
        public string IsRADAR_System { get; set; }
        
        [StringLength(5)]
        public string IsActiveOrPassiveAcousticSensor { get; set; }
        
        [StringLength(5)]
        public string IsVisualOrImagingSensor { get; set; }
        
        [StringLength(5)]
        public string IsRemoteVehicle { get; set; }
        
        [StringLength(5)]
        public string IsPassiveElectronicWarfareSensor { get; set; }
        
        [StringLength(5)]
        public string IsISR_Sensor { get; set; }
        
        [StringLength(5)]
        public string IsNationalSensor { get; set; }
        
        [StringLength(5)]
        public string IsNavigationAndControlSensor { get; set; }
        
        [StringLength(5)]
        public string IsElectronicWarfare { get; set; }
        
        [StringLength(5)]
        public string IsIntelligence { get; set; }
        
        [StringLength(5)]
        public string IsEnvironmental { get; set; }
        
        [StringLength(5)]
        public string IsAcoustic { get; set; }
        
        [StringLength(5)]
        public string IsGeographic { get; set; }

        [StringLength(5)]
        public string IsTacticalDecisionAid { get; set; }

        [StringLength(100)]
        public string OtherSystemTypeDescription { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<Group> Groups { get; set; }
    }
}
