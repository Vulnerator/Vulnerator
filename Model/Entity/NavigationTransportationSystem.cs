namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class NavigationTransportationSystem
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public NavigationTransportationSystem()
        {
            PIT_Determination = new HashSet<PIT_Determination>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NavigationSystem_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string ShipAircraftControl { get; set; }

        [Required]
        [StringLength(5)]
        public string IntegratedBridge { get; set; }

        [Required]
        [StringLength(5)]
        public string ElectronicCharts { get; set; }

        [Required]
        [StringLength(5)]
        public string GPS { get; set; }

        [Required]
        [StringLength(5)]
        public string WSN { get; set; }

        [Required]
        [StringLength(5)]
        public string InertialNavigation { get; set; }

        [Required]
        [StringLength(5)]
        public string DeadReckoningDevice { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<PIT_Determination> PIT_Determination { get; set; }
    }
}
