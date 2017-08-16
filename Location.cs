namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class Location
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public Location()
        {
            HardwareLocations = new HashSet<HardwareLocation>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Location_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string Location_Name { get; set; }

        [Required]
        [StringLength(50)]
        public string StreetAddressOne { get; set; }

        [Required]
        [StringLength(50)]
        public string StreeAddressTwo { get; set; }

        [StringLength(25)]
        public string BuildingNumber { get; set; }

        public long? FloorNumber { get; set; }

        public long? RoomNumber { get; set; }

        [StringLength(25)]
        public string City { get; set; }

        [StringLength(25)]
        public string State { get; set; }

        [Required]
        [StringLength(25)]
        public string Country { get; set; }

        public long? ZipCode { get; set; }

        [StringLength(50)]
        public string APO_FPO { get; set; }

        public DateTime? OSS_AccreditationDate { get; set; }

        [StringLength(5)]
        public string IsBaselineLocation_Global { get; set; }

        [StringLength(5)]
        public string IsDeploymentLocation_Global { get; set; }

        [StringLength(5)]
        public string IsTestLocation_Global { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<HardwareLocation> HardwareLocations { get; set; }
    }
}
