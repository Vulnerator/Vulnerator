namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("Business")]
    public partial class Business
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Business_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string MissionCriticality { get; set; }

        [Required]
        [StringLength(25)]
        public string GoverningMissionArea { get; set; }

        [Required]
        [StringLength(25)]
        public string DOD_Component { get; set; }

        [Required]
        [StringLength(25)]
        public string ACQ_Category { get; set; }

        [Required]
        [StringLength(25)]
        public string ACQ_Phase { get; set; }

        [Required]
        [StringLength(25)]
        public string SoftwareCategory { get; set; }

        [Required]
        [StringLength(50)]
        public string SystemOwnershipAndControl { get; set; }

        [StringLength(2000)]
        public string OtherInformation { get; set; }
    }
}
