namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("UtilityDistribution")]
    public partial class UtilityDistribution
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long UtilityDistribution_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string SCADA { get; set; }

        [Required]
        [StringLength(5)]
        public string UtilitiesEngineering { get; set; }

        [Required]
        [StringLength(5)]
        public string MeteringAndControl { get; set; }

        [Required]
        [StringLength(5)]
        public string MechanicalMonitoring { get; set; }

        [Required]
        [StringLength(5)]
        public string DamageControlMonitoring { get; set; }
    }
}
