namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class Building
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Building_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string RealTimeAccessControl { get; set; }

        [Required]
        [StringLength(5)]
        public string HVAC { get; set; }

        [Required]
        [StringLength(5)]
        public string RealTimeSecurityMonitoring { get; set; }
    }
}
