namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("HardwareLocation")]
    public partial class HardwareLocation
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Hardware_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Location_ID { get; set; }

        [Key]
        [Column(Order = 2)]
        [StringLength(5)]
        public string IsBaselineLocation { get; set; }

        [Key]
        [Column(Order = 3)]
        [StringLength(5)]
        public string IsDeploymentLocation { get; set; }

        [Key]
        [Column(Order = 4)]
        [StringLength(5)]
        public string IsTestLocation { get; set; }

        public virtual Hardware Hardware { get; set; }

        public virtual Location Location { get; set; }
    }
}
