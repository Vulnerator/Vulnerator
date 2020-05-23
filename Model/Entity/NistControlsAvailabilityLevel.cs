namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class NistControlsAvailabilityLevel
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NIST_Control_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AvailabilityLevel_ID { get; set; }

        [Key]
        [Column(Order = 2)]
        [StringLength(10)]
        public string NSS_Systems_Only { get; set; }

        public virtual AvailabilityLevel AvailabilityLevel { get; set; }

        public virtual NistControl NistControl { get; set; }
    }
}
