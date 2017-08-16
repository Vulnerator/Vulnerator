namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class Hardware_PPS
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Hardware_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long PPS_ID { get; set; }

        [StringLength(5)]
        public string ReportInAccreditation { get; set; }

        [Key]
        [Column(Order = 2)]
        [StringLength(25)]
        public string Discovered_Service { get; set; }

        [StringLength(50)]
        public string Display_Service { get; set; }

        [StringLength(25)]
        public string Direction { get; set; }

        [StringLength(25)]
        public string BoundaryCrossed { get; set; }

        [StringLength(5)]
        public string DoD_Compliant { get; set; }

        [StringLength(25)]
        public string Classification { get; set; }

        public virtual Hardware Hardware { get; set; }

        public virtual PP PP { get; set; }
    }
}
