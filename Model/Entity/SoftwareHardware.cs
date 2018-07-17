namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("SoftwareHardware")]
    public partial class SoftwareHardware
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Software_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Hardware_ID { get; set; }

        [Key]
        [Column(Order = 2)]
        public DateTime Install_Date { get; set; }

        [StringLength(5)]
        public string ReportInAccreditation { get; set; }

        [StringLength(5)]
        public string ApprovedForBaseline { get; set; }

        [StringLength(50)]
        public string BaselineApprover { get; set; }

        public virtual Hardware Hardware { get; set; }

        public virtual Software Software { get; set; }
    }
}
