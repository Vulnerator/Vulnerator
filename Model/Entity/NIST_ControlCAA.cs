namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class NIST_ControlCAA
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NIST_Control_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long CAA_ID { get; set; }

        [Key]
        [Column(Order = 2)]
        [StringLength(10)]
        public string LegacyDifficulty { get; set; }

        [Key]
        [Column(Order = 3)]
        [StringLength(25)]
        public string Applicability { get; set; }

        public virtual ControlApplicabilityAssessment ControlApplicabilityAssessment { get; set; }

        public virtual NIST_Control NistControl { get; set; }
    }
}
