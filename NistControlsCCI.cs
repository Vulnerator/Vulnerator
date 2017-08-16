namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class NistControlsCCI
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long NIST_Control_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long CCI_ID { get; set; }

        [StringLength(10)]
        public string DOD_AssessmentProcedureMapping { get; set; }

        [Key]
        [Column(Order = 2)]
        [StringLength(25)]
        public string ControlIndicator { get; set; }

        [Key]
        [Column(Order = 3)]
        [StringLength(1000)]
        public string ImplementationGuidance { get; set; }

        [Key]
        [Column(Order = 4)]
        [StringLength(1000)]
        public string AssessmentProcedureText { get; set; }

        public virtual CCI CCI { get; set; }

        public virtual NistControl NistControl { get; set; }
    }
}
