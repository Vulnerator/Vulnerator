namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class AccreditationsNistControl
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long AccreditationsNistControls_ID { get; set; }

        public long Accreditation_ID { get; set; }

        public long NIST_Control_ID { get; set; }

        [StringLength(5)]
        public string IsInherited { get; set; }

        [StringLength(50)]
        public string InheritedFrom { get; set; }

        [StringLength(5)]
        public string Inheritable { get; set; }

        [StringLength(25)]
        public string ImplementationStatus { get; set; }

        [StringLength(500)]
        public string ImplementationNotes { get; set; }

        public virtual Accreditation Accreditation { get; set; }

        public virtual NistControl NistControl { get; set; }
    }
}
