namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("CustomTestCases")]
    public partial class CustomTestCas
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public CustomTestCas()
        {
            SAPs = new HashSet<SAP>();
        }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long CustomTestCase_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string TestCaseName { get; set; }

        [Required]
        [StringLength(500)]
        public string TestCaseDescription { get; set; }

        [Required]
        [StringLength(500)]
        public string TestCaseBackground { get; set; }

        [Required]
        [StringLength(25)]
        public string TestCaseClassification { get; set; }

        [Required]
        [StringLength(25)]
        public string TestCaseSeverity { get; set; }

        [Required]
        [StringLength(500)]
        public string TestCaseAssessmentProcedure { get; set; }

        [Required]
        [StringLength(25)]
        public string TestCase_CCI { get; set; }

        [Required]
        [StringLength(25)]
        public string TestCase_NIST_Control { get; set; }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SAP> SAPs { get; set; }
    }
}
