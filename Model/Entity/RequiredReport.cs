namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class RequiredReport
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Required_Report_ID { get; set; }

        [Required]
        [StringLength(50)]
        public string Report_Name { get; set; }

        [Required]
        [StringLength(25)]
        public string Report_Bound_Property { get; set; }

        [Required]
        [StringLength(10)]
        public string Report_Type { get; set; }

        [Required]
        [StringLength(50)]
        public string Report_Category_ID { get; set; }

        public virtual ReportCategory ReportCategory { get; set; }
    }
}
