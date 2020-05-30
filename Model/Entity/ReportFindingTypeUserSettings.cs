namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;
    
    public class ReportFindingTypeUserSettings
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public ReportFindingTypeUserSettings()
        { }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ReportFindingTypeUserSettings_ID { get; set; }
        
        [Required]
        public long RequiredReport_ID { get; set; }
        
        [Required]
        public virtual RequiredReport RequiredReport { get; set; }
        
        [Required]
        public long FindingType_ID { get; set; }
        
        [Required]
        public virtual FindingType FindingType { get; set; }

        [Required]
        [StringLength(50)]
        public string UserName { get; set; }
    }
}