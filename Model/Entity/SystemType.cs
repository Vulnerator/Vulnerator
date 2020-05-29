namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class SystemType
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public SystemType()
        { }

        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SystemType_ID { get; set; }

        [Column("SystemType")]
        [Required]
        [StringLength(100)]
        public string System_Type { get; set; }
    }
}
