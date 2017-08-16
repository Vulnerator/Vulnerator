namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class SpecialPurposeConsole
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SpecialPurposeConsole_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string WarFighting { get; set; }

        [Required]
        [StringLength(5)]
        public string InputOutputConsole { get; set; }
    }
}
