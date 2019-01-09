namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("TacticalSupportDatabases")]
    public partial class TacticalSupportDatabas
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long TacticalSupportDatabase_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string ElectronicWarfare { get; set; }

        [Required]
        [StringLength(5)]
        public string Intelligence { get; set; }

        [Required]
        [StringLength(5)]
        public string Environmental { get; set; }

        [Required]
        [StringLength(5)]
        public string Acoustic { get; set; }

        [Required]
        [StringLength(5)]
        public string Geographic { get; set; }
    }
}
