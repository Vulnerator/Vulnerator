namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class ResearchWeaponsSystem
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ResearchWeaponsSystem_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string RDTE_Network { get; set; }

        [Required]
        [StringLength(5)]
        public string RDTE_ConnectedSystem { get; set; }
    }
}
