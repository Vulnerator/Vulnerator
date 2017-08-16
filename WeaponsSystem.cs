namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class WeaponsSystem
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long WeaponsSystem_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string FireControlAndTargeting { get; set; }

        [Required]
        [StringLength(5)]
        public string Missile { get; set; }

        [Required]
        [StringLength(5)]
        public string Gun { get; set; }

        [Required]
        [StringLength(5)]
        public string Torpedoes { get; set; }

        [Required]
        [StringLength(5)]
        public string ActiveElectronicWarfare { get; set; }

        [Required]
        [StringLength(5)]
        public string Launchers { get; set; }

        [Required]
        [StringLength(5)]
        public string Decoy { get; set; }

        [Required]
        [StringLength(5)]
        public string Vehicles { get; set; }

        [Required]
        [StringLength(5)]
        public string Tanks { get; set; }

        [Required]
        [StringLength(5)]
        public string Artillery { get; set; }

        [Required]
        [StringLength(5)]
        public string ManDeployableWeapons { get; set; }
    }
}
