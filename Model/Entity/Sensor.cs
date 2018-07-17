namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class Sensor
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Sensor_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string RADAR { get; set; }

        [Required]
        [StringLength(5)]
        public string Acoustic { get; set; }

        [Required]
        [StringLength(5)]
        public string VisualAndImaging { get; set; }

        [Required]
        [StringLength(5)]
        public string RemoteVehicle { get; set; }

        [Required]
        [StringLength(5)]
        public string PassiveElectronicWarfare { get; set; }

        [Required]
        [StringLength(5)]
        public string ISR { get; set; }

        [Required]
        [StringLength(5)]
        public string National { get; set; }

        [Required]
        [StringLength(5)]
        public string NavigationAndControl { get; set; }
    }
}
