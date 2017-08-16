namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class TrainingSimulationSystem
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long TrainingSimulation_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string FlightSimulator { get; set; }

        [Required]
        [StringLength(5)]
        public string BridgeSimulator { get; set; }

        [Required]
        [StringLength(5)]
        public string ClassroomNetworkOther { get; set; }

        [Required]
        [StringLength(5)]
        public string EmbeddedTactical { get; set; }
    }
}
