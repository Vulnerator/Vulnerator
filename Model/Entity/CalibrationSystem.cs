namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class CalibrationSystem
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Calibration_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string BuiltInCalibration { get; set; }

        [Required]
        [StringLength(5)]
        public string PortableCalibration { get; set; }
    }
}
