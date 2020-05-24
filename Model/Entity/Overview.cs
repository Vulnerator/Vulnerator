namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    [Table("Overview")]
    public partial class Overview
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Overview_ID { get; set; }

        [Required]
        [StringLength(25)]
        public string RegistrationType { get; set; }

        public long InformationSystemOwner_ID { get; set; }

        public long SystemType_ID { get; set; }

        [StringLength(100)]
        public string DVS_Site { get; set; }
        
        public virtual Contact InformationSystemOwner { get; set; }

        public virtual SystemType SystemType { get; set; }
    }
}
