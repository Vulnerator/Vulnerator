namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class SystemCategorizationInformationType
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SystemCategorizationInformationType_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SystemCategorization_ID { get; set; }

        [Key]
        [Column(Order = 2)]
        [StringLength(500)]
        public string Description { get; set; }

        [Key]
        [Column(Order = 3)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long InformationType_ID { get; set; }

        [Key]
        [Column(Order = 4)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long ImpactAdjustment_ID { get; set; }

        public virtual InformationType InformationType { get; set; }

        public virtual SystemCategorization SystemCategorization { get; set; }
        
        public virtual ImpactAdjustment ImpactAdjustment { get; set; }
    }
}
