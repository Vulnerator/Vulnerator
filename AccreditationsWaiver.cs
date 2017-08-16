namespace Vulnerator
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class AccreditationsWaiver
    {
        [Key]
        [Column(Order = 0)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Accreditation_ID { get; set; }

        [Key]
        [Column(Order = 1)]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long Waiver_ID { get; set; }

        [Key]
        [Column(Order = 2)]
        public DateTime WaiverGrantedDate { get; set; }

        [Key]
        [Column(Order = 3)]
        public DateTime WaiverExpirationDate { get; set; }

        public virtual Accreditation Accreditation { get; set; }

        public virtual Waiver Waiver { get; set; }
    }
}
