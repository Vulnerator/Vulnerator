namespace Vulnerator.Model.Entity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class ScapScore
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long SCAP_Score_ID { get; set; }

        public long Score { get; set; }

        public long Hardware_ID { get; set; }

        public long Finding_Source_File_ID { get; set; }

        public long Vulnerability_Source_ID { get; set; }

        public DateTime Scan_Date { get; set; }

        public virtual Hardware Hardware { get; set; }

        public virtual VulnerabilitySource VulnerabilitySource { get; set; }
    }
}
