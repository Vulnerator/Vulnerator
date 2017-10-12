namespace Vulnerator.Model.Entity
{
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class CombatSystem
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.None)]
        public long CombatSystem_ID { get; set; }

        [Required]
        [StringLength(5)]
        public string CommandAndControl { get; set; }

        [Required]
        [StringLength(5)]
        public string CombatIdentification { get; set; }

        [Required]
        [StringLength(5)]
        public string RealTimeTrackManagement { get; set; }

        [Required]
        [StringLength(5)]
        public string ForceOrders { get; set; }

        [Required]
        [StringLength(5)]
        public string TroopMovement { get; set; }

        [Required]
        [StringLength(5)]
        public string EngagementCoordination { get; set; }
    }
}
