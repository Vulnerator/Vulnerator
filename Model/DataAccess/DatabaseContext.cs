using Microsoft.EntityFrameworkCore;
using Vulnerator.Model.Object;
using System;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseContext : DbContext
    {
        private static string databasePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private static string databaseFile = databasePath + @"\Vulnerator\Vulnerator.sqlite";
        public DbSet<Group> Groups { get; set; }
        public DbSet<Asset> Assets { get; set; }
        public DbSet<Mitigation> Mitigations { get; set; }
        public DbSet<FindingStatus> FindingStatuses { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        { optionsBuilder.UseSqlite(@"Filename=" + databaseFile); }
    }
}
