using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class WasspSystem : BaseInpc
    {
        public string AffectedAsset { get; set; }
        public string SystemName { get; set; }
        public string FileName { get; set; }
        public int CatIFindings = 0;
        public int CatIIFindings = 0;
        public int CatIIIFindings = 0;
        public int CatIVFindings = 0;
        public int TotalFindings = 0;

        public WasspSystem(string affectedAsset, string systemName, string fileName, string impact)
        {
            this.AffectedAsset = affectedAsset;
            this.SystemName = systemName;
            this.FileName = fileName;
            switch (impact)
            {
                case "High":
                    { IncreaseCatIAndTotalFindings(); break; }
                case "Medium":
                    { IncreaseCatIIAndTotalFindings(); break; }
                case "Low":
                    { IncreaseCatIIIAndTotalFindings(); break; }
                case "Informational":
                    { IncreaseCatIVAndTotalFindings(); break; }
                default:
                    { break; }
            }
        }

        public void IncreaseCatIAndTotalFindings()
        {
            CatIFindings++;
            TotalFindings++;
        }

        public void IncreaseCatIIAndTotalFindings()
        {
            CatIIFindings++;
            TotalFindings++;
        }

        public void IncreaseCatIIIAndTotalFindings()
        {
            CatIIIFindings++;
            TotalFindings++;
        }

        public void IncreaseCatIVAndTotalFindings()
        {
            CatIVFindings++;
            TotalFindings++;
        }
    }
}
