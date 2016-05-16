namespace Vulnerator.Model
{
    public class StigSystem
    {
        public string AffectedAsset { get; set; }
        public string SystemName { get; set; }
        public string FileName { get; set; }
        public int CatIFindings = 0;
        public int CatIIFindings = 0;
        public int CatIIIFindings = 0;
        public int CatIVFindings = 0;
        public int TotalFindings = 0;

        public StigSystem(string affectedAsset, string systemName, string fileName, string stigSeverity)
        {
            this.AffectedAsset = affectedAsset;
            this.SystemName = systemName;
            this.FileName = fileName;
            switch (stigSeverity)
            {
                case "I":
                    { IncreaseCatIAndTotalFindings(); break; }
                case "II":
                    { IncreaseCatIIAndTotalFindings(); break; }
                case "III":
                    { IncreaseCatIIIAndTotalFindings(); break; }
                case "IV":
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
