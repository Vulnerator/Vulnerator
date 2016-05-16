using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    public class Files : BaseInpc
    {
        private string _fileName
        {
            get;
            set;
        }
        public string FileName
        {
            get { return _fileName; }
            set
            {
                if (_fileName != value)
                {
                    _fileName = value;
                    OnPropertyChanged("FileName");
                }
            }
        }

        private string _fileType
        {
            get;
            set;
        }
        public string FileType
        {
            get { return _fileType; }
            set
            {
                if (_fileType != value)
                {
                    _fileType = value;
                    OnPropertyChanged("FileType");
                }
            }
        }

        private string _fileSystemName
        {
            get;
            set;
        }
        public string FileSystemName
        {
            get { return _fileSystemName; }
            set
            {
                if (_fileSystemName != value)
                {
                    _fileSystemName = value;
                    OnPropertyChanged("FileSystemName");
                }
            }
        }

        private string _status
        {
            get;
            set;
        }
        public string Status
        {
            get { return _status; }
            set
            {
                if (_status != value)
                {
                    _status = value;
                    OnPropertyChanged("Status");
                }
            }
        }

        private string _filePath
        {
            get;
            set;
        }
        public string FilePath
        {
            get { return _filePath; }
            set
            {
                if (_filePath != value)
                {
                    _filePath = value;
                    OnPropertyChanged("FilePath");
                }
            }
        }

        public Files(string fileName, string fileType, string status, string fileSystemName, string filePath)
        {
            this._fileName = fileName;
            this._fileType = fileType;
            this._fileSystemName = fileSystemName;
            this._status = status;
            this._filePath = filePath;
        }
    }
}
