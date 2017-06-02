using Vulnerator.ViewModel;
using GalaSoft.MvvmLight;

namespace Vulnerator.Model.Object
{
    public class File : ViewModelBase
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
                    RaisePropertyChanged("FileName");
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
                    RaisePropertyChanged("FileType");
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
                    RaisePropertyChanged("FileSystemName");
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
                    RaisePropertyChanged("Status");
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
                    RaisePropertyChanged("FilePath");
                }
            }
        }

        private string _hostNameProvided
        {
            get;
            set;
        }
        public string HostNameProvided
        {
            get { return _hostNameProvided; }
            set
            {
                if (_hostNameProvided != value)
                {
                    _hostNameProvided = value;
                    RaisePropertyChanged("HostNameProvided");
                }
            }
        }

        public File(string fileName, string fileType, string status, string fileSystemName, string filePath, string hostNameProvided)
        {
            _fileName = fileName;
            _fileType = fileType;
            _fileSystemName = fileSystemName;
            _status = status;
            _filePath = filePath;
            _hostNameProvided = hostNameProvided;
        }
    }
}
