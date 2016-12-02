# Access REST APIs from Excel using User Defined Functions (UDF)

## Requirements

- [Python 3.6](https://www.python.org/ftp/python/3.6.0/python-3.6.0b4-amd64.exe) (at least) must be installed
- Within Excel, "Trust access to the VBA project object model" should be enabled

    > File > Options > Trust Center > Trust Center Settings > Macro Settings

- The following python modules must be installed:

    - [pywin32](https://sourceforge.net/projects/pywin32/) should be downloaded from http://www.lfd.uci.edu/~gohlke/pythonlibs/#pywin32

    And installed thanks to the following command:

            pip install pywin32-220.1-cp36-cp36m-win_amd64.whl

    - [xlwings](https://www.xlwings.org/)
    - [requests](http://docs.python-requests.org/en/master/)
    - [pandas](http://pandas.pydata.org/)

    Thanks to the following command executed from within src\main\python folder:

            pip install -e . --trusted-host rms.gdfsuez.net --index http://rms.gdfsuez.net:8310/artifactory/api/pypi/python3/simple

- PathToXlWingsBasFile environment variable must be set to the path of xlwings.bas

    - You can retrieve this path thanks to the following python code:

            import xlwings
            print(xlwings.__path__[0])

- Update xlwings.bas Settings function:

        PYTHON_WIN = "path\to\your\local\environment\Scripts\pythonw.exe"
        PYTHONPATH = "path\to\the\pyxelrest\module\folder"
        UDF_MODULES = "pyxelrest"

- XLWings Excel Add In must be installed

        xlwings addin install

- Auto Load PyxelRest Excel Add In must be installed

    > VSTO file is generated by AutoLoadPyxelRestAddIn project
