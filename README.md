# Access REST APIs from Excel using User Defined Functions (UDF)

## Client Requirements

- Python >= 3.6 must be installed

    - You can download it from https://www.python.org/ftp/python/3.6.0/python-3.6.0b4-amd64.exe

- Within Excel, enable "Trust access to the VBA project object model"

    > File > Options > Trust Center > Trust Center Settings > Macro Settings

- XLWings Excel Add In must be installed

    > xlwings addin install

The following steps should be performed thanks to a script:
- The following python modules must be installed:

    - pywin32
    - xlwings
    - requests
    - pandas

- Update default configuration: To be explained here
- Install Auto Load XLWings Excel AddIn: To be explained here

## Development setup

The following commands should be executed within the project folder:

    python -m venv env
    cd env\Scripts
    activate.bat
    cd ..\..\src\main\python
    pip install -e . --trusted-host rms.gdfsuez.net --index http://rms.gdfsuez.net:8310/artifactory/api/pypi/python/simple

### PyCharm setup

In case your IDE is PyCharm, you will need to add a local virtual environment to your project.

    Settings > Project > Python Interpreter > Add local

And then specify your python executable in env\Scripts
