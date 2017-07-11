import os
import sys
import platform
import logging.config
import logging.handlers

from pyxelrest import _version
from pyxelrest import alert
from distutils import sysconfig

logger = logging.getLogger(__name__)


def my_excepthook(excType, excValue, traceback, logger=logging):
    logger.error("Logging an uncaught exception",
                 exc_info=(excType, excValue, traceback))
    alert.message_box("Python Error", str(excValue))

sys.excepthook = my_excepthook


def load_logging_configuration():
    """
    Load YAML logging configuration from %APPDATA%\pyxelrest\configuration\logging.ini
    If file is not found, then logging will be performed as INFO into %APPDATA%\pyxelrest\logs\pyxelrest.log
    and file will be rolled every day.
    :return: None
    """
    logging_configuration_file_path = os.path.join(os.getenv('APPDATA'), 'pyxelrest', 'configuration', 'logging.ini')
    if os.path.isfile(logging_configuration_file_path):
        # Only consider YAML as mandatory  in case a specific user logging configuration is provided.
        import yaml
        with open(logging_configuration_file_path, 'r') as config_file:
             log_config_dict = yaml.load(config_file)
             logging.config.dictConfig(log_config_dict)
             logger.info('Loading PyxelRest: {} Python: {} OS: {} Lib: {}'.format(
                 _version.__version__, sys.version, platform.platform(), sysconfig.get_python_lib()))
    else:
        set_file_logger('pyxelrest')
        logger.warning('Logging configuration file ({0}) cannot be found. Using default logging configuration.'.format(
            logging_configuration_file_path))


def set_file_logger(filename, level=logging.INFO):
    default_log_file_path = os.path.join(os.getenv('APPDATA'), 'pyxelrest', 'logs', filename + '.log')
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(process)d:%(thread)d - %(filename)s:%(lineno)d - %(message)s',
        handlers=[logging.handlers.TimedRotatingFileHandler(default_log_file_path, when='D')],
        level=level)
    logger.info('Loading PyxelRest: {} Python: {} OS: {} Lib: {}'.format(
        _version.__version__, sys.version, platform.platform(), sysconfig.get_python_lib()))


def set_syslog_logger(host, port, level):
    handler = logging.handlers.SysLogHandler(address=(host, port))
    formatter = logging.Formatter('%(levelname)s - %(process)d:%(thread)d - %(filename)s:%(lineno)d - %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(level)
    logging.getLogger().addHandler(handler)


class StreamToLogger(object):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """

    def __init__(self, logger, log_level=logging.INFO):
        self.logger = logger
        self.log_level = log_level

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.log_level, line.rstrip())

    def flush(self):
        pass
