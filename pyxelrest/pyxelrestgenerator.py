"""
Each time this module is loaded (and GENERATE_UDF_ON_IMPORT is True) it will generate xlwings User Defined Functions.
"""
import os
import jinja2
import logging.config
import logging.handlers
import datetime
from importlib import import_module
from builtins import open
from pyxelrest import (
    vba,
    authentication,
    swagger,
    _version,
    GENERATE_UDF_ON_IMPORT,
    custom_logging
)


def user_defined_functions(loaded_services, flattenize=True):
    """
    Create xlwings User Defined Functions according to user_defined_functions template.
    :return: A string containing python code with all xlwings UDFs.
    """
    renderer = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.dirname(__file__), encoding="utf-8"),
        trim_blocks=True,
        lstrip_blocks=True
    )
    return renderer.get_template('user_defined_functions.jinja2').render(
        current_utc_time=datetime.datetime.utcnow().isoformat(),
        services=loaded_services,
        modified_parameters={value: key for key, value in vba.vba_restricted_keywords.items()},
        support_pandas=swagger.support_pandas(),
        support_ujson=support_ujson(),
        authentication=authentication,
        flattenize=flattenize
    )


def support_ujson():
    try:
        import ujson
        return True
    except:
        return False


def generate_user_defined_functions(output='user_defined_functions.py', flattenize=True):
    """
    Load services and create user_defined_functions.py python file containing generated xlwings User Defined Functions.
    :param flattenize: Set to False if you want the JSON dictionary as result of your UDF call.
    :return: None
    """
    services = swagger.load_services()
    logging.debug('Generating user defined functions.')
    with open(os.path.join(os.path.dirname(__file__), output), 'w', encoding='utf-8') \
            as generated_file:
        generated_file.write(user_defined_functions(services, flattenize))


def load_user_defined_functions():
    import_module('pyxelrest.user_defined_functions')


def reset_authentication():
    authentication.security_definitions = {}
    authentication.custom_authentications = {}


if __name__ == '__main__':
    logger = logging.getLogger("pyxelrest.pyxelrestgenerator")
else:
    logger = logging.getLogger(__name__)

if GENERATE_UDF_ON_IMPORT:
    custom_logging.load_logging_configuration()
    reset_authentication()
    try:
        generate_user_defined_functions()
    except Exception as e:
        logger.exception('Cannot generate user defined functions.')
        raise

    try:
        logger.debug('Expose user defined functions through PyxelRest.')
        load_user_defined_functions()
        from pyxelrest.user_defined_functions import *
    except:
        logger.exception('Error while importing UDFs.')

# Uncomment to debug Microsoft Excel UDF calls.
# if __name__ == '__main__':
#      xw.serve()
