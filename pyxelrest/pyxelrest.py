"""
Each time the pyxelrest module is imported it will generate xlwings User Defined Functions.
"""
import os
import datetime
import logging
import logging.config
import jinja2
import vba
import swagger_service


def user_defined_functions(services):
    """
    Create xlwings User Defined Functions according to user_defined_functions template.
    :return: A string containing python code with all xlwings UDFs.
    """
    renderer = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), trim_blocks=True)
    renderer.tests['table_result'] = lambda produces: produces and ('application/json' in produces or 'application/msqpack' in produces)
    return renderer.get_template('user_defined_functions.jinja2').render(
        current_utc_time=datetime.datetime.utcnow().isoformat(),
        services=services,
        modified_parameters={value: key for key, value in vba.vba_restricted_keywords.items()}
    )


def generate_user_defined_functions(services):
    """
    Create user_defined_functions.py python file containing generated xlwings User Defined Functions.
    :return: None
    """
    logging.info('Generating user defined functions.')
    with open(os.path.join(os.path.dirname(__file__), 'user_defined_functions.py'), 'w') as generated_file:
        generated_file.write(user_defined_functions(services))

logging.config.fileConfig(os.path.join(os.getenv('APPDATA'), 'pyxelrest', 'logging_configuration.ini'))

services = swagger_service.load_services()
generate_user_defined_functions(services)

logging.info('Expose user defined functions through PyxelRest.')
try:
    from user_defined_functions import *
except Exception:
    logging.warning('Failed to import UDFs relatively to module class. Trying relatively to module folder.')
    # Occurs when calling pyxelrest via xlwings in non-debug mode
    from pyxelrest.user_defined_functions import *


# Uncomment to debug Microsoft Excel UDF calls.
# if __name__ == '__main__':
#     xw.serve()
