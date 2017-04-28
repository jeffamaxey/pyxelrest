import multiprocessing
import os
import os.path
import shutil
import unittest
from importlib import import_module
import time

try:
    # Python 3
    from importlib import reload
except ImportError:
    # Python 2
    from imp import reload


class PyxelRestTest(unittest.TestCase):
    service_processes = []
    services_config_file_path = os.path.join(os.getenv('APPDATA'),
                                             'pyxelrest',
                                             'configuration',
                                             'services.ini')
    backup_services_config_file_path = os.path.join(os.getenv('APPDATA'),
                                                    'pyxelrest',
                                                    'configuration',
                                                    'services.ini.back')

    @classmethod
    def setUpClass(cls):
        cls.start_services()
        cls._add_test_config()
        reload(import_module('pyxelrestgenerator'))

    @classmethod
    def tearDownClass(cls):
        import authentication
        authentication.stop_servers()
        cls.stop_services()
        cls._add_back_initial_config()

    @classmethod
    def start_services(cls):
        import testsutils.authenticated_test_service as authenticated_test_service
        cls.service_processes.append(multiprocessing.Process(target=authenticated_test_service.start_server, args=(8946,)))
        import testsutils.authentication_test_service as authentication_test_service
        cls.service_processes.append(multiprocessing.Process(target=authentication_test_service.start_server, args=(8947,)))
        import testsutils.non_authenticated_test_service as non_authenticated_test_service
        cls.service_processes.append(multiprocessing.Process(target=non_authenticated_test_service.start_server, args=(8948,)))
        for service_process in cls.service_processes:
            service_process.start()
        time.sleep(5)

    @classmethod
    def stop_services(cls):
        for service_process in cls.service_processes:
            service_process.terminate()
            service_process.join(timeout=0.5)
        cls.service_processes[:] = []

    @classmethod
    def _add_test_config(cls):
        this_dir = os.path.abspath(os.path.dirname(__file__))
        shutil.copyfile(cls.services_config_file_path, cls.backup_services_config_file_path)
        shutil.copyfile(os.path.join(this_dir, 'pyxelresttest_authentication_services_configuration.ini'), cls.services_config_file_path)

    @classmethod
    def _add_back_initial_config(cls):
        shutil.move(cls.backup_services_config_file_path, cls.services_config_file_path)

    def test_authentication_on_custom_server_port(self):
        import pyxelrestgenerator
        first_token = pyxelrestgenerator.authenticated_second_test_get_test_authentication_success()
        # Wait for 1 second and send a second request from another server to the same auth server (should request another token)
        import time
        time.sleep(1)
        second_token = pyxelrestgenerator.authenticated_test_get_test_authentication_success()
        self.assertEqual(first_token[0], ['Bearer'])
        self.assertEqual(second_token[0], ['Bearer'])
        self.assertNotEqual(first_token[1], second_token[1])

    def test_authentication_success(self):
        import pyxelrestgenerator
        first_token = pyxelrestgenerator.authenticated_test_get_test_authentication_success()
        second_token = pyxelrestgenerator.authenticated_test_get_test_authentication_success()
        self.assertEqual(first_token[0], ['Bearer'])
        self.assertEqual(first_token, second_token)

    def test_authentication_failure(self):
        import pyxelrestgenerator
        self.assertEqual('User was not authenticated', pyxelrestgenerator.authenticated_test_get_test_authentication_failure())

    def test_authentication_timeout(self):
        import pyxelrestgenerator
        self.assertEqual('User was not authenticated', pyxelrestgenerator.authenticated_test_get_test_authentication_timeout())

    def test_without_authentication(self):
        import pyxelrestgenerator
        self.assertEqual([
            ['received token'],
            [False]
        ],
            pyxelrestgenerator.non_authenticated_test_get_test_without_auth())

    def test_authentication_expiry(self):
        import pyxelrestgenerator
        first_token = pyxelrestgenerator.authenticated_test_get_test_authentication_success_quick_expiry()
        second_token = pyxelrestgenerator.authenticated_test_get_test_authentication_success_quick_expiry()
        self.assertEqual(first_token[0], ['Bearer'])
        self.assertEqual(second_token[0], ['Bearer'])
        self.assertNotEqual(first_token[1], second_token[1])
