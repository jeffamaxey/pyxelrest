import unittest
import testsutils.serviceshandler as serviceshandler
import testsutils.loader as loader
import sys

class PyxelRestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.start_services()
        loader.load('pyxelresttest_authentication_services_configuration.ini')

    @classmethod
    def tearDownClass(cls):
        loader.unload()
        serviceshandler.stop_services()

    @classmethod
    def start_services(cls):
        import testsutils.authenticated_test_service as authenticated_test_service
        import testsutils.authentication_test_service as authentication_test_service
        import testsutils.non_authenticated_test_service as non_authenticated_test_service
        serviceshandler.start_services((authenticated_test_service, 8946),
                                       (authentication_test_service, 8947),
                                       (non_authenticated_test_service, 8948)
                                       )

    def test_authentication_on_custom_server_port(self):
        import pyxelrestgenerator
        first_token = pyxelrestgenerator.authenticated_second_test_get_test_authentication_success()
        # Wait for 1 second and send a second request from another server to the same auth server
        # (should request another token)
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
        self.assertEqual('An error occurred. Please check logs for full details: "User was not authenticated"',
                         pyxelrestgenerator.authenticated_test_get_test_authentication_failure())

    def test_authentication_timeout(self):
        if sys.version_info[0] == 2:
            self.fail('Authentication timeout is not handled in Python 2.7 for now')
        else:
            import pyxelrestgenerator
            self.assertEqual('An error occurred. Please check logs for full details: "User was not authenticated"',
                             pyxelrestgenerator.authenticated_test_get_test_authentication_timeout())

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
