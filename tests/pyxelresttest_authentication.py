import unittest
import testsutils.serviceshandler as serviceshandler
import testsutils.loader as loader
import sys


class PyxelRestAuthenticationTest(unittest.TestCase):
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
        from testsutils import (
            authenticated_test_service,
            oauth2_authentication_test_service,
            non_authenticated_test_service
        )
        serviceshandler.start_services(
            (authenticated_test_service, 8946),
            (oauth2_authentication_test_service, 8947),
            (non_authenticated_test_service, 8948)
        )

    def test_oauth2_authentication_on_custom_server_port(self):
        import pyxelrestgenerator
        first_token = pyxelrestgenerator.authenticated_second_test_get_test_oauth2_authentication_success()
        self.assertEqual(first_token[0], ['Bearer'])
        # Wait for 1 second and send a second request from another server to the same auth server
        # (should request another token)
        import time
        time.sleep(1)
        second_token = pyxelrestgenerator.authenticated_test_get_test_oauth2_authentication_success()
        self.assertEqual(second_token[0], ['Bearer'])
        self.assertNotEqual(first_token[1], second_token[1])

    def test_oauth2_authentication_success(self):
        import pyxelrestgenerator
        first_token = pyxelrestgenerator.authenticated_test_get_test_oauth2_authentication_success()
        self.assertEqual(first_token[0], ['Bearer'])
        second_token = pyxelrestgenerator.authenticated_test_get_test_oauth2_authentication_success()
        self.assertEqual(first_token, second_token)

    def test_oauth2_authentication_failure(self):
        import pyxelrestgenerator
        self.assertEqual('An error occurred. Please check logs for full details: "User was not authenticated."',
                         pyxelrestgenerator.authenticated_test_get_test_oauth2_authentication_failure())

    def test_oauth2_authentication_timeout(self):
        import pyxelrestgenerator
        self.assertEqual('An error occurred. Please check logs for full details: "User was not authenticated."',
                         pyxelrestgenerator.authenticated_test_get_test_oauth2_authentication_timeout())

    def test_without_authentication(self):
        import pyxelrestgenerator
        self.assertEqual([
            ['received token'],
            [False]
        ],
            pyxelrestgenerator.non_authenticated_test_get_test_without_auth())

    def test_oauth2_authentication_expiry(self):
        import pyxelrestgenerator
        first_token = pyxelrestgenerator.authenticated_test_get_test_oauth2_authentication_success_quick_expiry()
        self.assertEqual(first_token[0], ['Bearer'])
        second_token = pyxelrestgenerator.authenticated_test_get_test_oauth2_authentication_success_quick_expiry()
        self.assertEqual(second_token[0], ['Bearer'])
        self.assertNotEqual(first_token[1], second_token[1])

    def test_api_key_header_authentication_success(self):
        import pyxelrestgenerator
        self.assertEqual(pyxelrestgenerator.authenticated_test_get_test_api_key_header_authentication_success(),
                         [
                             ['X-API-HEADER-KEY'],
                             ['my_provided_api_key']
                         ])

    def test_api_key_query_authentication_success(self):
        import pyxelrestgenerator
        self.assertEqual(pyxelrestgenerator.authenticated_test_get_test_api_key_query_authentication_success(),
                         [
                             ['X-API-QUERY-KEY'],
                             ['my_provided_api_key']
                         ])

    def test_basic_authentication_success(self):
        import pyxelrestgenerator
        self.assertEqual(pyxelrestgenerator.authenticated_test_get_test_basic_authentication_success(),
                         [
                             ['Authorization'],
                             ['Basic dGVzdF91c2VyOnRlc3RfcHdk']
                         ])

    def test_basic_and_api_key_authentication_success(self):
        import pyxelrestgenerator
        self.assertEqual(pyxelrestgenerator.authenticated_test_get_test_basic_and_api_key_authentication_success(),
                         [
                             ['Authorization', 'X-API-HEADER-KEY'],
                             ['Basic dGVzdF91c2VyOnRlc3RfcHdk', 'my_provided_api_key']
                         ])

    def test_basic_or_api_key_authentication_success(self):
        import pyxelrestgenerator
        self.assertEqual(pyxelrestgenerator.authenticated_test_get_test_basic_or_api_key_authentication_success(),
                         [
                             ['Authorization', 'X-API-HEADER-KEY'],
                             ['Basic dGVzdF91c2VyOnRlc3RfcHdk', '']
                         ])

    def test_api_key_or_basic_authentication_success(self):
        import pyxelrestgenerator
        self.assertEqual(pyxelrestgenerator.authenticated_test_get_test_api_key_or_basic_authentication_success(),
                         [
                             ['Authorization', 'X-API-HEADER-KEY'],
                             ['', 'my_provided_api_key']
                         ])

if __name__ == '__main__':
    unittest.main()
