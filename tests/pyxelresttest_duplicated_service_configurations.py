import unittest
import testsutils.serviceshandler as serviceshandler
import testsutils.loader as loader

import pyxelrest


class PyxelRestDuplicatedServiceConfigurationTest(unittest.TestCase):
    def setUp(self):
        from testsutils import usual_parameters_service
        serviceshandler.start_services((usual_parameters_service, 8943))

    def tearDown(self):
        serviceshandler.stop_services()

    def test_without_service_configuration_file(self):
        try:
            loader.load('pyxelresttest_duplicated_service_configuration.ini')
        except Exception as e:
            self.assertEqual(str(e), "While reading from '{0}' [line  5]: section 'usual_parameters' already exists".format(
                pyxelrest.SERVICES_CONFIGURATION_FILE_PATH.replace('\\', '\\\\')))


if __name__ == '__main__':
    unittest.main()
