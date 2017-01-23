import unittest
import os
import shutil
import datetime


# Test cases requires test_service to run prior to execution
class PyxelRestTest(unittest.TestCase):
    def setUp(self):
        self._add_config()
        import pyxelrest

    def tearDown(self):
        self._add_back_initial_config()

    def test_generated_file(self):
        """
        Assert content of generated file.
        This test is mainly here to be aware that a change broke generated file.
        """
        expected_file = open(os.path.join(os.path.dirname(__file__),
                                          'test_service_user_defined_functions.py'), 'r')
        expected = expected_file.readlines()
        expected_file.close()
        actual_file = open(os.path.join(os.path.dirname(__file__),
                                        r'..\pyxelrest\user_defined_functions.py'), 'r')
        actual = actual_file.readlines()
        actual_file.close()
        self.assertEqual(actual[:3], expected[:3])
        self.assertRegexpMatches(actual[3], expected[3])
        # PyCharm may rstrip lines without asking...
        self.assertEqual([line.rstrip() for line in actual[4:]], [line.rstrip() for line in expected[4:]])

    def test_mandatory_integer_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=None,
                                                                                query_integer32=None,
                                                                                query_integer64=None,
                                                                                query_number=None,
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_integer is required.'])

    def test_mandatory_integer_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer='str value',
                                                                                query_integer32=None,
                                                                                query_integer64=None,
                                                                                query_number=None,
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_integer must be an integer.'])

    def test_optional_integer_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_integer='str value'),
                         ['query_integer must be an integer.'])

    def test_mandatory_array_integer_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer is required.'])

    def test_mandatory_array_integer_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[],
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer is required.'])

    def test_mandatory_array_integer_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[None],
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer is required.'])

    def test_mandatory_array_integer_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer='str value',
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer must be an integer.'])

    def test_mandatory_array_integer_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=['str value'],
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer must contain integers.'])

    def test_optional_array_integer_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_integer='str value'),
                         ['query_array_integer must be an integer.'])

    def test_optional_array_integer_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_integer=['str value']
        ),
            ['query_array_integer must contain integers.'])

    def test_mandatory_integer32_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=None,
                                                                                query_integer64=None,
                                                                                query_number=None,
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_integer32 is required.'])

    def test_mandatory_integer32_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32='str value',
                                                                                query_integer64=None,
                                                                                query_number=None,
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_integer32 must be an integer.'])

    def test_optional_integer32_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_integer32='str value'),
                         ['query_integer32 must be an integer.'])

    def test_mandatory_array_integer32_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer32 is required.'])

    def test_mandatory_array_integer32_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[],
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer32 is required.'])

    def test_mandatory_array_integer32_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[None],
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer32 is required.'])

    def test_mandatory_array_integer32_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32='str value',
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer32 must be an integer.'])

    def test_mandatory_array_integer32_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=['str value'],
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer32 must contain integers.'])

    def test_optional_array_integer32_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_integer32='str value'),
                         ['query_array_integer32 must be an integer.'])

    def test_optional_array_integer32_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_integer32=['str value']),
                         ['query_array_integer32 must contain integers.'])

    def test_mandatory_integer64_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=None,
                                                                                query_number=None,
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_integer64 is required.'])

    def test_mandatory_integer64_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64='str value',
                                                                                query_number=None,
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_integer64 must be an integer.'])

    def test_optional_integer64_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_integer64='str value'),
                         ['query_integer64 must be an integer.'])

    def test_mandatory_array_integer64_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer64 is required.'])

    def test_mandatory_array_integer64_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[],
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer64 is required.'])

    def test_mandatory_array_integer64_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[None],
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer64 is required.'])

    def test_mandatory_array_integer64_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64='str value',
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer64 must be an integer.'])

    def test_mandatory_array_integer64_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=['str value'],
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_integer64 must contain integers.'])

    def test_optional_array_integer64_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_integer64='str value'),
                         ['query_array_integer64 must be an integer.'])

    def test_optional_array_integer64_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_integer64=['str value']),
                         ['query_array_integer64 must contain integers.'])

    def test_mandatory_number_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=None,
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_number is required.'])

    def test_mandatory_number_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number='str value',
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_number must be a number.'])

    def test_optional_number_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_number='str value'),
                         ['query_number must be a number.'])

    def test_mandatory_array_number_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_number is required.'])

    def test_mandatory_array_number_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[],
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_number is required.'])

    def test_mandatory_array_number_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[None],
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_number is required.'])

    def test_mandatory_array_number_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number='str value',
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_number must be a number.'])

    def test_mandatory_array_number_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=['str value'],
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_number must contain numbers.'])

    def test_optional_array_number_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_number='str value'),
                         ['query_array_number must be a number.'])

    def test_optional_array_number_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_number=['str value']),
                         ['query_array_number must contain numbers.'])

    def test_mandatory_float_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=None,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_float is required.'])

    def test_mandatory_float_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float='str value',
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_float must be a number.'])

    def test_optional_float_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_float='str value'),
                         ['query_float must be a number.'])

    def test_mandatory_array_float_number_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_float is required.'])

    def test_mandatory_array_float_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[],
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_float is required.'])

    def test_mandatory_array_float_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[None],
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_float is required.'])

    def test_mandatory_array_float_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float='str value',
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_float must be a number.'])

    def test_mandatory_array_float_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=['str value'],
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_float must contain numbers.'])

    def test_optional_array_float_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_array_float='str value'),
                         ['query_array_float must be a number.'])

    def test_optional_array_float_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_float=['str value']),
                         ['query_array_float must contain numbers.'])

    def test_mandatory_double_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=None,
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_double is required.'])

    def test_mandatory_double_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double='str value',
                                                                                query_string=None,
                                                                                query_string_byte=None,
                                                                                query_string_binary=None,
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_double must be a number.'])

    def test_optional_double_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_double='str value'),
                         ['query_double must be a number.'])

    def test_mandatory_array_double_number_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_double is required.'])

    def test_mandatory_array_double_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[],
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_double is required.'])

    def test_mandatory_array_double_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[None],
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_double is required.'])

    def test_mandatory_array_double_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double='str value',
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_double must be a number.'])

    def test_mandatory_array_double_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=['str value'],
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_double must contain numbers.'])

    def test_optional_array_double_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_double='str value'),
                         ['query_array_double must be a number.'])

    def test_optional_array_double_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_double=['str value']),
                         ['query_array_double must contain numbers.'])

    def test_mandatory_boolean_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean=None,
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_boolean is required.'])

    def test_mandatory_boolean_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='non boolean',
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_boolean must be either "true" or "false".'])

    def test_optional_boolean_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_boolean='non boolean'),
                         ['query_boolean must be either "true" or "false".'])

    def test_mandatory_array_boolean_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_boolean is required.'])

    def test_mandatory_array_boolean_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=[],
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_boolean is required.'])

    def test_mandatory_array_boolean_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=[None],
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_boolean is required.'])

    def test_mandatory_array_boolean_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean='non boolean',
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_boolean must contain "true" or "false".'])

    def test_mandatory_array_boolean_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['non boolean'],
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_boolean must be either "true" or "false".'])

    def test_optional_array_boolean_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_boolean='non boolean'),
                         ['query_array_boolean must contain "true" or "false".'])

    def test_optional_array_boolean_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_boolean=['non boolean']),
                         ['query_array_boolean must be either "true" or "false".'])

    def test_mandatory_date_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=None,
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_date is required.'])

    def test_mandatory_date_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date='str value',
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_date must be a date.'])

    def test_optional_date_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_date='str value'),
                         ['query_date must be a date.'])

    def test_mandatory_array_date_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_date is required.'])

    def test_mandatory_array_date_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=[],
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_date is required.'])

    def test_mandatory_array_date_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=[None],
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_date is required.'])

    def test_mandatory_array_date_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date='str value',
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_date must be a date.'])

    def test_mandatory_array_date_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=['str value'],
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_date must contain dates.'])

    def test_optional_array_date_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_array_date='str value'),
                         ['query_array_date must be a date.'])

    def test_optional_array_date_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_date=['str value']),
                         ['query_array_date must contain dates.'])

    def test_mandatory_date_time_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=None,
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_date_time is required.'])

    def test_mandatory_date_time_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time='str value',
                                                                                query_password=None,
                                                                                query_array_integer=None,
                                                                                query_array_integer32=None,
                                                                                query_array_integer64=None,
                                                                                query_array_number=None,
                                                                                query_array_float=None,
                                                                                query_array_double=None,
                                                                                query_array_string=None,
                                                                                query_array_string_byte=None,
                                                                                query_array_string_binary=None,
                                                                                query_array_boolean=None,
                                                                                query_array_date=None,
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_date_time must be a date time.'])

    def test_optional_date_time_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(query_date_time='str value'),
                         ['query_date_time must be a date time.'])

    def test_mandatory_array_date_time_parameter_not_provided(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=[datetime.date.today()],
                                                                                query_array_date_time=None,
                                                                                query_array_password=None),
                         ['query_array_date_time is required.'])

    def test_mandatory_array_date_time_parameter_provided_as_empty_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=[datetime.date.today()],
                                                                                query_array_date_time=[],
                                                                                query_array_password=None),
                         ['query_array_date_time is required.'])

    def test_mandatory_array_date_time_parameter_provided_as_none_filled_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=[datetime.date.today()],
                                                                                query_array_date_time=[None],
                                                                                query_array_password=None),
                         ['query_array_date_time is required.'])

    def test_mandatory_array_date_time_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=[datetime.date.today()],
                                                                                query_array_date_time='str value',
                                                                                query_array_password=None),
                         ['query_array_date_time must be a date time.'])

    def test_mandatory_array_date_time_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_parameters_types(query_integer=0,
                                                                                query_integer32=0,
                                                                                query_integer64=0,
                                                                                query_number=0.0,
                                                                                query_float=0.0,
                                                                                query_double=0.0,
                                                                                query_string='str value',
                                                                                query_string_byte='str value',
                                                                                query_string_binary='str value',
                                                                                query_boolean='true',
                                                                                query_date=datetime.date.today(),
                                                                                query_date_time=datetime.datetime.today(),
                                                                                query_password='str value',
                                                                                query_array_integer=[0],
                                                                                query_array_integer32=[0],
                                                                                query_array_integer64=[0],
                                                                                query_array_number=[0.0],
                                                                                query_array_float=[0.0],
                                                                                query_array_double=[0.0],
                                                                                query_array_string=['str value'],
                                                                                query_array_string_byte=['str value'],
                                                                                query_array_string_binary=['str value'],
                                                                                query_array_boolean=['true'],
                                                                                query_array_date=[datetime.date.today()],
                                                                                query_array_date_time=['str value'],
                                                                                query_array_password=None),
                         ['query_array_date_time must contain date times.'])

    def test_optional_array_date_time_parameter_with_wrong_type(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_date_time='str value'),
                         ['query_array_date_time must be a date time.'])

    def test_optional_array_date_time_parameter_with_wrong_type_in_array(self):
        import pyxelrest
        self.assertEqual(pyxelrest.test_get_test_json_with_all_optional_parameters_types(
            query_array_date_time=['str value']),
                         ['query_array_date_time must contain date times.'])

    def _add_config(self):
        config_file_path = os.path.join(os.getenv('APPDATA'), 'pyxelrest', 'services_configuration.ini')
        self.backup_config_file_path = os.path.join(os.getenv('APPDATA'),
                                                    'pyxelrest',
                                                    'services_configuration.ini.back')
        shutil.copyfile(config_file_path, self.backup_config_file_path)
        shutil.copyfile('test_services_configuration.ini', config_file_path)

    def _add_back_initial_config(self):
        config_file_path = os.path.join(os.getenv('APPDATA'), 'pyxelrest', 'services_configuration.ini')
        shutil.move(self.backup_config_file_path, config_file_path)
