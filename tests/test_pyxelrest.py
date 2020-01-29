import datetime
import os
import re

from dateutil.tz import tzutc
import pytest
from responses import RequestsMock

from testsutils import loader


def support_pandas():
    try:
        import pandas

        return True
    except:
        return False


@pytest.fixture
def services(responses: RequestsMock):
    # usual_parameters_service
    responses.add(
        responses.GET,
        url="http://localhost:8943/",
        json={
            "swagger": "2.0",
            "paths": {
                "/with/all/parameters/types": {
                    "get": {
                        "operationId": "get_with_all_parameters_types",
                        "parameters": [
                            {
                                "description": "integer parameter",
                                "in": "query",
                                "name": "query_integer",
                                "required": True,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 parameter",
                                "in": "query",
                                "name": "query_integer32",
                                "required": True,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 parameter",
                                "in": "query",
                                "name": "query_integer64",
                                "required": True,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number parameter",
                                "in": "query",
                                "name": "query_number",
                                "required": True,
                                "type": "number",
                            },
                            {
                                "description": "number float parameter",
                                "in": "query",
                                "name": "query_float",
                                "required": True,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double parameter",
                                "in": "query",
                                "name": "query_double",
                                "required": True,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "query_string",
                                "required": True,
                                "type": "string",
                            },
                            {
                                "description": "string byte parameter",
                                "in": "query",
                                "name": "query_string_byte",
                                "required": True,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary parameter",
                                "in": "query",
                                "name": "query_string_binary",
                                "required": True,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean parameter",
                                "in": "query",
                                "name": "query_boolean",
                                "required": True,
                                "type": "boolean",
                            },
                            {
                                "description": "date parameter",
                                "in": "query",
                                "name": "query_date",
                                "required": True,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time parameter",
                                "in": "query",
                                "name": "query_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password parameter",
                                "in": "query",
                                "name": "query_password",
                                "required": True,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array parameter",
                                "in": "query",
                                "name": "query_array_integer",
                                "required": True,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array parameter",
                                "in": "query",
                                "name": "query_array_integer32",
                                "required": True,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array parameter",
                                "in": "query",
                                "name": "query_array_integer64",
                                "required": True,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array parameter",
                                "in": "query",
                                "name": "query_array_number",
                                "required": True,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array parameter",
                                "in": "query",
                                "name": "query_array_float",
                                "required": True,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array parameter",
                                "in": "query",
                                "name": "query_array_double",
                                "required": True,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "query_array_string",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array parameter",
                                "in": "query",
                                "name": "query_array_string_byte",
                                "required": True,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array parameter",
                                "in": "query",
                                "name": "query_array_string_binary",
                                "required": True,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array parameter",
                                "in": "query",
                                "name": "query_array_boolean",
                                "required": True,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array parameter",
                                "in": "query",
                                "name": "query_array_date",
                                "required": True,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array parameter",
                                "in": "query",
                                "name": "query_array_date_time",
                                "required": True,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array parameter",
                                "in": "query",
                                "name": "query_array_password",
                                "required": True,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "post": {
                        "operationId": "post_with_all_parameters_types",
                        "parameters": [
                            {
                                "description": "integer parameter",
                                "in": "query",
                                "name": "query_integer",
                                "required": True,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 parameter",
                                "in": "query",
                                "name": "query_integer32",
                                "required": True,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 parameter",
                                "in": "query",
                                "name": "query_integer64",
                                "required": True,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number parameter",
                                "in": "query",
                                "name": "query_number",
                                "required": True,
                                "type": "number",
                            },
                            {
                                "description": "number float parameter",
                                "in": "query",
                                "name": "query_float",
                                "required": True,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double parameter",
                                "in": "query",
                                "name": "query_double",
                                "required": True,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "query_string",
                                "required": True,
                                "type": "string",
                            },
                            {
                                "description": "string byte parameter",
                                "in": "query",
                                "name": "query_string_byte",
                                "required": True,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary parameter",
                                "in": "query",
                                "name": "query_string_binary",
                                "required": True,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean parameter",
                                "in": "query",
                                "name": "query_boolean",
                                "required": True,
                                "type": "boolean",
                            },
                            {
                                "description": "date parameter",
                                "in": "query",
                                "name": "query_date",
                                "required": True,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time parameter",
                                "in": "query",
                                "name": "query_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password parameter",
                                "in": "query",
                                "name": "query_password",
                                "required": True,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array parameter",
                                "in": "query",
                                "name": "query_array_integer",
                                "required": True,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array parameter",
                                "in": "query",
                                "name": "query_array_integer32",
                                "required": True,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array parameter",
                                "in": "query",
                                "name": "query_array_integer64",
                                "required": True,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array parameter",
                                "in": "query",
                                "name": "query_array_number",
                                "required": True,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array parameter",
                                "in": "query",
                                "name": "query_array_float",
                                "required": True,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array parameter",
                                "in": "query",
                                "name": "query_array_double",
                                "required": True,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "query_array_string",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array parameter",
                                "in": "query",
                                "name": "query_array_string_byte",
                                "required": True,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array parameter",
                                "in": "query",
                                "name": "query_array_string_binary",
                                "required": True,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array parameter",
                                "in": "query",
                                "name": "query_array_boolean",
                                "required": True,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array parameter",
                                "in": "query",
                                "name": "query_array_date",
                                "required": True,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array parameter",
                                "in": "query",
                                "name": "query_array_date_time",
                                "required": True,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array parameter",
                                "in": "query",
                                "name": "query_array_password",
                                "required": True,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "put": {
                        "operationId": "put_with_all_parameters_types",
                        "parameters": [
                            {
                                "description": "integer parameter",
                                "in": "query",
                                "name": "query_integer",
                                "required": True,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 parameter",
                                "in": "query",
                                "name": "query_integer32",
                                "required": True,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 parameter",
                                "in": "query",
                                "name": "query_integer64",
                                "required": True,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number parameter",
                                "in": "query",
                                "name": "query_number",
                                "required": True,
                                "type": "number",
                            },
                            {
                                "description": "number float parameter",
                                "in": "query",
                                "name": "query_float",
                                "required": True,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double parameter",
                                "in": "query",
                                "name": "query_double",
                                "required": True,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "query_string",
                                "required": True,
                                "type": "string",
                            },
                            {
                                "description": "string byte parameter",
                                "in": "query",
                                "name": "query_string_byte",
                                "required": True,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary parameter",
                                "in": "query",
                                "name": "query_string_binary",
                                "required": True,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean parameter",
                                "in": "query",
                                "name": "query_boolean",
                                "required": True,
                                "type": "boolean",
                            },
                            {
                                "description": "date parameter",
                                "in": "query",
                                "name": "query_date",
                                "required": True,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time parameter",
                                "in": "query",
                                "name": "query_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password parameter",
                                "in": "query",
                                "name": "query_password",
                                "required": True,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array parameter",
                                "in": "query",
                                "name": "query_array_integer",
                                "required": True,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array parameter",
                                "in": "query",
                                "name": "query_array_integer32",
                                "required": True,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array parameter",
                                "in": "query",
                                "name": "query_array_integer64",
                                "required": True,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array parameter",
                                "in": "query",
                                "name": "query_array_number",
                                "required": True,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array parameter",
                                "in": "query",
                                "name": "query_array_float",
                                "required": True,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array parameter",
                                "in": "query",
                                "name": "query_array_double",
                                "required": True,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "query_array_string",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array parameter",
                                "in": "query",
                                "name": "query_array_string_byte",
                                "required": True,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array parameter",
                                "in": "query",
                                "name": "query_array_string_binary",
                                "required": True,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array parameter",
                                "in": "query",
                                "name": "query_array_boolean",
                                "required": True,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array parameter",
                                "in": "query",
                                "name": "query_array_date",
                                "required": True,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array parameter",
                                "in": "query",
                                "name": "query_array_date_time",
                                "required": True,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array parameter",
                                "in": "query",
                                "name": "query_array_password",
                                "required": True,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "delete": {
                        "operationId": "delete_with_all_parameters_types",
                        "parameters": [
                            {
                                "description": "integer parameter",
                                "in": "query",
                                "name": "query_integer",
                                "required": True,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 parameter",
                                "in": "query",
                                "name": "query_integer32",
                                "required": True,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 parameter",
                                "in": "query",
                                "name": "query_integer64",
                                "required": True,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number parameter",
                                "in": "query",
                                "name": "query_number",
                                "required": True,
                                "type": "number",
                            },
                            {
                                "description": "number float parameter",
                                "in": "query",
                                "name": "query_float",
                                "required": True,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double parameter",
                                "in": "query",
                                "name": "query_double",
                                "required": True,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "query_string",
                                "required": True,
                                "type": "string",
                            },
                            {
                                "description": "string byte parameter",
                                "in": "query",
                                "name": "query_string_byte",
                                "required": True,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary parameter",
                                "in": "query",
                                "name": "query_string_binary",
                                "required": True,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean parameter",
                                "in": "query",
                                "name": "query_boolean",
                                "required": True,
                                "type": "boolean",
                            },
                            {
                                "description": "date parameter",
                                "in": "query",
                                "name": "query_date",
                                "required": True,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time parameter",
                                "in": "query",
                                "name": "query_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password parameter",
                                "in": "query",
                                "name": "query_password",
                                "required": True,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array parameter",
                                "in": "query",
                                "name": "query_array_integer",
                                "required": True,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array parameter",
                                "in": "query",
                                "name": "query_array_integer32",
                                "required": True,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array parameter",
                                "in": "query",
                                "name": "query_array_integer64",
                                "required": True,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array parameter",
                                "in": "query",
                                "name": "query_array_number",
                                "required": True,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array parameter",
                                "in": "query",
                                "name": "query_array_float",
                                "required": True,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array parameter",
                                "in": "query",
                                "name": "query_array_double",
                                "required": True,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "query_array_string",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array parameter",
                                "in": "query",
                                "name": "query_array_string_byte",
                                "required": True,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array parameter",
                                "in": "query",
                                "name": "query_array_string_binary",
                                "required": True,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array parameter",
                                "in": "query",
                                "name": "query_array_boolean",
                                "required": True,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array parameter",
                                "in": "query",
                                "name": "query_array_date",
                                "required": True,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array parameter",
                                "in": "query",
                                "name": "query_array_date_time",
                                "required": True,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array parameter",
                                "in": "query",
                                "name": "query_array_password",
                                "required": True,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                },
                "/with/all/optional/parameters/types": {
                    "get": {
                        "operationId": "get_with_all_optional_parameters_types",
                        "parameters": [
                            {
                                "description": "integer parameter",
                                "in": "query",
                                "name": "query_integer",
                                "required": False,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 parameter",
                                "in": "query",
                                "name": "query_integer32",
                                "required": False,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 parameter",
                                "in": "query",
                                "name": "query_integer64",
                                "required": False,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number parameter",
                                "in": "query",
                                "name": "query_number",
                                "required": False,
                                "type": "number",
                            },
                            {
                                "description": "number float parameter",
                                "in": "query",
                                "name": "query_float",
                                "required": False,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double parameter",
                                "in": "query",
                                "name": "query_double",
                                "required": False,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "query_string",
                                "required": False,
                                "type": "string",
                            },
                            {
                                "description": "string byte parameter",
                                "in": "query",
                                "name": "query_string_byte",
                                "required": False,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary parameter",
                                "in": "query",
                                "name": "query_string_binary",
                                "required": False,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean parameter",
                                "in": "query",
                                "name": "query_boolean",
                                "required": False,
                                "type": "boolean",
                            },
                            {
                                "description": "date parameter",
                                "in": "query",
                                "name": "query_date",
                                "required": False,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time parameter",
                                "in": "query",
                                "name": "query_date_time",
                                "required": False,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password parameter",
                                "in": "query",
                                "name": "query_password",
                                "required": False,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array parameter",
                                "in": "query",
                                "name": "query_array_integer",
                                "required": False,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array parameter",
                                "in": "query",
                                "name": "query_array_integer32",
                                "required": False,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array parameter",
                                "in": "query",
                                "name": "query_array_integer64",
                                "required": False,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array parameter",
                                "in": "query",
                                "name": "query_array_number",
                                "required": False,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array parameter",
                                "in": "query",
                                "name": "query_array_float",
                                "required": False,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array parameter",
                                "in": "query",
                                "name": "query_array_double",
                                "required": False,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "query_array_string",
                                "required": False,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array parameter",
                                "in": "query",
                                "name": "query_array_string_byte",
                                "required": False,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array parameter",
                                "in": "query",
                                "name": "query_array_string_binary",
                                "required": False,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array parameter",
                                "in": "query",
                                "name": "query_array_boolean",
                                "required": False,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array parameter",
                                "in": "query",
                                "name": "query_array_date",
                                "required": False,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array parameter",
                                "in": "query",
                                "name": "query_array_date_time",
                                "required": False,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array parameter",
                                "in": "query",
                                "name": "query_array_password",
                                "required": False,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "post": {
                        "operationId": "post_with_all_optional_parameters_types",
                        "parameters": [
                            {
                                "description": "integer parameter",
                                "in": "query",
                                "name": "query_integer",
                                "required": False,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 parameter",
                                "in": "query",
                                "name": "query_integer32",
                                "required": False,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 parameter",
                                "in": "query",
                                "name": "query_integer64",
                                "required": False,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number parameter",
                                "in": "query",
                                "name": "query_number",
                                "required": False,
                                "type": "number",
                            },
                            {
                                "description": "number float parameter",
                                "in": "query",
                                "name": "query_float",
                                "required": False,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double parameter",
                                "in": "query",
                                "name": "query_double",
                                "required": False,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "query_string",
                                "required": False,
                                "type": "string",
                            },
                            {
                                "description": "string byte parameter",
                                "in": "query",
                                "name": "query_string_byte",
                                "required": False,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary parameter",
                                "in": "query",
                                "name": "query_string_binary",
                                "required": False,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean parameter",
                                "in": "query",
                                "name": "query_boolean",
                                "required": False,
                                "type": "boolean",
                            },
                            {
                                "description": "date parameter",
                                "in": "query",
                                "name": "query_date",
                                "required": False,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time parameter",
                                "in": "query",
                                "name": "query_date_time",
                                "required": False,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password parameter",
                                "in": "query",
                                "name": "query_password",
                                "required": False,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array parameter",
                                "in": "query",
                                "name": "query_array_integer",
                                "required": False,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array parameter",
                                "in": "query",
                                "name": "query_array_integer32",
                                "required": False,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array parameter",
                                "in": "query",
                                "name": "query_array_integer64",
                                "required": False,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array parameter",
                                "in": "query",
                                "name": "query_array_number",
                                "required": False,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array parameter",
                                "in": "query",
                                "name": "query_array_float",
                                "required": False,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array parameter",
                                "in": "query",
                                "name": "query_array_double",
                                "required": False,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "query_array_string",
                                "required": False,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array parameter",
                                "in": "query",
                                "name": "query_array_string_byte",
                                "required": False,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array parameter",
                                "in": "query",
                                "name": "query_array_string_binary",
                                "required": False,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array parameter",
                                "in": "query",
                                "name": "query_array_boolean",
                                "required": False,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array parameter",
                                "in": "query",
                                "name": "query_array_date",
                                "required": False,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array parameter",
                                "in": "query",
                                "name": "query_array_date_time",
                                "required": False,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array parameter",
                                "in": "query",
                                "name": "query_array_password",
                                "required": False,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "put": {
                        "operationId": "put_with_all_optional_parameters_types",
                        "parameters": [
                            {
                                "description": "integer parameter",
                                "in": "query",
                                "name": "query_integer",
                                "required": False,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 parameter",
                                "in": "query",
                                "name": "query_integer32",
                                "required": False,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 parameter",
                                "in": "query",
                                "name": "query_integer64",
                                "required": False,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number parameter",
                                "in": "query",
                                "name": "query_number",
                                "required": False,
                                "type": "number",
                            },
                            {
                                "description": "number float parameter",
                                "in": "query",
                                "name": "query_float",
                                "required": False,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double parameter",
                                "in": "query",
                                "name": "query_double",
                                "required": False,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "query_string",
                                "required": False,
                                "type": "string",
                            },
                            {
                                "description": "string byte parameter",
                                "in": "query",
                                "name": "query_string_byte",
                                "required": False,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary parameter",
                                "in": "query",
                                "name": "query_string_binary",
                                "required": False,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean parameter",
                                "in": "query",
                                "name": "query_boolean",
                                "required": False,
                                "type": "boolean",
                            },
                            {
                                "description": "date parameter",
                                "in": "query",
                                "name": "query_date",
                                "required": False,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time parameter",
                                "in": "query",
                                "name": "query_date_time",
                                "required": False,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password parameter",
                                "in": "query",
                                "name": "query_password",
                                "required": False,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array parameter",
                                "in": "query",
                                "name": "query_array_integer",
                                "required": False,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array parameter",
                                "in": "query",
                                "name": "query_array_integer32",
                                "required": False,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array parameter",
                                "in": "query",
                                "name": "query_array_integer64",
                                "required": False,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array parameter",
                                "in": "query",
                                "name": "query_array_number",
                                "required": False,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array parameter",
                                "in": "query",
                                "name": "query_array_float",
                                "required": False,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array parameter",
                                "in": "query",
                                "name": "query_array_double",
                                "required": False,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "query_array_string",
                                "required": False,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array parameter",
                                "in": "query",
                                "name": "query_array_string_byte",
                                "required": False,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array parameter",
                                "in": "query",
                                "name": "query_array_string_binary",
                                "required": False,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array parameter",
                                "in": "query",
                                "name": "query_array_boolean",
                                "required": False,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array parameter",
                                "in": "query",
                                "name": "query_array_date",
                                "required": False,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array parameter",
                                "in": "query",
                                "name": "query_array_date_time",
                                "required": False,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array parameter",
                                "in": "query",
                                "name": "query_array_password",
                                "required": False,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "delete": {
                        "operationId": "delete_with_all_optional_parameters_types",
                        "parameters": [
                            {
                                "description": "integer parameter",
                                "in": "query",
                                "name": "query_integer",
                                "required": False,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 parameter",
                                "in": "query",
                                "name": "query_integer32",
                                "required": False,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 parameter",
                                "in": "query",
                                "name": "query_integer64",
                                "required": False,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number parameter",
                                "in": "query",
                                "name": "query_number",
                                "required": False,
                                "type": "number",
                            },
                            {
                                "description": "number float parameter",
                                "in": "query",
                                "name": "query_float",
                                "required": False,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double parameter",
                                "in": "query",
                                "name": "query_double",
                                "required": False,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "query_string",
                                "required": False,
                                "type": "string",
                            },
                            {
                                "description": "string byte parameter",
                                "in": "query",
                                "name": "query_string_byte",
                                "required": False,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary parameter",
                                "in": "query",
                                "name": "query_string_binary",
                                "required": False,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean parameter",
                                "in": "query",
                                "name": "query_boolean",
                                "required": False,
                                "type": "boolean",
                            },
                            {
                                "description": "date parameter",
                                "in": "query",
                                "name": "query_date",
                                "required": False,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time parameter",
                                "in": "query",
                                "name": "query_date_time",
                                "required": False,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password parameter",
                                "in": "query",
                                "name": "query_password",
                                "required": False,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array parameter",
                                "in": "query",
                                "name": "query_array_integer",
                                "required": False,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array parameter",
                                "in": "query",
                                "name": "query_array_integer32",
                                "required": False,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array parameter",
                                "in": "query",
                                "name": "query_array_integer64",
                                "required": False,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array parameter",
                                "in": "query",
                                "name": "query_array_number",
                                "required": False,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array parameter",
                                "in": "query",
                                "name": "query_array_float",
                                "required": False,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array parameter",
                                "in": "query",
                                "name": "query_array_double",
                                "required": False,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "query_array_string",
                                "required": False,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array parameter",
                                "in": "query",
                                "name": "query_array_string_byte",
                                "required": False,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array parameter",
                                "in": "query",
                                "name": "query_array_string_binary",
                                "required": False,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array parameter",
                                "in": "query",
                                "name": "query_array_boolean",
                                "required": False,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array parameter",
                                "in": "query",
                                "name": "query_array_date",
                                "required": False,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array parameter",
                                "in": "query",
                                "name": "query_array_date_time",
                                "required": False,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array parameter",
                                "in": "query",
                                "name": "query_array_password",
                                "required": False,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                },
                "/with/all/paths/types": {
                    "get": {
                        "operationId": "get_with_all_paths_types",
                        "parameters": [
                            {
                                "description": "integer path",
                                "in": "path",
                                "name": "path_integer",
                                "required": True,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 path",
                                "in": "path",
                                "name": "path_integer32",
                                "required": True,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 path",
                                "in": "path",
                                "name": "path_integer64",
                                "required": True,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number path",
                                "in": "path",
                                "name": "path_number",
                                "required": True,
                                "type": "number",
                            },
                            {
                                "description": "number float path",
                                "in": "path",
                                "name": "path_float",
                                "required": True,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double path",
                                "in": "path",
                                "name": "path_double",
                                "required": True,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string path",
                                "in": "path",
                                "name": "path_string",
                                "required": True,
                                "type": "string",
                            },
                            {
                                "description": "string byte path",
                                "in": "path",
                                "name": "path_string_byte",
                                "required": True,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary path",
                                "in": "path",
                                "name": "path_string_binary",
                                "required": True,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean path",
                                "in": "path",
                                "name": "path_boolean",
                                "required": True,
                                "type": "boolean",
                            },
                            {
                                "description": "date path",
                                "in": "path",
                                "name": "path_date",
                                "required": True,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time path",
                                "in": "path",
                                "name": "path_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password path",
                                "in": "path",
                                "name": "path_password",
                                "required": True,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array path",
                                "in": "path",
                                "name": "path_array_integer",
                                "required": True,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array path",
                                "in": "path",
                                "name": "path_array_integer32",
                                "required": True,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array path",
                                "in": "path",
                                "name": "path_array_integer64",
                                "required": True,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array path",
                                "in": "path",
                                "name": "path_array_number",
                                "required": True,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array path",
                                "in": "path",
                                "name": "path_array_float",
                                "required": True,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array path",
                                "in": "path",
                                "name": "path_array_double",
                                "required": True,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array path",
                                "in": "path",
                                "name": "path_array_string",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array path",
                                "in": "path",
                                "name": "path_array_string_byte",
                                "required": True,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array path",
                                "in": "path",
                                "name": "path_array_string_binary",
                                "required": True,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array path",
                                "in": "path",
                                "name": "path_array_boolean",
                                "required": True,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array path",
                                "in": "path",
                                "name": "path_array_date",
                                "required": True,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array path",
                                "in": "path",
                                "name": "path_array_date_time",
                                "required": True,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array path",
                                "in": "path",
                                "name": "path_array_password",
                                "required": True,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "post": {
                        "operationId": "post_with_all_paths_types",
                        "parameters": [
                            {
                                "description": "integer path",
                                "in": "path",
                                "name": "path_integer",
                                "required": True,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 path",
                                "in": "path",
                                "name": "path_integer32",
                                "required": True,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 path",
                                "in": "path",
                                "name": "path_integer64",
                                "required": True,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number path",
                                "in": "path",
                                "name": "path_number",
                                "required": True,
                                "type": "number",
                            },
                            {
                                "description": "number float path",
                                "in": "path",
                                "name": "path_float",
                                "required": True,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double path",
                                "in": "path",
                                "name": "path_double",
                                "required": True,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string path",
                                "in": "path",
                                "name": "path_string",
                                "required": True,
                                "type": "string",
                            },
                            {
                                "description": "string byte path",
                                "in": "path",
                                "name": "path_string_byte",
                                "required": True,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary path",
                                "in": "path",
                                "name": "path_string_binary",
                                "required": True,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean path",
                                "in": "path",
                                "name": "path_boolean",
                                "required": True,
                                "type": "boolean",
                            },
                            {
                                "description": "date path",
                                "in": "path",
                                "name": "path_date",
                                "required": True,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time path",
                                "in": "path",
                                "name": "path_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password path",
                                "in": "path",
                                "name": "path_password",
                                "required": True,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array path",
                                "in": "path",
                                "name": "path_array_integer",
                                "required": True,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array path",
                                "in": "path",
                                "name": "path_array_integer32",
                                "required": True,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array path",
                                "in": "path",
                                "name": "path_array_integer64",
                                "required": True,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array path",
                                "in": "path",
                                "name": "path_array_number",
                                "required": True,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array path",
                                "in": "path",
                                "name": "path_array_float",
                                "required": True,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array path",
                                "in": "path",
                                "name": "path_array_double",
                                "required": True,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array path",
                                "in": "path",
                                "name": "path_array_string",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array path",
                                "in": "path",
                                "name": "path_array_string_byte",
                                "required": True,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array path",
                                "in": "path",
                                "name": "path_array_string_binary",
                                "required": True,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array path",
                                "in": "path",
                                "name": "path_array_boolean",
                                "required": True,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array path",
                                "in": "path",
                                "name": "path_array_date",
                                "required": True,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array path",
                                "in": "path",
                                "name": "path_array_date_time",
                                "required": True,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array path",
                                "in": "path",
                                "name": "path_array_password",
                                "required": True,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "put": {
                        "operationId": "put_with_all_paths_types",
                        "parameters": [
                            {
                                "description": "integer path",
                                "in": "path",
                                "name": "path_integer",
                                "required": True,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 path",
                                "in": "path",
                                "name": "path_integer32",
                                "required": True,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 path",
                                "in": "path",
                                "name": "path_integer64",
                                "required": True,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number path",
                                "in": "path",
                                "name": "path_number",
                                "required": True,
                                "type": "number",
                            },
                            {
                                "description": "number float path",
                                "in": "path",
                                "name": "path_float",
                                "required": True,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double path",
                                "in": "path",
                                "name": "path_double",
                                "required": True,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string path",
                                "in": "path",
                                "name": "path_string",
                                "required": True,
                                "type": "string",
                            },
                            {
                                "description": "string byte path",
                                "in": "path",
                                "name": "path_string_byte",
                                "required": True,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary path",
                                "in": "path",
                                "name": "path_string_binary",
                                "required": True,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean path",
                                "in": "path",
                                "name": "path_boolean",
                                "required": True,
                                "type": "boolean",
                            },
                            {
                                "description": "date path",
                                "in": "path",
                                "name": "path_date",
                                "required": True,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time path",
                                "in": "path",
                                "name": "path_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password path",
                                "in": "path",
                                "name": "path_password",
                                "required": True,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array path",
                                "in": "path",
                                "name": "path_array_integer",
                                "required": True,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array path",
                                "in": "path",
                                "name": "path_array_integer32",
                                "required": True,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array path",
                                "in": "path",
                                "name": "path_array_integer64",
                                "required": True,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array path",
                                "in": "path",
                                "name": "path_array_number",
                                "required": True,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array path",
                                "in": "path",
                                "name": "path_array_float",
                                "required": True,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array path",
                                "in": "path",
                                "name": "path_array_double",
                                "required": True,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array path",
                                "in": "path",
                                "name": "path_array_string",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array path",
                                "in": "path",
                                "name": "path_array_string_byte",
                                "required": True,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array path",
                                "in": "path",
                                "name": "path_array_string_binary",
                                "required": True,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array path",
                                "in": "path",
                                "name": "path_array_boolean",
                                "required": True,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array path",
                                "in": "path",
                                "name": "path_array_date",
                                "required": True,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array path",
                                "in": "path",
                                "name": "path_array_date_time",
                                "required": True,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array path",
                                "in": "path",
                                "name": "path_array_password",
                                "required": True,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "delete": {
                        "operationId": "delete_with_all_paths_types",
                        "parameters": [
                            {
                                "description": "integer path",
                                "in": "path",
                                "name": "path_integer",
                                "required": True,
                                "type": "integer",
                            },
                            {
                                "description": "integer 32 path",
                                "in": "path",
                                "name": "path_integer32",
                                "required": True,
                                "type": "integer",
                                "format": "int32",
                            },
                            {
                                "description": "integer 64 path",
                                "in": "path",
                                "name": "path_integer64",
                                "required": True,
                                "type": "integer",
                                "format": "int64",
                            },
                            {
                                "description": "number path",
                                "in": "path",
                                "name": "path_number",
                                "required": True,
                                "type": "number",
                            },
                            {
                                "description": "number float path",
                                "in": "path",
                                "name": "path_float",
                                "required": True,
                                "type": "number",
                                "format": "float",
                            },
                            {
                                "description": "number double path",
                                "in": "path",
                                "name": "path_double",
                                "required": True,
                                "type": "number",
                                "format": "double",
                            },
                            {
                                "description": "string path",
                                "in": "path",
                                "name": "path_string",
                                "required": True,
                                "type": "string",
                            },
                            {
                                "description": "string byte path",
                                "in": "path",
                                "name": "path_string_byte",
                                "required": True,
                                "type": "string",
                                "format": "byte",
                            },
                            {
                                "description": "string binary path",
                                "in": "path",
                                "name": "path_string_binary",
                                "required": True,
                                "type": "string",
                                "format": "binary",
                            },
                            {
                                "description": "boolean path",
                                "in": "path",
                                "name": "path_boolean",
                                "required": True,
                                "type": "boolean",
                            },
                            {
                                "description": "date path",
                                "in": "path",
                                "name": "path_date",
                                "required": True,
                                "type": "string",
                                "format": "date",
                            },
                            {
                                "description": "date time path",
                                "in": "path",
                                "name": "path_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            },
                            {
                                "description": "password path",
                                "in": "path",
                                "name": "path_password",
                                "required": True,
                                "type": "string",
                                "format": "password",
                            },
                            {
                                "description": "integer array path",
                                "in": "path",
                                "name": "path_array_integer",
                                "required": True,
                                "items": {"type": "integer"},
                                "type": "array",
                            },
                            {
                                "description": "integer 32 array path",
                                "in": "path",
                                "name": "path_array_integer32",
                                "required": True,
                                "items": {"type": "integer", "format": "int32"},
                                "type": "array",
                            },
                            {
                                "description": "integer 64 array path",
                                "in": "path",
                                "name": "path_array_integer64",
                                "required": True,
                                "items": {"type": "integer", "format": "int64"},
                                "type": "array",
                            },
                            {
                                "description": "number array path",
                                "in": "path",
                                "name": "path_array_number",
                                "required": True,
                                "items": {"type": "number"},
                                "type": "array",
                            },
                            {
                                "description": "number float array path",
                                "in": "path",
                                "name": "path_array_float",
                                "required": True,
                                "items": {"type": "number", "format": "float"},
                                "type": "array",
                            },
                            {
                                "description": "number double array path",
                                "in": "path",
                                "name": "path_array_double",
                                "required": True,
                                "items": {"type": "number", "format": "double"},
                                "type": "array",
                            },
                            {
                                "description": "string array path",
                                "in": "path",
                                "name": "path_array_string",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            },
                            {
                                "description": "string byte array path",
                                "in": "path",
                                "name": "path_array_string_byte",
                                "required": True,
                                "items": {"type": "string", "format": "byte"},
                                "type": "array",
                            },
                            {
                                "description": "string binary array path",
                                "in": "path",
                                "name": "path_array_string_binary",
                                "required": True,
                                "items": {"type": "string", "format": "binary"},
                                "type": "array",
                            },
                            {
                                "description": "boolean array path",
                                "in": "path",
                                "name": "path_array_boolean",
                                "required": True,
                                "items": {"type": "boolean"},
                                "type": "array",
                            },
                            {
                                "description": "date array path",
                                "in": "path",
                                "name": "path_array_date",
                                "required": True,
                                "items": {"type": "string", "format": "date"},
                                "type": "array",
                            },
                            {
                                "description": "date time array path",
                                "in": "path",
                                "name": "path_array_date_time",
                                "required": True,
                                "items": {"type": "string", "format": "date-time"},
                                "type": "array",
                            },
                            {
                                "description": "password array path",
                                "in": "path",
                                "name": "path_array_password",
                                "required": True,
                                "items": {"type": "string", "format": "password"},
                                "type": "array",
                            },
                        ],
                        "responses": {"200": {"description": "return value"}},
                    },
                },
                "/date": {
                    "get": {
                        "operationId": "get_date",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {
                                    "type": "array",
                                    "items": {"type": "string", "format": "date"},
                                },
                            }
                        },
                    }
                },
                "/datetime": {
                    "get": {
                        "operationId": "get_date_time",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {
                                    "type": "array",
                                    "items": {"type": "string", "format": "date-time"},
                                },
                            }
                        },
                    }
                },
                "/datetime/encoding": {
                    "get": {
                        "operationId": "get_date_time_encoding",
                        "parameters": [
                            {
                                "description": "string parameter",
                                "in": "query",
                                "name": "encoded_date_time",
                                "required": True,
                                "type": "string",
                                "format": "date-time",
                            }
                        ],
                        "responses": {"200": {"description": "return value"}},
                    }
                },
            },
        },
        match_querystring=True,
    )
    # filtered tags service
    responses.add(
        responses.GET,
        url="http://localhost:8944/",
        json={
            "swagger": "2.0",
            "definitions": {
                "TestObject": {
                    "type": "object",
                    "properties": {"test": {"type": "string", "description": "test"}},
                    "title": "Test",
                }
            },
            "paths": {
                "/tags": {
                    "get": {
                        "operationId": "get_tags",
                        "tags": ["tag 0", "tag 1"],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    },
                    "post": {
                        "operationId": "post_tags",
                        "tags": ["tag 1", "tag 2"],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    },
                    "put": {
                        "operationId": "put_tags",
                        "tags": ["tag 2", "tag 3"],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    },
                    "delete": {
                        "operationId": "delete_tags",
                        "tags": ["tag 3", "tag 4"],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    },
                }
            },
        },
        match_querystring=True,
    )
    # values false service
    responses.add(
        responses.GET,
        url="http://localhost:8945/",
        json={
            "swagger": "2.0",
            "definitions": {
                "ZeroInteger": {
                    "properties": {
                        "zero_integer": {"type": "integer", "format": "int32"}
                    }
                },
                "ZeroFloat": {
                    "properties": {"zero_float": {"type": "number", "format": "float"}}
                },
                "FalseBoolean": {"properties": {"false_boolean": {"type": "boolean"}}},
                "EmptyString": {"properties": {"empty_string": {"type": "string"}}},
                "EmptyList": {
                    "properties": {
                        "empty_list": {
                            "type": "array",
                            "items": {"$ref": "#/definitions/Empty"},
                        }
                    }
                },
                "EmptyDictionary": {
                    "properties": {
                        "empty_dictionary": {
                            "type": "object",
                            "$ref": "#/definitions/Empty",
                        }
                    }
                },
                "Empty": {"properties": {}},
            },
            "paths": {
                "/with/zero/integer": {
                    "get": {
                        "operationId": "get_with_zero_integer",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/ZeroInteger"},
                                },
                            }
                        },
                    }
                },
                "/with/zero/float": {
                    "get": {
                        "operationId": "get_with_zero_float",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/ZeroFloat"},
                                },
                            }
                        },
                    }
                },
                "/with/false/boolean": {
                    "get": {
                        "operationId": "get_with_false_boolean",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/FalseBoolean"},
                                },
                            }
                        },
                    }
                },
                "/with/empty/string": {
                    "get": {
                        "operationId": "get_with_empty_string",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/EmptyString"},
                                },
                            }
                        },
                    }
                },
                "/with/empty/list": {
                    "get": {
                        "operationId": "get_with_empty_list",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/EmptyList"},
                                },
                            }
                        },
                    }
                },
                "/with/empty/dictionary": {
                    "get": {
                        "operationId": "get_with_empty_dictionary",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/definitions/EmptyDictionary"},
                                },
                            }
                        },
                    }
                },
            },
        },
        match_querystring=True,
    )
    # output order service
    responses.add(
        responses.GET,
        url="http://localhost:8946/",
        json={
            "swagger": "2.0",
            "definitions": {
                "Price": {
                    "required": ["curve", "date", "mat", "ts"],
                    "type": "object",
                    "properties": {
                        "ts": {
                            "type": "string",
                            "description": "timeslot",
                            "maxLength": 2,
                        },
                        "date": {
                            "type": "string",
                            "description": "date",
                            "format": "date",
                        },
                        "curve": {
                            "type": "string",
                            "description": "curvename",
                            "maxLength": 20,
                        },
                        "mat": {
                            "type": "string",
                            "description": "maturity",
                            "maxLength": 4,
                        },
                    },
                    "title": "RealizedPrice",
                }
            },
            "paths": {
                "/price/unordered": {
                    "get": {
                        "operationId": "get_price_unordered",
                        "description": "Price",
                        "parameters": [
                            {
                                "in": "query",
                                "description": "date",
                                "format": "date",
                                "required": False,
                                "type": "string",
                                "name": "date",
                            },
                            {
                                "name": "curve",
                                "in": "query",
                                "required": False,
                                "type": "string",
                                "description": "curvename",
                            },
                            {
                                "name": "ts",
                                "in": "query",
                                "required": False,
                                "type": "string",
                                "description": "timeslot",
                            },
                            {
                                "name": "mat",
                                "in": "query",
                                "required": False,
                                "type": "string",
                                "description": "maturity",
                            },
                        ],
                        "responses": {
                            "200": {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/Price"},
                                    "type": "array",
                                },
                            }
                        },
                    }
                }
            },
        },
        match_querystring=True,
    )
    # open_api_definition_parsing_service
    responses.add(
        responses.GET,
        url="http://localhost:8948/swagger_version_not_provided",
        json={
            "paths": {
                "/should_not_be_available": {
                    "get": {
                        "operationId": "get_should_not_be_available",
                        "responses": {200: {"description": "successful operation"}},
                    }
                }
            }
        },
        match_querystring=True,
    )
    responses.add(
        responses.GET,
        url="http://localhost:8948/swagger_version_not_supported",
        json={
            "swagger": "1.0",
            "paths": {
                "/should_not_be_available": {
                    "get": {
                        "operationId": "get_should_not_be_available",
                        "responses": {200: {"description": "successful operation"}},
                    }
                }
            },
        },
        match_querystring=True,
    )
    responses.add(
        responses.GET,
        url="http://localhost:8948/operation_id_not_provided",
        json={
            "swagger": "2.0",
            "paths": {
                "/without_operationId": {
                    "get": {"responses": {200: {"description": "successful operation"}}}
                }
            },
        },
        match_querystring=True,
    )
    responses.add(
        responses.GET,
        url="http://localhost:8948/operation_id_not_always_provided",
        json={
            "swagger": "2.0",
            "paths": {
                "/without_operationId": {
                    "get": {"responses": {200: {"description": "successful operation"}}}
                },
                "/with_operationId": {
                    "get": {
                        # This is obviously misleading but it can happen...
                        "operationId": "get_without_operationId",
                        "responses": {200: {"description": "successful operation"}},
                    }
                },
            },
        },
        match_querystring=True,
    )
    # without_parameter_service
    responses.add(
        responses.GET,
        url="http://localhost:8950/",
        json={
            "swagger": "2.0",
            "definitions": {"Test": {"properties": {}}},
            "paths": {
                "/without_parameter": {
                    "get": {
                        "operationId": "get_without_parameter",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {"type": "string"},
                            }
                        },
                    },
                    "post": {
                        "operationId": "post_without_parameter",
                        "responses": {
                            "200": {"description": "POST performed properly"}
                        },
                    },
                    "put": {
                        "operationId": "put_without_parameter",
                        "responses": {"200": {"description": "PUT performed properly"}},
                    },
                    "delete": {
                        "operationId": "delete_without_parameter",
                        "responses": {
                            "200": {"description": "DELETE performed properly"}
                        },
                    },
                },
                "/plain_text_without_parameter": {
                    "get": {
                        "operationId": "get_plain_text_without_parameter",
                        "produces": ["text/plain"],
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {"type": "string"},
                            }
                        },
                    },
                    "post": {
                        "operationId": "post_plain_text_without_parameter",
                        "produces": ["text/plain"],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "put": {
                        "operationId": "put_plain_text_without_parameter",
                        "produces": ["text/plain"],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "delete": {
                        "operationId": "delete_plain_text_without_parameter",
                        "produces": ["text/plain"],
                        "responses": {"200": {"description": "return value"}},
                    },
                },
                "/json_without_parameter": {
                    "get": {
                        "operationId": "get_json_without_parameter",
                        "produces": ["application/json"],
                        "responses": {
                            "200": {
                                "description": "return value",
                                "$ref": "#/definitions/Test",
                            }
                        },
                    },
                    "post": {
                        "operationId": "post_json_without_parameter",
                        "produces": ["application/json"],
                        "responses": {
                            "200": {
                                "description": "return value",
                                "$ref": "#/definitions/Test",
                            }
                        },
                    },
                    "put": {
                        "operationId": "put_json_without_parameter",
                        "produces": ["application/json"],
                        "responses": {
                            "200": {
                                "description": "return value",
                                "$ref": "#/definitions/Test",
                            }
                        },
                    },
                    "delete": {
                        "operationId": "delete_json_without_parameter",
                        "produces": ["application/json"],
                        "responses": {
                            "200": {
                                "description": "return value",
                                "$ref": "#/definitions/Test",
                            }
                        },
                    },
                },
                "/octet_without_parameter": {
                    "get": {
                        "operationId": "get_octet_without_parameter",
                        "produces": ["application/octet-stream"],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "post": {
                        "operationId": "post_octet_without_parameter",
                        "produces": ["application/octet-stream"],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "put": {
                        "operationId": "put_octet_without_parameter",
                        "produces": ["application/octet-stream"],
                        "responses": {"200": {"description": "return value"}},
                    },
                    "delete": {
                        "operationId": "delete_octet_without_parameter",
                        "produces": ["application/octet-stream"],
                        "responses": {"200": {"description": "return value"}},
                    },
                },
            },
        },
        match_querystring=True,
    )
    # header_parameter_service
    responses.add(
        responses.GET,
        url="http://localhost:8951/",
        json={
            "swagger": "2.0",
            "definitions": {
                "Header": {
                    "type": "object",
                    "properties": {
                        "Accept": {"type": "string"},
                        "Accept-Encoding": {"type": "string"},
                        "Connection": {"type": "string"},
                        "Content-Length": {"type": "string"},
                        "Content-Type": {"type": "string"},
                        "Header-String": {"type": "string"},
                        "Host": {"type": "string"},
                        "User-Agent": {"type": "string"},
                    },
                    "title": "Test",
                }
            },
            "paths": {
                "/header": {
                    "get": {
                        "operationId": "get_header",
                        "parameters": [
                            {
                                "description": "header parameter",
                                "in": "header",
                                "name": "header_string",
                                "required": True,
                                "type": "string",
                            }
                        ],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {"$ref": "#/definitions/Header"},
                            }
                        },
                    }
                }
            },
        },
        match_querystring=True,
    )
    # form_parameter_service
    responses.add(
        responses.GET,
        url="http://localhost:8952/",
        json={
            "swagger": "2.0",
            "definitions": {
                "Form": {
                    "type": "object",
                    "properties": {"form_string": {"type": "string"}},
                    "title": "Test",
                }
            },
            "paths": {
                "/form": {
                    "post": {
                        "operationId": "post_form",
                        "parameters": [
                            {
                                "description": "form parameter",
                                "in": "formData",
                                "name": "form_string",
                                "required": True,
                                "type": "string",
                            }
                        ],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {"$ref": "#/definitions/Form"},
                            }
                        },
                    }
                }
            },
        },
        match_querystring=True,
    )
    # array_parameter_service
    responses.add(
        responses.GET,
        url="http://localhost:8953/",
        json={
            "swagger": "2.0",
            "definitions": {
                "TestObject": {
                    "type": "object",
                    "properties": {"test": {"type": "string", "description": "test"}},
                    "title": "Test",
                }
            },
            "paths": {
                "/string_multi_array_parameter": {
                    "get": {
                        "operationId": "get_string_multi_array_parameter",
                        "parameters": [
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "string_array",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                                "collectionFormat": "multi",
                            }
                        ],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    }
                },
                "/string_default_array_parameter": {
                    "get": {
                        "operationId": "get_string_default_array_parameter",
                        "parameters": [
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "string_array",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                            }
                        ],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    }
                },
                "/string_csv_array_parameter": {
                    "get": {
                        "operationId": "get_string_csv_array_parameter",
                        "parameters": [
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "string_array",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                                "collectionFormat": "csv",
                            }
                        ],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    }
                },
                "/string_ssv_array_parameter": {
                    "get": {
                        "operationId": "get_string_ssv_array_parameter",
                        "parameters": [
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "string_array",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                                "collectionFormat": "ssv",
                            }
                        ],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    }
                },
                "/string_tsv_array_parameter": {
                    "get": {
                        "operationId": "get_string_tsv_array_parameter",
                        "parameters": [
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "string_array",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                                "collectionFormat": "tsv",
                            }
                        ],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    }
                },
                "/string_pipes_array_parameter": {
                    "get": {
                        "operationId": "get_string_pipes_array_parameter",
                        "parameters": [
                            {
                                "description": "string array parameter",
                                "in": "query",
                                "name": "string_array",
                                "required": True,
                                "items": {"type": "string"},
                                "type": "array",
                                "collectionFormat": "pipes",
                            }
                        ],
                        "responses": {
                            200: {
                                "description": "successful operation",
                                "schema": {
                                    "items": {"$ref": "#/definitions/TestObject"},
                                    "type": "array",
                                },
                            }
                        },
                    }
                },
            },
        },
        match_querystring=True,
    )
    # TODO add static_file_call_service mock to the specific test case
    # http_methods_service
    responses.add(
        responses.GET,
        url="http://localhost:8955/",
        json={
            "swagger": "2.0",
            "paths": {
                "/http_methods": {
                    "get": {
                        "operationId": "get_http_methods",
                        "responses": {200: {"description": "successful operation"}},
                    },
                    "post": {
                        "operationId": "post_http_methods",
                        "responses": {200: {"description": "successful operation"}},
                    },
                    "put": {
                        "operationId": "put_http_methods",
                        "responses": {200: {"description": "successful operation"}},
                    },
                    "delete": {
                        "operationId": "delete_http_methods",
                        "responses": {200: {"description": "successful operation"}},
                    },
                    "patch": {
                        "operationId": "patch_http_methods",
                        "responses": {200: {"description": "successful operation"}},
                    },
                    "options": {
                        "operationId": "options_http_methods",
                        "responses": {200: {"description": "successful operation"}},
                    },
                    "head": {
                        "operationId": "head_http_methods",
                        "responses": {200: {"description": "successful operation"}},
                    },
                }
            },
        },
        match_querystring=True,
    )
    # content_type_service
    responses.add(
        responses.GET,
        url="http://localhost:8956/",
        json={
            "swagger": "2.0",
            "paths": {
                "/msgpackpandas": {
                    "get": {
                        "operationId": "get_msgpackpandas",
                        "responses": {200: {"description": "successful operation"}},
                        "produces": ["application/msgpackpandas"],
                    }
                },
                "/json": {
                    "get": {
                        "operationId": "get_json",
                        "responses": {200: {"description": "successful operation"}},
                        "produces": ["application/json"],
                    }
                },
            },
        },
        match_querystring=True,
    )
    # base_path_ending_with_slash_service
    responses.add(
        responses.GET,
        url="http://localhost:8957/",
        json={
            "swagger": "2.0",
            "basePath": "//",
            "paths": {
                "/method": {
                    "get": {
                        "operationId": "get_method",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {"type": "string"},
                            }
                        },
                    },
                    "post": {
                        "operationId": "post_method",
                        "responses": {
                            "200": {"description": "POST performed properly"}
                        },
                    },
                    "put": {
                        "operationId": "put_method",
                        "responses": {"200": {"description": "PUT performed properly"}},
                    },
                    "delete": {
                        "operationId": "delete_method",
                        "responses": {
                            "200": {"description": "DELETE performed properly"}
                        },
                    },
                }
            },
        },
        match_querystring=True,
    )
    # async_service
    responses.add(
        responses.GET,
        url="http://localhost:8958/",
        json={
            "swagger": "2.0",
            "paths": {
                "/async": {
                    "get": {
                        "operationId": "get_async",
                        "responses": {
                            "202": {
                                "description": "return value",
                                "schema": {"type": "string"},
                            }
                        },
                    }
                }
            },
        },
        match_querystring=True,
    )
    loader.load("services.yml")


def test_string_multi_array_parameter(services):
    from pyxelrest import pyxelrestgenerator

    result = "string_array=\"['str1', 'str2']\""
    assert (
        pyxelrestgenerator.array_parameter_get_string_multi_array_parameter(
            ["str1", "str2"]
        )
        == result
    )


def test_string_default_array_parameter(services):
    from pyxelrest import pyxelrestgenerator

    result = "string_array=\"['str1,str2']\""
    assert (
        pyxelrestgenerator.array_parameter_get_string_default_array_parameter(
            ["str1", "str2"]
        )
        == result
    )


def test_string_csv_array_parameter(services):
    from pyxelrest import pyxelrestgenerator

    result = "string_array=\"['str1,str2']\""
    assert (
        pyxelrestgenerator.array_parameter_get_string_csv_array_parameter(
            ["str1", "str2"]
        )
        == result
    )


def test_string_ssv_array_parameter(services):
    from pyxelrest import pyxelrestgenerator

    result = "string_array=\"['str1 str2']\""
    assert (
        pyxelrestgenerator.array_parameter_get_string_ssv_array_parameter(
            ["str1", "str2"]
        )
        == result
    )


def test_string_tsv_array_parameter(services):
    from pyxelrest import pyxelrestgenerator

    result = "string_array=\"['str1\\tstr2']\""
    assert (
        pyxelrestgenerator.array_parameter_get_string_tsv_array_parameter(
            ["str1", "str2"]
        )
        == result
    )


def test_string_pipes_array_parameter(services):
    from pyxelrest import pyxelrestgenerator

    result = "string_array=\"['str1|str2']\""
    assert (
        pyxelrestgenerator.array_parameter_get_string_pipes_array_parameter(
            ["str1", "str2"]
        )
        == result
    )


def test_plain_without_parameter(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.without_parameter_get_plain_text_without_parameter()
        == "string value returned should be truncated so that the following information cannot be seen by user, because of the fact that Excel does not allow more than 255 characters in a cell. Only the 255 characters will be returned by the user defined functions:  "
    )


def test_post_without_parameter(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.without_parameter_post_without_parameter()
        == "POST performed properly"
    )


def test_put_without_parameter(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.without_parameter_put_without_parameter()
        == "PUT performed properly"
    )


def test_delete_without_parameter(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.without_parameter_delete_without_parameter()
        == "DELETE performed properly"
    )


def test_service_without_sync_does_not_have_sync(services):
    from pyxelrest import pyxelrestgenerator

    with pytest.raises(AttributeError) as exception_info:
        pyxelrestgenerator.vba_without_parameter_delete_without_parameter()
    assert (
        str(exception_info.value)
        == "module 'pyxelrest.pyxelrestgenerator' has no attribute 'vba_without_parameter_delete_without_parameter'"
    )


def test_get_header_parameter(services):
    from pyxelrest import pyxelrestgenerator

    headers = pyxelrestgenerator.header_parameter_get_header("sent header")
    header_param_index = headers[0].index("Header-String")
    assert headers[1][header_param_index] == "sent header"


def test_get_header_parameter_sync(services):
    from pyxelrest import pyxelrestgenerator

    headers = pyxelrestgenerator.vba_header_parameter_get_header("sent header")
    header_param_index = headers[0].index("Header-String")
    assert headers[1][header_param_index] == "sent header"


def test_service_only_sync_does_not_have_vba_prefix(services):
    from pyxelrest import pyxelrestgenerator

    with pytest.raises(AttributeError) as exception_info:
        pyxelrestgenerator.vba_header_advanced_configuration_get_header("sent header")
    assert (
        str(exception_info.value)
        == "module 'pyxelrest.pyxelrestgenerator' has no attribute 'vba_header_advanced_configuration_get_header'"
    )


def test_get_header_advanced_configuration(services):
    from pyxelrest import pyxelrestgenerator

    headers = pyxelrestgenerator.header_advanced_configuration_get_header("sent header")

    custom_header_index = headers[0].index("X-Pxl-Custom")
    assert headers[1][custom_header_index] == "MyCustomValue"

    other_header_index = headers[0].index("X-Pxl-Other")
    assert headers[1][other_header_index] == "MyOtherValue"

    envvar_header_index = headers[0].index("X-Pxl-Envvar")
    assert headers[1][envvar_header_index] == os.environ["USERNAME"]

    request_header_index = headers[0].index("X-Pxl-Request")
    assert request_header_index

    session_header_index = headers[0].index("X-Pxl-Session")
    assert re.match(
        "\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d",
        headers[1][session_header_index],
    )

    user_agent_index = headers[0].index("User-Agent")
    assert headers[1][user_agent_index] == "PyxelRest v0.69.0"

    cell_header_index = headers[0].index("X-Pxl-Cell")
    assert headers[1][cell_header_index] == "Python"


def test_post_form_parameter(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.form_parameter_post_form("sent string form data") == [
        ["form_string"],
        ["sent string form data"],
    ]


def test_get_with_selected_tags(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.selected_tags_get_tags()
        == "Second tag is one of the accepted tags"
    )


def test_post_with_selected_tags(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.selected_tags_post_tags() == "All tags are accepted"


def test_put_with_selected_tags(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.selected_tags_put_tags()
        == "First tag is one of the accepted tags"
    )


def test_delete_with_selected_tags(services):
    from pyxelrest import pyxelrestgenerator

    assert not hasattr(pyxelrestgenerator, "selected_tags_delete_tags")


def test_get_with_excluded_tags(services):
    from pyxelrest import pyxelrestgenerator

    assert not hasattr(pyxelrestgenerator, "excluded_tags_get_tags")


def test_post_with_excluded_tags(services):
    from pyxelrest import pyxelrestgenerator

    assert not hasattr(pyxelrestgenerator, "excluded_tags_post_tags")


def test_put_with_excluded_tags(services):
    from pyxelrest import pyxelrestgenerator

    assert not hasattr(pyxelrestgenerator, "excluded_tags_put_tags")


def test_delete_with_excluded_tags(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.excluded_tags_delete_tags()
        == "This method should not be available"
    )


def test_get_with_selected_operation_ids(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.selected_operation_ids_get_tags()
        == "Second tag is one of the accepted tags"
    )


def test_post_with_selected_operation_ids(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.selected_operation_ids_post_tags() == "All tags are accepted"
    )


def test_put_with_selected_operation_ids(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.selected_operation_ids_put_tags()
        == "First tag is one of the accepted tags"
    )


def test_delete_with_selected_operation_ids(services):
    from pyxelrest import pyxelrestgenerator

    assert not hasattr(pyxelrestgenerator, "selected_operation_ids_delete_tags")


def test_get_with_excluded_operation_ids(services):
    from pyxelrest import pyxelrestgenerator

    assert not hasattr(pyxelrestgenerator, "excluded_operation_ids_get_tags")


def test_post_with_excluded_operation_ids(services):
    from pyxelrest import pyxelrestgenerator

    assert not hasattr(pyxelrestgenerator, "excluded_operation_ids_post_tags")


def test_put_with_excluded_operation_ids(services):
    from pyxelrest import pyxelrestgenerator

    assert not hasattr(pyxelrestgenerator, "excluded_operation_ids_put_tags")


def test_delete_with_excluded_operation_ids(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.excluded_operation_ids_delete_tags()
        == "This method should not be available"
    )


def test_get_with_zero_integer(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.values_false_get_with_zero_integer() == [
        ["zero_integer"],
        [0],
    ]


def test_get_with_zero_float(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.values_false_get_with_zero_float() == [
        ["zero_float"],
        [0.0],
    ]


def test_get_with_false_boolean(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.values_false_get_with_false_boolean() == [
        ["false_boolean"],
        [False],
    ]


def test_get_with_empty_string(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.values_false_get_with_empty_string() == [
        ["empty_string"],
        [""],
    ]


def test_get_with_empty_list(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.values_false_get_with_empty_list() == [
        ["empty_list"],
        [""],
    ]


def test_get_with_empty_dictionary(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.values_false_get_with_empty_dictionary() == [
        ["empty_dictionary"],
        [""],
    ]


def test_get_compare_output_order(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.output_order_get_price_unordered() == [
        [u"curve", u"date", u"mat", u"ts"],
        [u"PW_FR", datetime.datetime(2017, 4, 5, 0, 0), u"H01", u""],
        [u"PW_FR", datetime.datetime(2017, 4, 5, 0, 0), u"H02", u"2017-04-05 12:03:15"],
        [u"PW_FR", datetime.datetime(2017, 4, 5, 0, 0), u"H03", u""],
    ]


def test_get_date(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.usual_parameters_get_date() == [
        [datetime.datetime(2014, 3, 5, 0, 0)],
        [datetime.datetime(9999, 1, 1, 0, 0)],
        [datetime.datetime(3001, 1, 1, 0, 0)],
        [datetime.datetime(1970, 1, 1, 0, 0)],
        [datetime.datetime(1900, 1, 1, 0, 0)],
    ]


def test_get_datetime(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.usual_parameters_get_date_time() == [
        [datetime.datetime(2014, 3, 5, 15, 59, 58, 201980, tzinfo=tzutc())],
        [datetime.datetime(2014, 3, 5, 15, 59, 58, 201980, tzinfo=tzutc())],
        [datetime.datetime(2014, 3, 5, 15, 59, 58, 201980, tzinfo=tzutc())],
        [datetime.datetime(2014, 3, 5, 15, 59, 58, 201980, tzinfo=tzutc())],
        [datetime.datetime(2014, 3, 5, 15, 59, 58, 201980, tzinfo=tzutc())],
        [datetime.datetime(9999, 1, 1, 0, 0, 0, 0, tzinfo=tzutc())],
        [datetime.datetime(3001, 1, 1, 8, 0, 0, 0, tzinfo=tzutc())],
        [datetime.datetime(1970, 1, 1, 1, 0, 0, 0, tzinfo=tzutc())],
        [datetime.datetime(1970, 1, 1, 2, 0, 0, 0, tzinfo=tzutc())],
    ]


def test_get_datetime_encoding(services):
    from pyxelrest import pyxelrestgenerator

    date_time = datetime.datetime.strptime("2017-09-13T15:20:35", "%Y-%m-%dT%H:%M:%S")
    assert (
        pyxelrestgenerator.usual_parameters_get_date_time_encoding(
            encoded_date_time=date_time
        )
        == "2017-09-13T15:20:35"
    )
    date_time = datetime.datetime.strptime("2017-09-13T15:20", "%Y-%m-%dT%H:%M")
    assert (
        pyxelrestgenerator.usual_parameters_get_date_time_encoding(
            encoded_date_time=date_time
        )
        == "2017-09-13T15:20:00"
    )
    date_time = datetime.datetime.strptime("2017-09-13 15", "%Y-%m-%d %H")
    assert (
        pyxelrestgenerator.usual_parameters_get_date_time_encoding(
            encoded_date_time=date_time
        )
        == "2017-09-13T15:00:00"
    )


def test_get_static_open_api_definition(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.open_api_definition_loaded_from_file_get_static_file_call()
        == "success"
    )


def test_get_http_method(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.http_methods_get_http_methods() == "GET"


def test_post_http_method(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.http_methods_post_http_methods() == "POST"


def test_put_http_method(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.http_methods_put_http_methods() == "PUT"


def test_delete_http_method(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.http_methods_delete_http_methods() == "DELETE"


def test_patch_http_method(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.http_methods_patch_http_methods() == "PATCH"


def test_options_http_method(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.http_methods_options_http_methods() == "OPTIONS"


def test_head_http_method(services):
    from pyxelrest import pyxelrestgenerator

    # HEAD is already handled by Flask
    assert pyxelrestgenerator.http_methods_head_http_methods() == ""


def test_msgpackpandas_content_type(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.content_type_get_msgpackpandas()
        == ["application/msgpackpandas"]
        if support_pandas()
        else ["*/*"]
    )


def test_json_content_type(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.content_type_get_json() == ["application/json"]


def test_missing_operation_id(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.operation_id_not_provided_get_without_operationId()
        == "/without_operationId called."
    )


def test_mixed_operation_id(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.operation_id_not_always_provided_get_without_operationId()
        == "/with_operationId called."
    )
    assert (
        pyxelrestgenerator.operation_id_not_always_provided_duplicated_get_without_operationId()
        == "/without_operationId called."
    )


def test_get_base_path_ending_with_slash(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.base_path_ending_with_slash_get_method()
        == "http://localhost:8957/method"
    )


def test_post_base_path_ending_with_slash(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.base_path_ending_with_slash_post_method()
        == "http://localhost:8957/method"
    )


def test_put_base_path_ending_with_slash(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.base_path_ending_with_slash_put_method()
        == "http://localhost:8957/method"
    )


def test_delete_base_path_ending_with_slash(services):
    from pyxelrest import pyxelrestgenerator

    assert (
        pyxelrestgenerator.base_path_ending_with_slash_delete_method()
        == "http://localhost:8957/method"
    )


def test_get_async_url(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.async_get_async() == [
        ["Status URL"],
        ["http://localhost:8958/async/status"],
    ]


def test_get_custom_url_sync(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.vba_pyxelrest_get_url(
        "http://localhost:8958/async/status",
        extra_headers=[
            ["X-Custom-Header1", "custom1"],
            ["X-Custom-Header2", "custom2"],
        ],
    ) == [["X-Custom-Header1", "X-Custom-Header2"], ["custom1", "custom2"]]


def test_get_custom_url(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.pyxelrest_get_url(
        "http://localhost:8958/async/status",
        extra_headers=[
            ["X-Custom-Header1", "custom1"],
            ["X-Custom-Header2", "custom2"],
        ],
    ) == [["X-Custom-Header1", "X-Custom-Header2"], ["custom1", "custom2"]]


def test_delete_custom_url_sync(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.vba_pyxelrest_delete_url(
        "http://localhost:8958/unlisted",
        extra_headers=[
            ["X-Custom-Header1", "custom1"],
            ["X-Custom-Header2", "custom2"],
        ],
    ) == [["X-Custom-Header1", "X-Custom-Header2"], ["custom1", "custom2"]]


def test_delete_custom_url(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.pyxelrest_delete_url(
        "http://localhost:8958/unlisted",
        extra_headers=[
            ["X-Custom-Header1", "custom1"],
            ["X-Custom-Header2", "custom2"],
        ],
    ) == [["X-Custom-Header1", "X-Custom-Header2"], ["custom1", "custom2"]]


def test_post_custom_url_dict(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.pyxelrest_post_url(
        "http://localhost:8958/dict",
        [["key1", "key2", "key3"], ["value1", 1, "value3"]],
        extra_headers=[["Content-Type", "application/json"]],
        parse_body_as="dict",
    ) == [["key1", "key2", "key3"], ["value1", 1, "value3"]]


def test_post_custom_url_dict_list_sync(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.vba_pyxelrest_post_url(
        "http://localhost:8958/dict",
        [["key1", "key2", "key3"], ["value1", 1, "value3"], ["other1", 2, "other3"]],
        extra_headers=[["Content-Type", "application/json"]],
        parse_body_as="dict_list",
    ) == [["key1", "key2", "key3"], ["value1", 1, "value3"], ["other1", 2, "other3"]]


def test_post_custom_url_dict_list(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.pyxelrest_post_url(
        "http://localhost:8958/dict",
        [["key1", "key2", "key3"], ["value1", 1, "value3"], ["other1", 2, "other3"]],
        extra_headers=[["Content-Type", "application/json"]],
        parse_body_as="dict_list",
    ) == [["key1", "key2", "key3"], ["value1", 1, "value3"], ["other1", 2, "other3"]]


def test_put_custom_url_dict_list(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.pyxelrest_put_url(
        "http://localhost:8958/dict",
        [["key1", "key2", "key3"], ["value1", 1, "value3"], ["other1", 2, "other3"]],
        extra_headers=[["Content-Type", "application/json"]],
        parse_body_as="dict_list",
    ) == [["key1", "key2", "key3"], ["value1", 1, "value3"], ["other1", 2, "other3"]]


def test_put_custom_url_dict(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.pyxelrest_put_url(
        "http://localhost:8958/dict",
        [["key1", "key2", "key3"], ["value1", 1, "value3"]],
        extra_headers=[["Content-Type", "application/json"]],
        parse_body_as="dict",
    ) == [["key1", "key2", "key3"], ["value1", 1, "value3"]]


def test_put_custom_url_dict_sync(services):
    from pyxelrest import pyxelrestgenerator

    assert pyxelrestgenerator.vba_pyxelrest_put_url(
        "http://localhost:8958/dict",
        [["key1", "key2", "key3"], ["value1", 1, "value3"]],
        extra_headers=[["Content-Type", "application/json"]],
        parse_body_as="dict",
    ) == [["key1", "key2", "key3"], ["value1", 1, "value3"]]
