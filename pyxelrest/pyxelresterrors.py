class InvalidOpenAPIDefinition(Exception):
    """ Invalid OpenAPI Definition. """
    def __init__(self, message, *args, **kwargs):  # real signature unknown
        Exception.__init__(self, 'Invalid Definition: ' + message)


class OpenAPIVersionNotProvided(InvalidOpenAPIDefinition):
    """ OpenAPI version is not provided. """
    def __init__(self, *args, **kwargs):
        InvalidOpenAPIDefinition.__init__(self, 'Version not provided.')


class UnsupportedOpenAPIVersion(InvalidOpenAPIDefinition):
    """ OpenAPI version is not supported. """
    def __init__(self, version, *args, **kwargs):
        InvalidOpenAPIDefinition.__init__(self, f'Version {version} not supported.')


class MandatoryPropertyNotProvided(Exception):
    """ Mandatory property not provided. """
    def __init__(self, section, property_name, *args, **kwargs):
        Exception.__init__(self, f'"{section}" configuration section must provide "{property_name}".')


class ConfigurationFileNotFound(Exception):
    """ Configuration file not found. """
    def __init__(self, file_path, *args, **kwargs):
        Exception.__init__(self, f'"{file_path}" configuration file cannot be read.')


class DuplicatedParameters(Exception):
    """ Method contains duplicated parameters. """
    def __init__(self, method, *args, **kwargs):
        Exception.__init__(self, f'"{method["operationId"]}" parameters are not unique per location: {method["parameters"]}.')


class EmptyResponses(InvalidOpenAPIDefinition):
    """ Responses are not set in OpenAPI definition. """
    def __init__(self, method_name, *args, **kwargs):
        InvalidOpenAPIDefinition.__init__(self, f'At least one response must be specified for "{method_name}".')
