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
        InvalidOpenAPIDefinition.__init__(self, 'Version {} not supported.'.format(version))


class MandatoryPropertyNotProvided(Exception):
    """ Mandatory property not provided. """
    def __init__(self, section, property_name, *args, **kwargs):
        Exception.__init__(self, '"{0}" configuration section must provide "{1}".'.format(section, property_name))


class ConfigurationFileNotFound(Exception):
    """ Configuration file not found. """
    def __init__(self, file_path, *args, **kwargs):
        Exception.__init__(self, '"{0}" configuration file cannot be read.'.format(file_path))


class DuplicatedParameters(Exception):
    """ Method contains duplicated parameters. """
    def __init__(self, method, *args, **kwargs):
        Exception.__init__(self, '"{0}" parameters are not unique per location: {1}.'.format(method['operationId'],
                                                                                             method['parameters']))


class EmptyResponses(InvalidOpenAPIDefinition):
    """ Responses are not set in OpenAPI definition. """
    def __init__(self, method_name, *args, **kwargs):
        InvalidOpenAPIDefinition.__init__(self, 'At least one response must be specified for "{0}".'.format(method_name))
