class InvalidSwaggerDefinition(Exception):
    """ Invalid Swagger Definition. """
    def __init__(self, message, *args, **kwargs):  # real signature unknown
        Exception.__init__(self, 'Invalid Definition: ' + message)


class SwaggerVersionNotProvided(InvalidSwaggerDefinition):
    """ Swagger version is not provided. """
    def __init__(self, *args, **kwargs):
        InvalidSwaggerDefinition.__init__(self, 'Version not provided.')


class UnsupportedSwaggerVersion(InvalidSwaggerDefinition):
    """ Swagger version is not supported. """
    def __init__(self, version, *args, **kwargs):
        InvalidSwaggerDefinition.__init__(self, 'Version {} not supported.'.format(version))


class MandatoryPropertyNotProvided(Exception):
    """ Mandatory property not provided. """
    def __init__(self, section, property_name, *args, **kwargs):
        Exception.__init__(self, '"{0}" configuration section must provide "{1}".'.format(section, property_name))


class NoMethodsProvided(Exception):
    """ No Methods provided. """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, 'At least one method must be provided amongst [get, post, put, delete].')


class PortNotAvailable(Exception):
    """ No Methods provided. """
    def __init__(self, port, *args, **kwargs):
        Exception.__init__(self, 'The port {0} is not available.'.format(port))


class ConfigurationFileNotFound(Exception):
    """ Configuration file not found. """
    def __init__(self, file_path, *args, **kwargs):
        Exception.__init__(self, '"{0}" configuration file cannot be read.'.format(file_path))


class DuplicatedParameters(Exception):
    """ Method contains duplicated parameters. """
    def __init__(self, method, *args, **kwargs):
        Exception.__init__(self, '"{0}" parameters are not unique: {1}.'.format(method['operationId'],
                                                                                method['parameters']))


class EmptyResponses(InvalidSwaggerDefinition):
    """ Responses are not set in Swagger. """
    def __init__(self, method_name, *args, **kwargs):
        Exception.__init__(self, 'At least one response must be specified for "{0}".'.format(method_name))


class AuthenticationFailed(Exception):
    """ User was not authenticated. """
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, 'User was not authenticated.')


class InvalidToken(Exception):
    """ Token is invalid. """
    def __init__(self, token_name, *args, **kwargs):
        Exception.__init__(self, '{0} is invalid.'.format(token_name))


class TokenNotProvided(Exception):
    """ Token was not provided. """
    def __init__(self, token_name, *args, **kwargs):
        Exception.__init__(self, '{0} not provided.'.format(token_name))


class TokenExpiryNotProvided(Exception):
    """ Token expiry was not provided. """
    def __init__(self, token_body, *args, **kwargs):
        Exception.__init__(self, 'Expiry (exp) is not provided in {0}.'.format(token_body))
