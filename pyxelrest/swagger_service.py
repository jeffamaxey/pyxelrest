import os
try:
    # Python 3
    from configparser import ConfigParser
    from urllib.parse import urlsplit
except ImportError:
    # Python 2
    from ConfigParser import ConfigParser
    from urlparse import urlsplit

import re
import requests
import vba
import logging


def to_valid_python_vba(str_value):
    return re.sub('[^a-zA-Z_]+[^a-zA-Z_0-9]*', '', str_value)


class SwaggerService:
    def __init__(self, service_name, config):
        """
        Load service information from configuration and swagger JSON.
        :param service_name: Will be used as prefix to use in front of services UDFs to avoid duplicate between services.
        :param config: ConfigParser instance from where service details are retrieved.
        """
        self.name = service_name
        self.udf_prefix = to_valid_python_vba(service_name)
        self.methods = [method.strip() for method in self.get_item(config, 'methods').split(',') if method.strip()]
        if not self.methods:
            raise Exception('All methods were filtered out.')
        swagger_url = self.get_item(config, 'swagger_url')
        swagger_url_parsed = urlsplit(swagger_url)
        proxy_url = self.get_item_default(config, 'proxy_url', None)
        self.proxy = {swagger_url_parsed.scheme: proxy_url} if proxy_url else {}
        self.swagger = self._retrieve_swagger(swagger_url)
        self.validate_swagger_version()
        self.uri = self._extract_uri(swagger_url_parsed, config)
        logging.info('"{0}" service ({1}) will be available ({2}).'.format(self.name, self.uri, self.methods))

    def _extract_uri(self, swagger_url_parsed, config):
        # The default scheme to be used is the one used to access the Swagger definition itself.
        scheme = self.swagger.get('schemes', [swagger_url_parsed.scheme])[0]
        # If the host is not included, the host serving the documentation is to be used (including the port).
        # service_host property is here to handle services behind a reverse proxy
        # (otherwise host will be the reverse proxy one)
        host = self.swagger.get('host', self.get_item_default(config, 'service_host', swagger_url_parsed.netloc))
        # Allow user to provide service_host starting with scheme (removing it)
        host_parsed = urlsplit(host)
        if host_parsed.netloc:
            host = host_parsed.netloc + host_parsed.path
        # If it is not included, the API is served directly under the host.
        base_path = self.swagger.get('basePath', None)

        return scheme + '://' + host + base_path if base_path else scheme + '://' + host

    def get_item(self, config, key):
        try:
            # Python 3
            section = config[self.name]
            if key not in section:
                raise Exception('"{0}" configuration section must provide "{1}".'.format(self.name, key))
            return section[key]
        except AttributeError:
            # Python 2
            if not config.has_option(self.name, key):
                raise Exception('"{0}" configuration section must provide "{1}".'.format(self.name, key))
            return config.get(self.name, key)

    def get_item_default(self, config, key, default_value):
        try:
            # Python 3
            section = config[self.name]
            return section[key] if key in section else default_value
        except AttributeError:
            # Python 2
            return config.get(self.name, key) if config.has_option(self.name, key) else default_value

    def _retrieve_swagger(self, swagger_url):
        """
        Retrieve swagger JSON from service.
        :param swagger_url: URI of the service swagger JSON.
        :return: Dictionary representation of the retrieved swagger JSON.
        """
        response = requests.get(swagger_url, proxies=self.proxy, timeout=1)
        response.raise_for_status()
        swagger = response.json()
        self._update_vba_restricted_keywords(swagger)
        return swagger

    @classmethod
    def _update_vba_restricted_keywords(cls, swagger_json):
        """
        Update name of parameters in the swagger JSON to avoid using VBA restricted keywords as parameter names.
        :param swagger_json: Dictionary representing the swagger JSON.
        :return: None
        """
        for methods in swagger_json['paths'].values():
            for method in methods.values():
                if 'parameters' in method:
                    for parameter in method['parameters']:
                        if parameter['name'] in vba.vba_restricted_keywords:
                            parameter['name'] = vba.vba_restricted_keywords[parameter['name']]

    def validate_swagger_version(self):
        if 'swagger' not in self.swagger:
            raise Exception('Swagger version is not provided.')
        if self.swagger['swagger'] != '2.0':
            raise Exception('PyxelRest does not support any other version (in this case "{}") than Swagger 2.0'.format(
                self.swagger['swagger']
            ))


def load_services():
    """
    Retrieve swagger JSON for each service defined in configuration file.
    :return: List of SwaggerService objects, size is the same one as the number of sections within configuration file
    (DEFAULT excluded).
    """
    config_parser = ConfigParser()
    file_path = os.path.join(os.getenv('APPDATA'), 'pyxelrest', 'services_configuration.ini')
    if not config_parser.read(file_path):
        raise Exception('"{0}" services configuration file cannot be read.'.format(file_path))
    logging.debug('Loading services from "{0}".'.format(file_path))
    loaded_services = []
    for service_name in config_parser.sections():
        try:
            loaded_services.append(SwaggerService(service_name, config_parser))
        except Exception as e:
            logging.error('"{0}" service will not be available: {1}'.format(service_name, e))
    check_for_duplicates(loaded_services)
    return loaded_services


def check_for_duplicates(loaded_services):
    services_by_prefix = {}
    for service in loaded_services:
        duplicates = services_by_prefix.get(service.udf_prefix, [])
        duplicates.append(service.name)
        services_by_prefix[service.udf_prefix] = duplicates
    for udf_prefix in services_by_prefix:
        service_names = services_by_prefix[udf_prefix]
        if len(service_names) > 1:
            logging.warning('{0} services will use the same "{1}" prefix, in case there is the same call available, '
                            'only the last declared one will be available.'.format(service_names, udf_prefix))
