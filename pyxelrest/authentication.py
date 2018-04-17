import logging
import os
from requests_auth.authentication import NTLM, OAuth2, HeaderApiKey, QueryApiKey, Basic, Auths
from requests_auth.oauth2_tokens import JsonTokenFileCache

logger = logging.getLogger(__name__)

oauth2_tokens_cache_path = os.path.join(os.getenv('APPDATA'), 'pyxelrest', 'configuration', 'tokens.json')
OAuth2.token_cache = JsonTokenFileCache(oauth2_tokens_cache_path)


def _create_authentication(service_config, open_api_security_definition, request_content):
    if 'oauth2' == open_api_security_definition.get('type'):
        oauth2_config = dict(service_config.oauth2)
        if open_api_security_definition.get('flow') == 'implicit':
            return OAuth2(authorization_url=open_api_security_definition.get('authorizationUrl', request_content.extra_parameters.get('oauth2_auth_url')),
                          redirect_uri_port=oauth2_config.pop('port', None),
                          token_reception_timeout=oauth2_config.pop('timeout', None),
                          token_reception_success_display_time=oauth2_config.pop('success_display_time', None),
                          token_reception_failure_display_time=oauth2_config.pop('failure_display_time', None),
                          **oauth2_config)
        # TODO Handle all OAuth2 flows
        logger.warning('OAuth2 flow is not supported: {0}'.format(open_api_security_definition))
    elif 'apiKey' == open_api_security_definition.get('type'):
        if open_api_security_definition['in'] == 'query':
            return QueryApiKey(service_config.api_key, open_api_security_definition['name'])
        return HeaderApiKey(service_config.api_key, open_api_security_definition['name'])
    elif 'basic' == open_api_security_definition.get('type'):
        return Basic(service_config.basic.get('username'), service_config.basic.get('password'))
    else:
        logger.error('Unexpected security definition type: {0}'.format(open_api_security_definition))


def get_auth(udf_method, request_content):
    if not udf_method.requires_authentication(request_content):
        return None

    security_definitions = udf_method.service.open_api_definition.get('securityDefinitions', {})

    securities = udf_method.security(request_content)
    ntlm_config = udf_method.service.config.ntlm_auth
    ntlm_authentication = NTLM(ntlm_config.get('username'), ntlm_config.get('password')) if ntlm_config else None

    # Run through all available securities
    for security in securities:
        authentication_modes = [ntlm_authentication] if ntlm_authentication else []
        for security_definition_key in security.keys():
            try:
                auth = _create_authentication(udf_method.service.config, security_definitions.get(security_definition_key, {}), request_content)
                if auth:
                    authentication_modes.append(auth)
            except:
                logger.exception('{0} authentication cannot be handled.'.format(security_definition_key))
        # A single authentication method is required and PyxelRest support it
        if len(authentication_modes) == 1:
            return authentication_modes[0]
        # Multiple authentication methods are required and PyxelRest support it
        if len(authentication_modes) > 1:
            return Auths(authentication_modes)
        # Otherwise check if there is another security available

    # Default to custom authentication if no security is supported
    return ntlm_authentication
