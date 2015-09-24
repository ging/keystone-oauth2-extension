# Copyright (C) 2014 Universidad Politecnica de Madrid
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime

from keystone import exception
from keystone.auth import plugins as auth_plugins
from keystone.common import dependency
from keystone.openstack.common import log
from oauthlib.oauth2 import RequestValidator

from oslo.utils import timeutils

METHOD_NAME = 'oauth2_validator'
LOG = log.getLogger(__name__)

@dependency.requires('oauth2_api')
class OAuth2Validator(RequestValidator):
    """OAuthlib request validator."""
    # Ordered roughly in order of appearance in the authorization grant flow

    # Pre- and post-authorization.
    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        client_dict = self.oauth2_api.get_consumer(client_id)
        if client_dict:
            return True
        # NOTE(garcianavalon) Currently the sql driver raises an exception 
        # if the consumer doesnt exist so we throw the Keystone NotFound 
        # 404 Not Found exception instead of the OAutlib InvalidClientId 
        # 400 Bad Request exception.
        return False 

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        client_dict = self.oauth2_api.get_consumer(client_id)
        registered_uris = client_dict['redirect_uris']  
        return redirect_uri in registered_uris

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        # TODO(garcianavalon) implement
        pass

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        if not scopes:
            return True # the client is not requesting any scope

        client_dict = self.oauth2_api.get_consumer(client_id)

        if not client_dict['scopes']:
            return False # the client isnt allowed any scopes

        for scope in scopes:
            if not scope in client_dict['scopes']:
                return False
        return True      

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        # TODO(garcianavalon) implement
        pass

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.

        # FIXME(garcianavalon) we need to support multiple grant types
        # for the same consumers right now. In the future we should
        # separate them and only allow one grant type (registering
        # each client one time for each grant or allowing components)
        # or update the tools to allow to create clients with 
        # multiple grants

        # client_dict = self.oauth2_api.get_consumer(client_id)
        # allowed_response_type = client_dict['response_type']
        # return allowed_response_type == response_type
        return True

    # Post-authorization
    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client, request.state and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        authorization_code = {
            'code': code['code'], # code is a dict with state and the code
            'consumer_id': client_id,
            'scopes': request.scopes,
            'authorizing_user_id': request.user_id, # populated through the credentials
            'state': request.state,
            'redirect_uri': request.redirect_uri
        }
        token_duration = 28800 # TODO(garcianavalon) extract as configuration option
        # TODO(garcianavalon) find a better place to do this
        now = timeutils.utcnow()
        future = now + datetime.timedelta(seconds=token_duration)
        expiry_date = timeutils.isotime(future, subsecond=True)
        authorization_code['expires_at'] = expiry_date
        self.oauth2_api.store_authorization_code(authorization_code)

    # Token request
    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work 
        # TODO(garcianavalon) write it cleaner
        LOG.debug('OAUTH2: authenticating client')
        authmethod, auth = request.headers['Authorization'].split(' ', 1)
        auth = auth.decode('unicode_escape')
        if authmethod.lower() == 'basic':
            auth = auth.decode('base64')
            client_id, secret = auth.split(':', 1)
            client_dict = self.oauth2_api.get_consumer_with_secret(client_id)
            if client_dict['secret'] == secret:
                # TODO(garcianavalon) this can be done in a cleaner way 
                #if we change the consumer model attribute to client_id
                request.client = type('obj', (object,), 
                    {'client_id' : client_id})
                LOG.info('OAUTH2: succesfully authenticated client %s',
                    client_dict['name'])
                return True
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        # TODO(garcianavalon) check this method
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes, request.state and request.user.
        authorization_code = self.oauth2_api.get_authorization_code(code)
        if not authorization_code['valid']:
            return False
        if not authorization_code['consumer_id'] == request.client.client_id:
            return False
        request.scopes = authorization_code['scopes']
        request.state = authorization_code['state']
        request.user = authorization_code['authorizing_user_id']
        return True
        
    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        authorization_code = self.oauth2_api.get_authorization_code(code)
        return authorization_code['redirect_uri'] == redirect_uri

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.

        # FIXME(garcianavalon) we need to support multiple grant types
        # for the same consumers right now. In the future we should
        # separate them and only allow one grant type (registering
        # each client one time for each grant or allowing components)
        # or update the tools to allow to create clients with 
        # multiple grants
        # # client_id comes as None, we use the one in request
        # client_dict = self.oauth2_api.get_consumer(request.client.client_id)
        # return grant_type == client_dict['grant_type']

        # TODO(garcianavalon) sync with SQL backend soported grant_types
        return grant_type in [
            'password', 'authorization_code', 'client_credentials', 'refresh_token',
        ]

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
 

        # token is a dictionary with the following elements:
        # { 
        #     u'access_token': u'iC1DQuu7zOgNIjquPXPmXE5hKnTwgu', 
        #     u'expires_in': 3600, 
        #     u'token_type': u'Bearer', 
        #     u'state': u'yKxWeujbz9VUBncQNrkWvVcx8EXl1w', 
        #     u'scope': u'basic_scope', 
        #     u'refresh_token': u'02DTsL6oWgAibU7xenvXttwG80trJC'
        # }

        # TODO(garcinanavalon) create a custom TokenCreator instead of
        # hacking the dictionary

        if getattr(request, 'client', None):
            consumer_id = request.client.client_id
        else:
            consumer_id = request.client_id

        if getattr(request, 'user', None):
            user_id = request.user
        else:
            user_id = request.user_id

        expires_at = datetime.datetime.today() + datetime.timedelta(seconds=token['expires_in'])
        access_token = {
            'id':token['access_token'],
            'consumer_id':consumer_id,
            'authorizing_user_id':user_id,
            'scopes': request.scopes,
            'expires_at':datetime.datetime.strftime(expires_at, '%Y-%m-%d %H:%M:%S'),
            'refresh_token': token.get('refresh_token', None),
        }
        self.oauth2_api.store_access_token(access_token)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        self.oauth2_api.invalidate_authorization_code(code)
        
    # Protected resource request
    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        try:
            access_token = self.oauth2_api.get_access_token(token)
        except exception.NotFound:
            return False

        if (datetime.datetime.strptime(access_token['expires_at'], '%Y-%m-%d %H:%M:%S') 
            < datetime.datetime.today()):
            return False

        if access_token['scopes'] != scopes:
            return False
        # NOTE(garcianavalon) we set some attributes in request for later use. There
        # is no documentation about this so I follow the comments found in the example
        # at https://oauthlib.readthedocs.org/en/latest/oauth2/endpoints/resource.html
        # which are:
        # oauthlib_request has a few convenient attributes set such as
        # oauthlib_request.client = the client associated with the token
        # oauthlib_request.user = the user associated with the token
        # oauthlib_request.scopes = the scopes bound to this token
        # request.scopes is set by oauthlib already
        request.user = access_token['authorizing_user_id']
        request.client = access_token['consumer_id']
        return True

    # Token refresh request
    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        # TODO(garcianavalon)
        return ['all_info']

    def is_within_original_scope(self, request_scopes, refresh_token, request, *args, **kwargs):
        """Check if requested scopes are within a scope of the refresh token.
        When access tokens are refreshed the scope of the new token
        needs to be within the scope of the original token. This is
        ensured by checking that all requested scopes strings are on
        the list returned by the get_original_scopes. If this check
        fails, is_within_original_scope is called. The method can be
        used in situations where returning all valid scopes from the
        get_original_scopes is not practical.
        :param request_scopes: A list of scopes that were requested by client
        :param refresh_token: Unicode refresh_token
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False
        Method is used by:
            - Refresh token grant
        """
        # TODO(garcianavalon)
        return True

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Ensure the Bearer token is valid and authorized access to scopes.
        OBS! The request.user attribute should be set to the resource owner
        associated with this refresh token.
        :param refresh_token: Unicode refresh token
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False
        Method is used by:
            - Authorization Code Grant (indirectly by issuing refresh tokens)
            - Resource Owner Password Credentials Grant (also indirectly)
            - Refresh Token Grant
        """
        try:
            access_token = self.oauth2_api.get_access_token_by_refresh_token(refresh_token)
            
            # Validate that the refresh token is not expired
            token_duration = 28800 # TODO(garcianavalon) extract as configuration option
            refresh_token_duration = 14 # TODO(garcianavalon) extract as configuration option
            
            # TODO(garcianavalon) find a better place to do this
            access_token_expiration_date = datetime.datetime.strptime(
                access_token['expires_at'], '%Y-%m-%d %H:%M:%S')

            refres_token_expiration_date = (
                access_token_expiration_date 
                - datetime.timedelta(seconds=token_duration) 
                + datetime.timedelta(days=refresh_token_duration))

            if refres_token_expiration_date < datetime.datetime.today():
                return False

        except exception.NotFound:
            return False

        request.user = access_token['authorizing_user_id']
        
        return True


    # Support for password grant
    def validate_user(self, username, password, client, request, 
                      *args, **kwargs):
        """Ensure the username and password is valid.
        OBS! The validation should also set the user attribute of the request
        to a valid resource owner, i.e. request.user = username or similar. If
        not set you will be unable to associate a token with a user in the
        persistance method used (commonly, save_bearer_token).
        :param username: Unicode username
        :param password: Unicode password
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False
        Method is used by:
            - Resource Owner Password Credentials Grant
        """
        # To validate the user, try to authenticate it
        password_plugin = auth_plugins.password.Password()
        auth_payload = {
            'user': {
                "domain": {
                    "id": "default"
                },
                "name": username,
                "password": password
            }
        }
        auth_context = {}
        try:
            password_plugin.authenticate(
                context={},
                auth_payload=auth_payload,
                auth_context=auth_context)
            # set the request user
            request.user = auth_context['user_id']
            return True
        except Exception:
            return False