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

import json
import urllib

from oauthlib.oauth2 import FatalClientError, OAuth2Error

from keystone import exception
from keystone.common import controller
from keystone.common import dependency
from keystone.common import wsgi
from keystone.contrib.oauth2 import core
from keystone.contrib.oauth2 import validator
from keystone.i18n import _
from keystone.models import token_model
from keystone.openstack.common import log

LOG = log.getLogger(__name__)

@dependency.requires('oauth2_api')
class ConsumerCrudV3(controller.V3Controller):

    collection_name = 'consumers'
    member_name = 'consumer'

    @classmethod
    def base_url(cls, context, path=None):
        """Construct a path and pass it to V3Controller.base_url method."""

        path = '/OS-OAUTH2/' + cls.collection_name
        return super(ConsumerCrudV3, cls).base_url(context, path=path)

    @controller.protected()
    def list_consumers(self, context):
        ref = self.oauth2_api.list_consumers()
        return ConsumerCrudV3.wrap_collection(context, ref)

    @controller.protected()
    def create_consumer(self, context, consumer):
        ref = self._assign_unique_id(self._normalize_dict(consumer))
        consumer_ref = self.oauth2_api.create_consumer(ref)
        return ConsumerCrudV3.wrap_member(context, consumer_ref)

    @controller.protected()
    def get_consumer(self, context, consumer_id):
        consumer_ref = self.oauth2_api.get_consumer_with_secret(consumer_id)
        return ConsumerCrudV3.wrap_member(context, consumer_ref)

    @controller.protected() 
    def update_consumer(self, context, consumer_id, consumer):
        self._require_matching_id(consumer_id, consumer)
        ref = self._normalize_dict(consumer)
        self._validate_consumer_ref(ref)
        ref = self.oauth2_api.update_consumer(consumer_id, ref)
        return ConsumerCrudV3.wrap_member(context, ref)

    def _validate_consumer_ref(self, consumer):
        if 'secret' in consumer:
            msg = _('Cannot change consumer secret')
            raise exception.ValidationError(message=msg)

    @controller.protected()
    def delete_consumer(self, context, consumer_id):
        self.oauth2_api.delete_consumer(consumer_id)

@dependency.requires('oauth2_api')
class AuthorizationCodeEndpointV3(controller.V3Controller):

    collection_name = 'authorization_codes'
    member_name = 'authorization_code'

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        # NOTE: overriding method to add proper path to self link
        ref.setdefault('links', {})
        path = '/OS-OAUTH2/users/%(user_id)s/authorization_codes' % {
           'user_id': cls._get_user_id(ref)
        }
        ref['links']['self'] = cls.base_url(context, path) + '/' + ref['authorizing_user_id']

    @staticmethod
    def _get_user_id(entity):
        return entity.get('authorizing_user_id', '')

    @controller.protected()
    def list_authorization_codes(self, context, user_id):
        """Description of the controller logic."""
        ref = self.oauth2_api.list_authorization_codes(user_id=user_id)
        return AuthorizationCodeEndpointV3.wrap_collection(context, ref)

@dependency.requires('oauth2_api')
class AccessTokenEndpointV3(controller.V3Controller):

    collection_name = 'access_tokens'
    member_name = 'access_token'

    @classmethod
    def _add_self_referential_link(cls, context, ref):
        # NOTE(garcianavalon): overriding method to add proper path to self link
        ref.setdefault('links', {})
        path = '/users/%(user_id)s/OS-OAUTH2/access_tokens' % {
            'user_id': cls._get_user_id(ref)
        }
        ref['links']['self'] = cls.base_url(context, path) + '/' + ref['id']

    @staticmethod
    def _get_user_id(entity):
        return entity.get('authorizing_user_id', '')

    @controller.protected()
    def list_access_tokens(self, context, user_id):
        """List authorized access tokens. """
        ref = self.oauth2_api.list_access_tokens(user_id=user_id)
        return AccessTokenEndpointV3.wrap_collection(context, ref)

    @controller.protected()
    def get_access_token(self, context, user_id, access_token_id):
        """Get access token. """
        ref = self.oauth2_api.get_access_token(access_token_id, user_id=user_id)
        return AccessTokenEndpointV3.wrap_member(context, ref)

    @controller.protected()
    def revoke_access_token(self, context, user_id, access_token_id):
        """Revokes an access token"""
        self.oauth2_api.revoke_access_token(access_token_id, user_id=user_id)

@dependency.requires('oauth2_api', 'token_provider_api')  
class OAuth2ControllerV3(controller.V3Controller):

    collection_name = 'not_used'
    member_name = 'not_used'

    def _extract_user_id_from_token(self, token_id):
        user_token = token_model.KeystoneToken(
                            token_id=token_id,
                            token_data=self.token_provider_api.validate_token(
                                token_id))
        return user_token.user_id

    @controller.protected()
    def request_authorization_code(self, context):
        request_validator = validator.OAuth2Validator()
        server = core.Server(request_validator)
        # Validate request
        headers = context['headers']
        body = context['query_string']
        uri = self.base_url(context, context['path'])
        http_method = 'GET'

        response = {}
        try:
            scopes, credentials = server.validate_authorization_request(
                uri, http_method, body, headers)
            # scopes will hold default scopes for client, i.e.
            #['https://example.com/userProfile', 'https://example.com/pictures']

            # credentials is a dictionary of
            # {
            #     'client_id': 'foo',
            #     'redirect_uri': 'https://foo.com/welcome_back',
            #     'response_type': 'code',
            #     'state': 'randomstring',
            #     'request' : The request object created internally. 
            # }
            # these credentials will be needed in the post authorization view and
            # should be persisted between. None of them are secret but take care
            # to ensure their integrity if embedding them in the form or cookies.

            # NOTE(garcianavalon) We are not storing this for now, 
            # but might do it in the future
            request = credentials.pop('request')
            
            # get the user id to identify the credentials in later stages
            credentials['user_id'] = self._extract_user_id_from_token(
                                                    context['token_id'])
            credentials_ref = self._assign_unique_id(self._normalize_dict(credentials))
            self.oauth2_api.store_consumer_credentials(credentials_ref)

            # Present user with a nice form where client (id foo) request access to
            # his default scopes (omitted from request), after which you will
            # redirect to his default redirect uri (omitted from request).
            
            # This JSON is to be used by the next layer (ie a Django server) to 
            # populate the view
            response['data'] = { 
                'consumer': {
                    'id':credentials['client_id']
                    # TODO(garcianavalon) add consumer description
                },
                'redirect_uri':credentials['redirect_uri'],
                'requested_scopes':request.scopes
            }
            LOG.info('OAUTH2: Requested Authorization Code by consumer %(consumer)s \
                to user %(user)s, with scope %(scope)s and redirect uri %(uri)s', {
                    'consumer': credentials['client_id'],
                    'user': credentials['user_id'],
                    'scope': request.scopes,
                    'uri': credentials['redirect_uri']})

        except FatalClientError as e:
            # NOTE(garcianavalon) form the OAuthLib documentation and comments:
            # Errors during authorization where user should not be redirected back.
            # If the request fails due to a missing, invalid, or mismatching
            # redirection URI, or if the client identifier is missing or invalid,
            # the authorization server SHOULD inform the resource owner of the
            # error and MUST NOT automatically redirect the user-agent to the
            # invalid redirection URI.
            # Instead the user should be informed of the error by the provider itself.
            # Fatal errors occur when the client_id or redirect_uri is invalid or
            # missing. These must be caught by the provider and handled, how this
            # is done is outside of the scope of OAuthLib but showing an error
            # page describing the issue is a good idea.
            msg = e.json
            LOG.warning('OAUTH2: FatalClientError %s' %msg)
            raise exception.ValidationError(message=msg)

        except OAuth2Error as e:
            # NOTE(garcianavalon) form the OAuthLib documentation and comments:
            # A normal error could be a missing response_type parameter or the client
            # attempting to access scope it is not allowed to ask authorization for.
            # Normal errors can safely be included in the redirection URI and
            # sent back to the client.

            # We send back the errors in the response body
            response['error'] = json.loads(e.json)
            LOG.warning('OAUTH2: OAuth2Error %s' %response['error'])            

        return response
            

    # @controller.protected()
    def create_authorization_code(self, context, user_auth):
        request_validator = validator.OAuth2Validator()
        server = core.Server(request_validator)
        # Validate request
        headers = context['headers']
        body = user_auth
        uri = self.base_url(context, context['path'])
        http_method = 'POST'

        # Fetch authorized scopes from the request
        scopes = body.get('scopes')
        if not scopes:
            raise exception.ValidationError(attribute='scopes', target='request')

        # Fetch the credentials saved in the pre authorization phase
        client_id = body.get('client_id')
        if not client_id:
            raise exception.ValidationError(attribute='client_id', target='request')

        user_id = body.get('user_id')
        if not user_id:
            # Try to extract the user_id from the token
            user_id = self._extract_user_id_from_token(context['token_id'])

        credentials = self.oauth2_api.get_consumer_credentials(
            client_id, user_id)

        try:

            headers, body, status = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            # headers = {'Location': 'https://foo.com/welcome_back?code=somera
            # ndomstring&state=xyz  '}, this might change to include suggested
            # headers related to cache best practices etc.
            # body = '', this might be set in future custom grant types
            # status = 302, suggested HTTP status code

            response = wsgi.render_response(body,
                                            status=(302, 'Found'),
                                            headers=headers.items())
            
            LOG.info('OAUTH2: Created Authorization Code to consumer %(consumer)s \
                for user %(user)s with scope %(scope)s. Redirecting to %(uri)s', {
                    'consumer': client_id,
                    'user': user_id,
                    'scope': scopes,
                    'uri': headers['Location']})

            return response
        except FatalClientError as e:
            # NOTE(garcianavalon) form the OAuthLib documentation and comments:
            # Errors during authorization where user should not be redirected back.
            # If the request fails due to a missing, invalid, or mismatching
            # redirection URI, or if the client identifier is missing or invalid,
            # the authorization server SHOULD inform the resource owner of the
            # error and MUST NOT automatically redirect the user-agent to the
            # invalid redirection URI.
            # Instead the user should be informed of the error by the provider itself.
            # Fatal errors occur when the client_id or redirect_uri is invalid or
            # missing. These must be caught by the provider and handled, how this
            # is done is outside of the scope of OAuthLib but showing an error
            # page describing the issue is a good ideaself.
            msg = e.json
            LOG.warning('OAUTH2: FatalClientError %s' %msg)
            raise exception.ValidationError(message=msg)

    def create_access_token(self, context, token_request):
        request_validator = validator.OAuth2Validator()
        server = core.Server(request_validator)

        # Validate request
        headers = context['headers']
        # NOTE(garcianavalon) Work around the keystone limitation with content types
        # Keystone only accepts JSON bodies while OAuth2.0 (RFC 6749) requires 
        # x-www-form-urlencoded
        # We leave it like this to support future versions where the use of 
        # x-www-form-urlencoded is accepted
        if headers['Content-Type'] == 'application/x-www-form-urlencoded':
            body = context['query_string']
        elif headers['Content-Type'] == 'application/json':
            # TODO(garcianavalon) are these checks really necessary or
            # can we delegate them to oauthlib?
            grant_type = token_request.get('grant_type', None)
            if not grant_type:
                msg = _('grant_type missing in request body: {0}'
                    ).format(token_request)
                raise exception.ValidationError(message=msg)
            if (grant_type == 'authorization_code' 
                and not 'code' in token_request):

                msg = _('code missing in request body: %s') %token_request
                raise exception.ValidationError(message=msg)

            body = urllib.urlencode(token_request)
        else:
            msg = _('Content-Type: %s is not supported') %headers['Content-Type']
            raise exception.ValidationError(message=msg) 

        # check headers for authentication
        authmethod, auth = headers['Authorization'].split(' ', 1)
        if authmethod.lower() != 'basic':
            msg = _('Authorization error: %s. Only HTTP Basic is supported') %headers['Authorization']
            raise exception.ValidationError(message=msg)

        uri = self.base_url(context, context['path'])
        http_method = 'POST'
        
        # Extra credentials you wish to include
        credentials = None # TODO(garcianavalon)

        headers, body, status = server.create_token_response(
            uri, http_method, body, headers, credentials)

        # headers will contain some suggested headers to add to your response
        # {
        #     'Content-Type': 'application/json',
        #     'Cache-Control': 'no-store',
        #     'Pragma': 'no-cache',
        # }
        # body will contain the token in json format and expiration from now
        # in seconds.
        # {
        #     'access_token': 'sldafh309sdf',
        #     'refresh_token': 'alsounguessablerandomstring',
        #     'expires_in': 3600,
        #     'scope': 'https://example.com/userProfile https://example.com/pictures',
        #     'token_type': 'Bearer'
        # }
        # body will contain an error code and possibly an error description if
        # the request failed, also in json format.
        # {
        #     'error': 'invalid_grant_type',
        #     'description': 'athorizatoin_coed is not a valid grant type'
        # }
        # status will be a suggested status code, 200 on ok, 400 on bad request
        # and 401 if client is trying to use an invalid authorization code,
        # fail to authenticate etc.

        # NOTE(garcianavalon) oauthlib returns the body as a JSON string already,
        # and the Keystone base controlers expect a dictionary  
        body = json.loads(body)
        # TODO(garcianavalon) body contains scope instead of scopes and is only a
        # space separated string instead of a list. We can wait for a change in
        # Oauthlib or implement our own TokenProvider
        if status == 200:
            response = wsgi.render_response(body,
                                        status=(status, 'OK'),
                                        headers=headers.items())
            LOG.info('OAUTH2: Created Access Token %s' %body['access_token'])
            return response
        # Build the error message and raise the corresponding error
        msg = _(body['error'])
        if hasattr(body, 'description'):
            msg = msg + ': ' + _(body['description'])
        LOG.warning('OAUTH2: Error creating Access Token %s' %msg)
        if status == 400:
            raise exception.ValidationError(message=msg)
        elif status == 401:
            # TODO(garcianavalon) custom exception class
            raise exception.Unauthorized(message=msg)
