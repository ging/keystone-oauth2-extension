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

from __future__ import absolute_import

import abc
import six

from keystone import exception
from keystone import notifications
from keystone.common import dependency
from keystone.common import extension
from keystone.common import manager
from keystone.openstack.common import log

from oauthlib import oauth2 as oauth2lib


LOG = log.getLogger(__name__)

EXTENSION_DATA = {
    'name': 'OpenStack OAUTH2 API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/'
                 'OS-OAUTH2/v1.0',
    'alias': 'OS-OAUTH2',
    'updated': '2014-09-11T12:00:0-00:00',
    'description': 'Openstack OAuth2.0 Auth Mechanism',
    'links': [
        {
            'rel': 'describedby',
            # TODO(garcianavalon): needs a description
            'type': 'text/html',
            'href': 'https://github.com/openstack/identity-api',
        }
    ]}
extension.register_admin_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)
extension.register_public_extension(EXTENSION_DATA['alias'], EXTENSION_DATA)

def filter_consumer(consumer_ref):
    """Filter out private items in a consumer dict.

    'secret' is never returned.

    :returns: consumer_ref

    """
    if consumer_ref:
        consumer_ref = consumer_ref.copy()
        consumer_ref.pop('secret', None)
    return consumer_ref

class Server(oauth2lib.AuthorizationEndpoint, oauth2lib.TokenEndpoint, 
             oauth2lib.ResourceEndpoint, oauth2lib.RevocationEndpoint):

    """An OAuth2 Server configured with the grants we need."""

    def __init__(self, request_validator, token_expires_in=None,
                 token_generator=None, refresh_token_generator=None,
                 *args, **kwargs):
        """
        :param request_validator: An implementation of
                                  oauthlib.oauth2.RequestValidator.
        :param token_expires_in: An int or a function to generate a token
                                 expiration offset (in seconds) given a
                                 oauthlib.common.Request object.
        :param token_generator: A function to generate a token from a request.
        :param refresh_token_generator: A function to generate a token from a
                                        request for the refresh token.
        :param kwargs: Extra parameters to pass to authorization-,
                       token-, resource-, and revocation-endpoint constructors.
        """
        auth_grant = oauth2lib.AuthorizationCodeGrant(request_validator)
        implicit_grant = oauth2lib.ImplicitGrant(request_validator)
        password_grant = oauth2lib.ResourceOwnerPasswordCredentialsGrant(
            request_validator)
        credentials_grant = oauth2lib.ClientCredentialsGrant(request_validator)
        refresh_grant = oauth2lib.RefreshTokenGrant(request_validator)
        bearer = oauth2lib.BearerToken(request_validator, token_generator,
                             token_expires_in, refresh_token_generator)
        oauth2lib.AuthorizationEndpoint.__init__(
            self, 
            default_response_type='code',
            response_types={
               'code': auth_grant,
               'token': implicit_grant,
            },
            default_token_type=bearer)
        oauth2lib.TokenEndpoint.__init__(
            self, 
            default_grant_type='authorization_code',
            grant_types={
               'authorization_code': auth_grant,
               'password': password_grant,
               'client_credentials': credentials_grant,
               'refresh_token': refresh_grant,
            },
            default_token_type=bearer)
        oauth2lib.ResourceEndpoint.__init__(self, default_token='Bearer',
                                  token_types={'Bearer': bearer})
        oauth2lib.RevocationEndpoint.__init__(self, request_validator)



@dependency.provider('oauth2_api')
class Manager(manager.Manager):
    """Manager.

    See :mod:`keystone.common.manager.Manager` for more details on
    how this dynamically calls the backend.

    """
    _CONSUMER = 'consumer_oauth2'

    def __init__(self):
        super(Manager, self).__init__(
            'keystone.contrib.oauth2.backends.sql.OAuth2')# TODO(garcianavalon) set as configuration option in keystone.conf

    # TODO(garcianavalon) revoke tokens on consumer delete
    # TODO(garcianavalon) revoke Identity tokens issued by an access token on token revokation
    
    
    @notifications.deleted(_CONSUMER)
    def delete_consumer(self, consumer_id):
        ret_val = self.driver.delete_consumer(consumer_id)
        
        # delete all the stored credentials
        self.driver.delete_consumer_credentials(consumer_id)

        # and the authorization codes
        self.driver.delete_authorization_codes(consumer_id)

        # and the issued tokens
        self.driver.delete_access_tokens(consumer_id)

        return ret_val

    @notifications.updated(_CONSUMER)
    def update_consumer(self, consumer_id, consumer_ref):
        ret_val = self.driver.update_consumer(consumer_id, consumer_ref)
        # TODO(garcianavalon) also delete on scopes or grant_type changes
        if 'redirect_uris' not in consumer_ref:
            return ret_val

        # delete all the stored credentials
        self.driver.delete_consumer_credentials(consumer_id)

        # and the authorization codes
        self.driver.delete_authorization_codes(consumer_id)

        # and the issued tokens
        self.driver.delete_access_tokens(consumer_id)

        return ret_val


@dependency.requires('identity_api')
@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    """Interface description for OAuth2 drivers"""

    # CONSUMERS
    @abc.abstractmethod
    def list_consumers(self):
        """List all registered consumers

        :returns: List of registered consumers

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_consumer(self, consumer):
        """Register a consumer

        :param consumer: consumer data
        :type consumer: dict
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_consumer(self, consumer_id):
        """Get consumer details, except the private ones
        like secret.

        :param consumer_id: id of consumer
        :type consumer_id: string
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_consumer_with_secret(self, consumer_id):
        """Like get_consumer() but returned consumer_ref includes
        the consumer secret.

        Secrets should only be shared upon consumer creation; the
        consumer secret is required to verify incoming OAuth requests.

        :param consumer_id: id of consumer to get
        :type consumer_id: string
        :returns: consumer_ref

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def update_consumer(self, consumer_id, consumer):
        """Update consumer details

        :param consumer_id: id of consumer to update
        :type consumer_id: string
        :param consumer: new consumer data
        :type consumer: dict
        :returns: consumer

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_consumer(self, consumer_id):
        """Delete consumer.

        :param consumer_id: id of consumer to delete
        :type consumer_id: string
        :returns: None.

        """
        raise exception.NotImplemented()

    # AUTHORIZATION CODES
    @abc.abstractmethod
    def list_authorization_codes(self, user_id):
        """List authorization codes.

        :param user_id: search for authorization codes authorized by given user id
        :type user_id: string
        :returns: list of authorization codes the user has authorized

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_authorization_code(self, code):
        """Get an authorization_code. Should never be exposed by the API, its
        called from the oauth2 flow through the validator

        :param code: the code
        :type code: string
        :returns: authorization_code as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def store_authorization_code(self, authorization_code):
        """Stores an authorization_code. This should never be exposed by the
        API, its called from the oauth2 flow through the validator

        :param authorization_code: All the requiered info
        :type authorization_code: dict
        :returns: Nothing

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def invalidate_authorization_code(self, code):
        """Invalidate an authorization_code.
        This method is called from the oauth2 flow through the validator but it
        is safe to expose it in the REST API if the use case is needed.

        :param code: the code
        :type code: string
        :returns: Nothing

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_authorization_codes(self, client_id):
        """Deletes all the authorization_codes issued for a consumer.

        :param client_id: client_id
        :type client_id: string
        :returns: Nothing

        """
        raise exception.NotImplemented()

    # CONSUMER CREDENTIALS
    @abc.abstractmethod
    def store_consumer_credentials(self, credentials):
        """Saves the consumer credentials until the user gives authorization to it

        :param credentials: Contains all the requiered credentials from the client
        :type credentials: dict
        :returns: The stored credentials

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_consumer_credentials(self, client_id, user_id):
        """Retrieves the consumer credentials saved when the authorization request

        :param client_id: client_id
        :type client_id: string
        :param user_id: the id of the keystone user that stored the client credentials
            in the request_authorization step
        :type user_id: string
        :returns: The stored credentials

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_consumer_credentials(self, client_id):
        """Deletes all the consumer credentials stored from authorization requests

        :param client_id: The id of the consumer
        :type client_id: string
        :returns: Nothing

        """
        raise exception.NotImplemented()

    # ACCESS TOKEN
    @abc.abstractmethod
    def list_access_tokens(self, user_id=None):
        """Lists all the access tokens granted by a user.

        :param user_id: optional filter to check the token belongs to a user
        :type user_id: string
        :returns: access_token as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_access_token(self, access_token_id, user_id=None):
        """Get an already existent access_token. If exposed by the Identity
         API, use the user_id check.

        :param access_token_id: the access_token_id (the string itself)
        :type access_token_id: string
        :param user_id: optional filter to check the token belongs to a user
        :type user_id: string
        :returns: access_token as dict

        """
        raise exception.NotImplemented()

    
    @abc.abstractmethod
    def revoke_access_token(self, access_token_id, user_id=None):
        """Invalidate an access token.

        :param access_token_id: the access_token_id (the string itself)
        :type access_token_id: string
        :param user_id: optional filter to check the token belongs to a user
        :type user_id: string
        :returns: access_token as dict

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def store_access_token(self, access_token):
        """Stores an access_token created by the validator. Should never be
         exposed by the Identity API.

        :param access_token: All the requiered info
        :type access_token: dict
        :returns: Nothing

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_access_tokens(self, client_id):
        """Deletes all the access tokens issued for a consumer.

        :param client_id: The id of the consumer
        :type client_id: string
        :returns: Nothing

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_access_token_by_refresh_token(self, refresh_token):
        """Obtains the access_token associated with a refresh token.

        :param refresh_token: The refresh token issued with the access token.
        :type refresh_token: string
        :returns: access_token as dict

        """
        raise exception.NotImplemented()