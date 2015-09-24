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
import functools

from keystone.common import json_home
from keystone.common import wsgi
from keystone.contrib import oauth2
from keystone.contrib.oauth2 import controllers

build_resource_relation = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-OAUTH2', extension_version='1.0')

build_parameter_relation = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-OAUTH2', extension_version='1.0')

class OAuth2Extension(wsgi.V3ExtensionRouter):
    """API Endpoints for the OAuth2 extension.

    The goal of this extension is to allow third-party service providers
    to acquire tokens with a limited subset of a user's roles for acting
    on behalf of that user. This is done using an oauth-similar flow and
    api.

    The API looks like::

      # Basic admin-only consumer crud
      POST /OS-OAUTH2/consumers
      GET /OS-OAUTH2/consumers
      PATCH /OS-OAUTH2/consumers/$consumer_id
      GET /OS-OAUTH2/consumers/$consumer_id
      DELETE /OS-OAUTH2/consumers/$consumer_id

      # User access token endpoint
      GET /users/$user_id/OS-OAUTH2/access_tokens
      GET /users/$user_id/OS-OAUTH2/access_tokens/{access_token_id}
      DELETE /users/$user_id/OS-OAUTH2/access_tokens/{access_token_id} # revoke an access token

      # OAuth interfaces
      GET /OS-OAUTH2/authorize # request authorization
      POST /OS-OAUTH2/authorize  # authorize a consumer
      POST /OS-OAUTH2/access_token  # create an access token
    """

    PATH_PREFIX = '/OS-OAUTH2'

    def add_routes(self, mapper):
        consumer_controller = controllers.ConsumerCrudV3()
        access_token_controller = controllers.AccessTokenEndpointV3()
        authorization_code_controller = controllers.AuthorizationCodeEndpointV3()
        oauth2_controller = controllers.OAuth2ControllerV3() 

        # Admin only consumer CRUD
        self._add_resource(
            mapper, consumer_controller,
            path=self.PATH_PREFIX + '/consumers',
            get_action='list_consumers',
            post_action='create_consumer',
            rel=build_resource_relation(resource_name='consumers'))

        self._add_resource(
            mapper, consumer_controller,
            path=self.PATH_PREFIX + '/consumers/{consumer_id}',
            get_action='get_consumer',
            patch_action='update_consumer',
            delete_action='delete_consumer',
            rel=build_resource_relation(resource_name='consumer'),
            path_vars={
                'consumer_id':
                build_parameter_relation(parameter_name='consumer_id'),
            })

        # Resource Owner CRUD for Access Tokens
        self._add_resource(
            mapper, access_token_controller,
            path='/users/{user_id}' + self.PATH_PREFIX + '/access_tokens',
            get_action='list_access_tokens',
            rel=build_resource_relation(resource_name='access_tokens'),
            path_vars={
                'user_id':
                build_parameter_relation(parameter_name='user_id'),
            })
        
        self._add_resource(
            mapper, access_token_controller,
            path='/users/{user_id}' + self.PATH_PREFIX + '/access_tokens/{access_token_id}',
            get_action='get_access_token',
            delete_action='revoke_access_token',
            rel=build_resource_relation(resource_name='access_token'),
            path_vars={
                'user_id': build_parameter_relation(parameter_name='user_id'),
                'access_token_id': build_parameter_relation(parameter_name='access_token_id'),
            })

        # Resource Owner endpoint for Authorization Codes
        self._add_resource(
            mapper, authorization_code_controller,
            path=self.PATH_PREFIX + '/users/{user_id}/authorization_codes',
            get_action='list_authorization_codes',
            rel=build_resource_relation(resource_name='authorization_code'),
            path_vars={
                'user_id':
                build_parameter_relation(parameter_name='user_id'),
            })
        
        # OAuth2 flow calls
        self._add_resource(
            mapper, oauth2_controller,
            path=self.PATH_PREFIX + '/authorize',
            post_action='create_authorization_code',
            get_action='request_authorization_code',
            rel=build_resource_relation(resource_name='authorization_code'))

        self._add_resource(
            mapper, oauth2_controller,
            path=self.PATH_PREFIX + '/access_token',
            post_action='create_access_token',
            rel=build_resource_relation(resource_name='access_tokens'))

        