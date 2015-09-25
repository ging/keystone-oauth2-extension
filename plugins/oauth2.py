# Copyright 2013 OpenStack Foundation
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

from keystone import auth
from keystone import exception
from keystone.common import controller
from keystone.common import dependency
from keystone.contrib.oauth2 import core as oauth2_core
from keystone.contrib.oauth2 import validator
from keystone.i18n import _
from keystone.openstack.common import log


LOG = log.getLogger(__name__)

@dependency.optional('oauth2_api')
class OAuth2(auth.AuthMethodHandler):

    method = 'oauth2'

    def authenticate(self, context, auth_payload, auth_context):
        """Turn a signed request with an access key into a keystone token."""
        if not self.oauth2_api:
            raise exception.Unauthorized(_('%s not supported') % self.method)

        access_token_id = auth_payload['access_token_id']
        if not access_token_id:
            raise exception.ValidationError(
                attribute='oauth2_token', target='request')

        headers = context['headers']
        uri = controller.V3Controller.base_url(context, context['path'])
        http_method = 'POST'
        required_scopes = ['all_info']
        request_validator = validator.OAuth2Validator()
        server = oauth2_core.Server(request_validator)
        body = {
            'access_token':access_token_id
        }
        valid, oauthlib_request = server.verify_request(
            uri, http_method, body, headers, required_scopes)
        # oauthlib_request has a few convenient attributes set such as
        # oauthlib_request.client = the client associated with the token
        # oauthlib_request.user = the user associated with the token
        # oauthlib_request.scopes = the scopes bound to this token
        if valid:
            auth_context['user_id'] = oauthlib_request.user
            #auth_context['access_token_id'] = access_token_id
            #auth_context['project_id'] = project_id
            return None
        else:
            msg = _('Could not validate the access token')
            raise exception.Unauthorized(msg)
