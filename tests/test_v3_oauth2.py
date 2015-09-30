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

import base64
import copy
import json
import urllib
import urlparse
import uuid

from keystone import config
from keystone.common import dependency
from keystone.contrib.oauth2 import core
from keystone.tests import test_v3

CONF = config.CONF

class OAuth2BaseTests(test_v3.RestfulTestCase):

    def auth_plugin_config_override(self, methods=None, **method_classes):
        super(OAuth2BaseTests, self).auth_plugin_config_override(
            methods=['external', 'password', 'token', 'oauth1', 'saml2', 'oauth2'],
            external='keystone.auth.plugins.external.DefaultDomain',
            password='keystone.auth.plugins.password.Password',
            token='keystone.auth.plugins.token.Token',
            oauth1='keystone.auth.plugins.oauth1.OAuth',
            saml2='keystone.auth.plugins.saml2.Saml2',
            oauth2='keystone.auth.plugins.oauth2.OAuth2'
        )

    EXTENSION_NAME = 'oauth2'
    EXTENSION_TO_ADD = 'oauth2_extension'

    PATH_PREFIX = '/OS-OAUTH2'
    CONSUMER_URL = PATH_PREFIX + '/consumers'
    USERS_URL = '/users/{user_id}'
    ACCESS_TOKENS_URL = PATH_PREFIX + '/access_tokens'

    DEFAULT_REDIRECT_URIS = [
        'https://%s.com' %uuid.uuid4().hex,
        'https://%s.com' %uuid.uuid4().hex
    ]
    DEFAULT_SCOPES = [
        uuid.uuid4().hex,
        uuid.uuid4().hex,
        'all_info'
    ]

    def setUp(self):
        super(OAuth2BaseTests, self).setUp()

        # Now that the app has been served, we can query CONF values
        self.base_url = 'http://localhost/v3'
        # NOTE(garcianavalon) I've put this line for dependency injection to work, 
        # but I don't know if its the right way to do it...
        self.manager = core.Manager()

    def _create_consumer(self, name=None, description=None,
                         client_type='confidential',
                         redirect_uris=DEFAULT_REDIRECT_URIS,
                         grant_type='authorization_code',
                         scopes=DEFAULT_SCOPES,
                         **kwargs):
        if not name:
            name = uuid.uuid4().hex
        data = {
            'name': name,
            'description': description,
            'client_type': client_type,
            'redirect_uris': redirect_uris,
            'grant_type': grant_type,
            'scopes': scopes
        }
        # extra
        data.update(kwargs)
        response = self.post(self.CONSUMER_URL, body={'consumer': data})

        return response.result['consumer'], data

    def _create_user_and_tenant(self):
        pass

class ConsumerCRUDTests(OAuth2BaseTests):


    def test_create_consumer(self):
        consumer, data = self._create_consumer()
        self.assertEqual(consumer['description'], data['description'])
        self.assertIsNotNone(consumer['id'])
        self.assertIsNotNone(consumer['name'])
        self.assertIsNotNone(consumer['secret'])
        # NOTE(garcianavalon) removed because owner field is removed
        # self.assertEqual(self.user['id'], consumer['owner'])

    def test_create_consumer_with_extra(self):
        extra_data = {
            'url': uuid.uuid4().hex,
            'image': uuid.uuid4().hex
        }
        consumer, data = self._create_consumer(**extra_data)
        self.assertEqual(consumer['description'], data['description'])
        self.assertIsNotNone(consumer['id'])
        self.assertIsNotNone(consumer['name'])
        self.assertIsNotNone(consumer['secret'])
        # NOTE(garcianavalon) removed because owner field is removed
        # self.assertEqual(self.user['id'], consumer['owner'])
        for k in extra_data:
            self.assertEqual(extra_data[k], consumer[k])

    def test_consumer_delete(self):
        consumer, data = self._create_consumer()
        consumer_id = consumer['id']
        response = self.delete(self.CONSUMER_URL + '/%s' % consumer_id,
                                expected_status=204)

    def test_consumer_delete_bad_id(self):
        consumer, data = self._create_consumer()
        consumer_id = uuid.uuid4().hex
        response = self.delete(self.CONSUMER_URL + '/%s' % consumer_id,
                                expected_status=404)

    def test_consumer_get(self):
        consumer, data = self._create_consumer()
        consumer_id = consumer['id']
        response = self.get(self.CONSUMER_URL + '/%s' % consumer_id)
        self_url = ['http://localhost/v3', self.CONSUMER_URL,
                    '/', consumer_id]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['consumer']['links']['self'], self_url)
        self.assertEqual(response.result['consumer']['id'], consumer_id)

    def test_consumer_get_bad_id(self):
        self.get(self.CONSUMER_URL + '/%(consumer_id)s'
                 % {'consumer_id': uuid.uuid4().hex},
                 expected_status=404)

    def test_consumer_list(self):
        self._create_consumer()
        response = self.get(self.CONSUMER_URL)
        entities = response.result['consumers']
        self.assertIsNotNone(entities)

        self_url = ['http://localhost/v3', self.CONSUMER_URL]
        self_url = ''.join(self_url)
        self.assertEqual(response.result['links']['self'], self_url)
        self.assertValidListLinks(response.result['links'])
       
    def test_consumer_update(self):
        consumer, data = self._create_consumer()
        original_id = consumer['id']
        original_description = consumer['description'] or ''
        update_description = original_description + '_new'
        update_scopes = ['new_scopes']
        update_redirect_uris = ['new_uris']

        body = {
            'consumer': {
                'description': update_description,
                'scopes': update_scopes,
                'redirect_uris': update_redirect_uris
            }
        }
        update_response = self.patch(self.CONSUMER_URL + '/%s' % original_id,
                                 body=body)
        consumer = update_response.result['consumer']
        self.assertEqual(consumer['description'], update_description)
        self.assertEqual(consumer['scopes'], update_scopes)
        self.assertEqual(consumer['redirect_uris'], update_redirect_uris)
        self.assertEqual(consumer['id'], original_id)

    def test_consumer_update_bad_secret(self):
        consumer, data = self._create_consumer()
        original_id = consumer['id']
        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = uuid.uuid4().hex
        update_ref['secret'] = uuid.uuid4().hex
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400)

    def test_consumer_update_bad_id(self):
        consumer, data = self._create_consumer()
        original_id = consumer['id']
        original_description = consumer['description'] or ''
        update_description = original_description + "_new"

        update_ref = copy.deepcopy(consumer)
        update_ref['description'] = update_description
        update_ref['id'] = uuid.uuid4().hex
        self.patch(self.CONSUMER_URL + '/%s' % original_id,
                   body={'consumer': update_ref},
                   expected_status=400) 

@dependency.requires('oauth2_api')
class AccessTokenEndpointTests(OAuth2BaseTests):

    def new_access_token_ref(self, user_id, consumer_id):
        token_ref = {
            'id':uuid.uuid4().hex,
            'consumer_id':consumer_id,
            'authorizing_user_id':user_id,
            'scopes': [uuid.uuid4().hex],
            'expires_at':uuid.uuid4().hex,
        }
        return token_ref

    def _create_access_token(self, user_id, consumer_id):
        token_ref = self.new_access_token_ref(user_id, consumer_id)
        access_token = self.oauth2_api.store_access_token(token_ref)
        return access_token

    def _list_access_tokens(self, user_id, expected_status=200):
        url = self.USERS_URL.format(user_id=user_id) + self.ACCESS_TOKENS_URL
        response = self.get(url, expected_status=expected_status)
        return response.result['access_tokens']

    def _get_access_token(self, user_id, token_id, expected_status=200):
        url = (self.USERS_URL.format(user_id=user_id) + self.ACCESS_TOKENS_URL 
                    + '/{0}'.format(token_id))
        response = self.get(url, expected_status=expected_status)
        return response.result['access_token']

    def _revoke_access_token(self, user_id, token_id, expected_status=204):
        url = (self.USERS_URL.format(user_id=user_id) + self.ACCESS_TOKENS_URL 
                    + '/{0}'.format(token_id))
        self.delete(url, expected_status=expected_status)

    def test_list_access_tokens(self):
        consumer_id = uuid.uuid4().hex
        number_of_tokens = 2
        access_tokens_reference = []
        for i in range(number_of_tokens):
            token = self._create_access_token(self.user['id'], consumer_id)
            access_tokens_reference.append(token)

        access_tokens = self._list_access_tokens(self.user['id'])

        actual_tokens = set([t['id'] for t in access_tokens])
        reference_tokens = set([t['id'] for t in access_tokens_reference])
        self.assertEqual(actual_tokens, reference_tokens)

    def test_get_access_token(self):
        consumer_id = uuid.uuid4().hex
        token = self._create_access_token(self.user['id'], consumer_id)
        token = self._get_access_token(self.user['id'], token['id'])
        # TODO(garcianavalon) access_token assertions

    def test_revoke_access_token(self):
        consumer_id = uuid.uuid4().hex
        token = self._create_access_token(self.user['id'], consumer_id)

        self._revoke_access_token(self.user['id'], token['id'])
        actual_token = self._get_access_token(self.user['id'], token['id'])
        self.assertEqual(actual_token['valid'], False)
        # TODO(garcianavalon) test revoke identity api tokens
        # TODO(garcianavalon) test can't get more identity api tokens


class OAuth2FlowBaseTests(OAuth2BaseTests):

    def setUp(self):
        super(OAuth2FlowBaseTests, self).setUp()
        self.consumer, self.data = self._create_consumer()

    def _flowstep_request_authorization(self, redirect_uri, scope, 
                                        expected_status=200, format_scope=True, 
                                        response_type='code', client_id=None):
        if format_scope:
            # Transform the array with the requested scopes into a list of 
            # space-delimited, case-sensitive strings as specified in RFC 6749
            # http://tools.ietf.org/html/rfc6749#section-3.3
            scope_string = ' '.join(scope)
        else:
            scope_string = scope

        if not client_id:
            client_id = self.consumer['id']

        # NOTE(garcianavalon) we use a list of tuples to ensure param order
        # in the query string to be able to mock it during testing.
        credentials = [
            ('client_id', client_id),
            ('redirect_uri', redirect_uri),
            ('scope', scope_string),
            ('state', uuid.uuid4().hex)
        ]
        if response_type:
            credentials.append(('response_type', response_type))
        query = urllib.urlencode(credentials)
        authorization_url = '/OS-OAUTH2/authorize?%s' %query

        # GET authorization_url to request the authorization
        return self.get(authorization_url, 
                        expected_status=expected_status)


    def _flowstep_grant_authorization(self, response, scopes, 
                                    expected_status=302, **kwargs):
        # POST authorization url to simulate ResourceOwner granting authorization
        consumer_id = response.result['data']['consumer']['id']
        data = {
            "user_auth": {
                "client_id":consumer_id,
                "scopes":scopes
            }
        }
        return self.post('/OS-OAUTH2/authorize', 
                        body=data, 
                        expected_status=expected_status,
                        **kwargs)
        
    def _extract_header_query_string(self, response):
        redirect_uri = response.headers['Location']
        query_params = urlparse.parse_qs(urlparse.urlparse(redirect_uri).query)
        return query_params

    def _http_basic(self, consumer_id, consumer_secret):
        auth_string = consumer_id + ':' + consumer_secret
        return 'Basic ' + base64.b64encode(auth_string)

    def _generate_urlencoded_request(self, authorization_code, 
                                    consumer_id, consumer_secret):
        # NOTE(garcianavalon) No use for now, keystone only accepts JSON bodies
        body = 'grant_type=authorization_code&code=%s&redirect_uri=%s' %authorization_code, self.DEFAULT_REDIRECT_URIS[0]
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': self._http_basic(consumer_id, consumer_secret)
        }
        return headers, body

    def _generate_json_request(self, authorization_code, consumer_id, consumer_secret):
        body = {
            'token_request' : {
                'grant_type':'authorization_code',
                'code': authorization_code,
                'redirect_uri':self.DEFAULT_REDIRECT_URIS[0]
            }
        }    
        headers = {
            'Authorization': self._http_basic(consumer_id, consumer_secret)
        }
        return headers, body

    def _extract_authorization_code_from_header(self, response):
        query_params = self._extract_header_query_string(response)
        authorization_code = query_params['code'][0]
        return authorization_code

    def _flowstep_obtain_access_token(self, response, expected_status=200):
        authorization_code = self._extract_authorization_code_from_header(response)

        consumer_id = self.consumer['id']
        consumer_secret = self.consumer['secret']

        headers, body = self._generate_json_request(authorization_code,
                                                   consumer_id, consumer_secret)
        #POST to the token url
        return self.post('/OS-OAUTH2/access_token', body=body,
                        headers=headers, expected_status=expected_status)

    def _auth_body(self, access_token, project=None):
        body = {
            "auth": {
                "identity": {  
                    "methods": [
                        "oauth2"
                    ],
                    "oauth2": {
                        'access_token_id':access_token['access_token']
                    },
                }
            }
        }
        if project:
            body['auth']['scope'] = {
                "project": {
                    "id": project
                }
            }
        return body

    def _assert_non_fatal_errors(self, response):
        error = response.result['error']
        self.assertIsNotNone(error['error'])
        if hasattr(error, 'description'):
            self.assertIsNotNone(error['description'])
        if hasattr(error, 'state'):
            self.assertIsNotNone(error['state'])

    def _assert_access_token(self, response, 
                             expected_scopes=None):
        access_token = response.result

        self.assertIsNotNone(access_token['access_token'])
        self.assertIsNotNone(access_token['token_type'])
        self.assertIsNotNone(access_token['expires_in'])
        self.assertIsNotNone(access_token['refresh_token'])

        scope = response.result['scope']
        if not expected_scopes:
            expected_scopes = ' '.join(self.DEFAULT_SCOPES)
        self.assertEqual(scope, expected_scopes)

class OAuth2AuthorizationCodeFlowTests(OAuth2FlowBaseTests):


    def test_flowstep_request_authorization(self):
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0] 
        expected_scopes = self.DEFAULT_SCOPES
        response = self._flowstep_request_authorization(
                                scope=expected_scopes,
                                redirect_uri=expected_redirect_uri)

        self.assertIsNotNone(response.result['data'])

        data = response.result['data']
        self.assertIsNotNone(data['redirect_uri'])
        self.assertIsNotNone(data['requested_scopes'])
        self.assertIsNotNone(data['consumer'])
        self.assertIsNotNone(data['consumer']['id'])

        consumer_id = data['consumer']['id']
        self.assertEqual(consumer_id, self.consumer['id'])

        self.assertEqual(data['requested_scopes'], expected_scopes)

        self.assertEqual(data['redirect_uri'], expected_redirect_uri)

    def test_flowstep_grant_authorization(self):
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0] 
        expected_scopes = self.DEFAULT_SCOPES
        get_response = self._flowstep_request_authorization(
                                scope=expected_scopes,
                                redirect_uri=expected_redirect_uri)

        response = self._flowstep_grant_authorization(get_response,
                                                    scopes=expected_scopes)

        self.assertIsNotNone(response.headers['Location'])
    
        query_params = self._extract_header_query_string(response)

        self.assertIsNotNone(query_params['code'][0])
        self.assertIsNotNone(query_params['state'][0])

    def test_granting_authorization_by_different_user_fails(self):
        """ Make the grant authorization step with a different
        authenticated user to check the code is only granted to the 
        redirected user. The response should be a 404 Not Found because no
        consumer has requested authorization for this user
        """
        # TODO(garcianavalon) what if other consumer has requested the authorization
        # for the second user???

        # First, request authorzation for our user
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0] 
        expected_scopes = self.DEFAULT_SCOPES
        get_response = self._flowstep_request_authorization(
                                scope=expected_scopes,
                                redirect_uri=expected_redirect_uri)
        # create the other user
        domain1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex}
        self.assignment_api.create_domain(domain1['id'], domain1)
        project1 = {'id': uuid.uuid4().hex, 'name': uuid.uuid4().hex,
                    'domain_id': domain1['id']}
        self.assignment_api.create_project(project1['id'], project1)
        user_foo = self.new_user_ref(domain_id=test_v3.DEFAULT_DOMAIN_ID)
        password = user_foo['password']
        user_foo = self.identity_api.create_user(user_foo)
        user_foo['password'] = password

        # TODO(garcianavalon) Im sure there is a better way to do this
        roles = self.assignment_api.list_roles()
        role_admin = next(r for r in roles if r['name'] == 'admin')

        self.assignment_api.create_grant(
            user_id=user_foo['id'],
            project_id=project1['id'],
            role_id=role_admin['id'])

        # Get a scoped token for the project
        auth_data = self.build_authentication_request(
            username=user_foo['name'],
            user_domain_id=test_v3.DEFAULT_DOMAIN_ID,
            password=user_foo['password'],
            project_name=project1['name'],
            project_domain_id=domain1['id'])

        # Try to grant authorization as the other user
        response = self._flowstep_grant_authorization(get_response,
                                                scopes=expected_scopes,
                                                expected_status=404, 
                                                auth=auth_data)
        
    def test_second_request_overrides_previous_credentials(self):
        """ Simulate the use case where the user gets redirected a
        second time by the same client.
        """
        # First make two requests with different scopes
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0]
        expected_scope1 = [self.DEFAULT_SCOPES[0]]
        get_response1 = self._flowstep_request_authorization(
                                scope=expected_scope1,
                                redirect_uri=expected_redirect_uri)
        scopes1 = get_response1.result['data']['requested_scopes']
        self.assertEqual(scopes1, expected_scope1)

        expected_scope2 = [self.DEFAULT_SCOPES[1]]
        get_response2 = self._flowstep_request_authorization(
                                scope=expected_scope2,
                                redirect_uri=expected_redirect_uri)
        scopes2 = get_response2.result['data']['requested_scopes']
        self.assertEqual(scopes2, expected_scope2)

        self.assertNotEqual(scopes2, scopes1)

        # TODO(garcianavalon) without using states this test is stupid because
        # the scopes returned in the response object are directly the ones in the
        # request and they are not stored with the credentials. Therefore, when
        # the client grants authorization it doesn't matter wich scopes where
        # requested in the first place because they are not saved, permission is
        # granted directly to the scopes in the POST request.
        # Solutions possible: add support for states and/or store the requested
        # scopes too

        # Now try to grant authorization using the first credentials to verify
        # it's not valid anymore
        response1 = self._flowstep_grant_authorization(get_response1,
                                    scopes=scopes1, 
                                    expected_status=302)

        # Now grant authorization using the second credentials
        response2 = self._flowstep_grant_authorization(get_response2,
                                    scopes=scopes2, 
                                    expected_status=302)

    def test_malformed_scopes_in_query(self):
        """ Scope must be a list (string) of space-delimited, case-sensitive 
        strings. This is a non fatal error and the provider will
        notify it in the response body
        """
        malformed_scope = "&".join(self.DEFAULT_SCOPES)
        response = self._flowstep_request_authorization(
                                    redirect_uri=self.DEFAULT_REDIRECT_URIS[0],
                                    scope=malformed_scope,
                                    format_scope=False)
        self._assert_non_fatal_errors(response)

    def test_invalid_scopes_in_query(self):
        """ The requested scope of access must be included in the registered
        scopes of the client. This is a non fatal error and the provider will
        notify it in the response body

            We ignore this value anyway (the scope granted in the end depends
        solely in the value submited by the user in the grant authorization step)
        but this value is the one showed in the info presented to the resource owner,
        so it's a good practice to check we actually allow the client that scope before.
        """
        new_scopes = [uuid.uuid4().hex]
        response = self._flowstep_request_authorization(
                                    redirect_uri=self.DEFAULT_REDIRECT_URIS[0],
                                    scope=new_scopes)
        self._assert_non_fatal_errors(response)

    def test_invalid_response_type_in_query(self):
        """ The response type must be set to 'code'. This is a non fatal error and 
        the provider will notify it in the response body
        """
        response = self._flowstep_request_authorization(
                                    redirect_uri=self.DEFAULT_REDIRECT_URIS[0],
                                    scope=self.DEFAULT_SCOPES,
                                    response_type=uuid.uuid4().hex)
        self._assert_non_fatal_errors(response)

    def test_missing_response_type_in_query(self):
        """ The response type missing is a non fatal error and the provider will
        notify it in the response body
        """
        response = self._flowstep_request_authorization(
                                    redirect_uri=self.DEFAULT_REDIRECT_URIS[0],
                                    scope=self.DEFAULT_SCOPES,
                                    response_type=None)
        self._assert_non_fatal_errors(response)

    def test_invalid_client_id_in_query(self):
        """ The client_id must be provided and present in our backend."""
        response = self._flowstep_request_authorization(
                                    redirect_uri=self.DEFAULT_REDIRECT_URIS[0],
                                    scope=self.DEFAULT_SCOPES,
                                    client_id=uuid.uuid4().hex,
                                    expected_status=404)

    def test_granted_scope_is_the_one_submited_by_user(self):
        """ Ensure that the scope we are going to give to the authorization code (and
        therefore to the access token) is the one submited by the user and not
        the one requested by the client.
        """
        pass


class OAuth2AccessTokenFromCodeFlowTests(OAuth2FlowBaseTests):


    def test_flowstep_obtain_access_token(self):
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0] 
        expected_scopes = self.DEFAULT_SCOPES
        get_response = self._flowstep_request_authorization(
            scope=expected_scopes,
            redirect_uri=expected_redirect_uri)

        post_response = self._flowstep_grant_authorization(
            get_response, scopes=expected_scopes)
        response = self._flowstep_obtain_access_token(post_response)
        self._assert_access_token(
            response, expected_scopes=' '.join(expected_scopes))

    def test_access_code_only_one_use(self):
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0] 
        expected_scopes = self.DEFAULT_SCOPES
        get_response = self._flowstep_request_authorization(
                                scope=expected_scopes,
                                redirect_uri=expected_redirect_uri)

        post_response = self._flowstep_grant_authorization(get_response,
                                                        scopes=expected_scopes)

        response_ok = self._flowstep_obtain_access_token(post_response,
                                                        expected_status=200)

        response_not = self._flowstep_obtain_access_token(post_response,
                                                        expected_status=401)  


    def _exchange_access_token_assertions(self, response):
        token = json.loads(response.body)['token']
        #self.assertEqual(token['project']['id'],self.project_id)
        self.assertEqual(token['user']['id'], self.user_id)
        self.assertEqual(token['methods'], ["oauth2"])
        self.assertIsNotNone(token['expires_at'])

    def test_auth_with_access_token_no_scope(self):
        scope = ['all_info']
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0] 
        get_response = self._flowstep_request_authorization(
                                scope=scope,
                                redirect_uri=expected_redirect_uri)

        post_response = self._flowstep_grant_authorization(get_response,
                                                        scopes=scope)
        response = self._flowstep_obtain_access_token(post_response)
        access_token = response.result


        body = self._auth_body(access_token)

        # POST to the auth url as an unauthenticated user to get a keystone token
        response = self.post('/auth/tokens', body=body, noauth=True)
        self._exchange_access_token_assertions(response)

    def test_auth_with_access_token_with_scope(self):
        scope = ['all_info']
        expected_redirect_uri = self.DEFAULT_REDIRECT_URIS[0] 
        get_response = self._flowstep_request_authorization(
                                scope=scope,
                                redirect_uri=expected_redirect_uri)

        post_response = self._flowstep_grant_authorization(get_response,
                                                        scopes=scope)
        response = self._flowstep_obtain_access_token(post_response)
        access_token = response.result

        body = self._auth_body(access_token, project=self.project_id)
        
        # POST to the auth url as an unauthenticated user to get a keystone token
        response = self.post('/auth/tokens', body=body)
        self._exchange_access_token_assertions(response)


class OAuth2PasswordGrantFlowTests(OAuth2FlowBaseTests):
    # NOTE(garcianavalon) because right now we can't sent
    # a domain id in the Password Grant, we need to use the
    # default_domain_user or the validator will fail

    def _assert_keystone_token(self, response):
        token = json.loads(response.body)['token']
        #self.assertEqual(token['project']['id'],self.project_id)
        self.assertEqual(token['user']['id'], 
                         self.default_domain_user['id'])
        self.assertEqual(token['methods'], ["oauth2"])
        self.assertIsNotNone(token['expires_at'])

    def _generate_urlencoded_request(self):
        # NOTE(garcianavalon) in order to use this content type the
        # UrlencodedBodyMiddleware provided in the extension must be
        # in the pipeline
        body = ('grant_type=password&username={username}'
            '&password={password}').format(
                username=self.default_domain_user['name'],
                password=self.default_domain_user['password'])
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': self._http_basic(
                self.consumer['id'], self.consumer['secret'])
        }
        return headers, body

    def _generate_json_request(self, scope=None):
        # NOTE(garcianavalon) this is non-compliant with the 
        # rfc6749 spec. Used when the UrlencodedBodyMiddleware
        # is not available in a keystone deployment

        body = {
            'token_request' : {
                'grant_type':'password',
                'username': self.default_domain_user['name'],
                'password': self.default_domain_user['password'],
            }
        }
        if scope:
            body['token_request']['scope'] = scope
        headers = {
            'Authorization': self._http_basic(
                self.consumer['id'], self.consumer['secret'])
        }
        return headers, body

    def _access_token_request(self, scope=None, expected_status=200):
        headers, body = self._generate_json_request(scope=scope)
        return self.post('/OS-OAUTH2/access_token', body=body,
            headers=headers, expected_status=expected_status)

    def _obtain_keystone_token(self, body):
        # POST as an unauthenticated user to get a keystone token
        return self.post('/auth/tokens', body=body, noauth=True)

    def test(self):
        scope = 'all_info'
        response = self._access_token_request(scope=scope)
        self._assert_access_token(response, 
            expected_scopes=scope)

    def test_auth_with_access_token(self):
        scope = 'all_info'
        at_response = self._access_token_request(scope=scope)
        body = self._auth_body(at_response.result)
        kt_response = self._obtain_keystone_token(body=body)
        
        self._assert_keystone_token(kt_response)
