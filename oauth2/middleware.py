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

import urlparse

from oslo.serialization import jsonutils

from keystone.common import wsgi
from keystone import exception
from keystone.openstack.common import log

LOG = log.getLogger(__name__)

class UrlencodedBodyMiddleware(wsgi.Middleware):
    """Serializes urlencoded to JSON."""

    def __init__(self, *args, **kwargs):
        super(UrlencodedBodyMiddleware, self).__init__(*args, **kwargs)
        self.xmlns = None

    def process_request(self, request):
        """Transform the request from urlencoded to JSON."""
        incoming_urlencoded = 'application/x-www-form-urlencoded' in str(request.content_type)
        if incoming_urlencoded and request.body:
            LOG.info('URLENCODED_MIDDLEWARE: serializing incoming urlencoded to JSON')
            request.content_type = 'application/json'
            try:
                request.body = jsonutils.dumps(
                    {'token_request':dict(urlparse.parse_qsl(request.body))})
                LOG.debug('URLENCODED_MIDDLEWARE: decoded body to {0}'.format(request.body))
            except Exception:
                LOG.exception('URLENCODED_MIDDLEWARE: Serializer failed')
                e = exception.ValidationError(attribute='valid urlencoded',
                                              target='request body')
                return wsgi.render_exception(e, request=request)

    def process_response(self, request, response):
        """Dont transform JSON to urlencoded, no need for that."""
        return response