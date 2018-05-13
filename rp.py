import logging

import cherrypy
import requests

from oidcmsg.key_jar import init_key_jar

from oidcrp.util import get_deserialization_method

from oidcservice.client_auth import factory as ca_factory
from oidcservice.exception import OidcServiceError
from oidcservice.exception import ParseError
from oidcservice.service import REQUEST_INFO
from oidcservice.service import SUCCESSFUL
from oidcservice.service_context import ServiceContext

from oidcservice.oauth2.client_credentials import AccessToken
from oidcservice.oauth2.client_credentials import RefreshAccessToken

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


class DB(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, item):
        try:
            return self.db[item]
        except KeyError:
            return None


class RP(object):
    def __init__(self, config, key_jar_conf=None, client_authn_factory=None):
        if key_jar_conf:
            _kj = init_key_jar(**key_jar_conf)
        else:
            _kj = None

        self.service_context = ServiceContext(config=config, keyjar=_kj)
        caf = client_authn_factory or ca_factory
        sdb = DB()
        self.service = {}
        self.service['token'] = AccessToken(
            service_context=self.service_context, state_db=sdb,
            client_authn_factory=caf)

        self.service['refresh_token'] = RefreshAccessToken(
            service_context=self.service_context, state_db=sdb,
            client_authn_factory=caf)

        self.http = requests.request

    def do_request(self, request_type, response_body_type="", request_args=None,
                   **kwargs):

        _srv = self.service[request_type]

        _info = _srv.get_request_parameters(request_args=request_args, **kwargs)

        if not response_body_type:
            response_body_type = _srv.response_body_type

        logger.debug('do_request info: {}'.format(_info))

        try:
            _state = kwargs['state']
        except:
            _state = ''
        return self.service_request(_srv, response_body_type=response_body_type,
                                    state=_state, **_info)

    def set_client_id(self, client_id):
        self.client_id = client_id
        self.service_context.client_id = client_id

    def service_request(self, service, url, method="GET", body=None,
                        response_body_type="", headers=None, **kwargs):
        """
        The method that sends the request and handles the response returned.
        This assumes that the response arrives in the HTTP response.

        :param url: The URL to which the request should be sent
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param response_body_type: The expected format of the body of the
            return message
        :param http_args: Arguments for the HTTP client
        :return: A cls or ResponseMessage instance or the HTTP response
            instance if no response body was expected.
        """

        if headers is None:
            headers = {}

        logger.debug(REQUEST_INFO.format(url, method, body, headers))

        try:
            resp = self.http(url=url, method=method, data=body, headers=headers)
        except Exception as err:
            logger.error('Exception on request: {}'.format(err))
            raise

        if "keyjar" not in kwargs:
            kwargs["keyjar"] = service.service_context.keyjar
        if not response_body_type:
            response_body_type = service.response_body_type

        response = self.parse_request_response(service, resp,
                                               response_body_type, **kwargs)
        if 'error' in response:
            pass
        else:
            service.update_service_context(response, **kwargs)
        return response

    def parse_request_response(self, service, reqresp, response_body_type='',
                               state="", **kwargs):
        """
        Deal with a self.http response. The response are expected to
        follow a special pattern, having the attributes:

            - headers (list of tuples with headers attributes and their values)
            - status_code (integer)
            - text (The text version of the response)
            - url (The calling URL)

        :param service: A :py:class:`oidcservice.service.Service` instance
        :param reqresp: The HTTP request response
        :param response_body_type: If response in body one of 'json', 'jwt' or
            'urlencoded'
        :param state: Session identifier
        :param kwargs: Extra keyword arguments
        :return:
        """

        # if not response_body_type:
        #     response_body_type = self.response_body_type

        if reqresp.status_code in SUCCESSFUL:
            logger.debug('response_body_type: "{}"'.format(response_body_type))
            _deser_method = get_deserialization_method(reqresp)

            if _deser_method != response_body_type:
                logger.warning(
                    'Not the body type I expected: {} != {}'.format(
                        _deser_method, response_body_type))
            if _deser_method in ['json', 'jwt', 'urlencoded']:
                value_type = _deser_method
            else:
                value_type = response_body_type

            logger.debug('Successful response: {}'.format(reqresp.text))

            try:
                return service.parse_response(reqresp.text, value_type,
                                              state, **kwargs)
            except Exception as err:
                logger.error(err)
                raise
        elif reqresp.status_code in [302, 303]:  # redirect
            return reqresp
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif 400 <= reqresp.status_code < 500:
            logger.error('Error response ({}): {}'.format(reqresp.status_code,
                                                          reqresp.text))
            # expecting an error response
            _deser_method = get_deserialization_method(reqresp)
            if not _deser_method:
                _deser_method = 'json'

            try:
                err_resp = service.parse_response(reqresp.text, _deser_method)
            except OidcServiceError:
                if _deser_method != response_body_type:
                    try:
                        err_resp = service.parse_response(reqresp.text,
                                                          response_body_type)
                    except OidcServiceError:
                        raise cherrypy.HTTPError("HTTP ERROR: %s [%s] on %s" % (
                            reqresp.text, reqresp.status_code, reqresp.url))
                else:
                    raise cherrypy.HTTPError("HTTP ERROR: %s [%s] on %s" % (
                        reqresp.text, reqresp.status_code, reqresp.url))

            return err_resp
        else:
            logger.error('Error response ({}): {}'.format(reqresp.status_code,
                                                          reqresp.text))
            raise cherrypy.HTTPError("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))

    def get_access_token(self, grant_type='client_credentials', scope=None,
                         authn_method=''):
        req_args = {'grant_type': grant_type}
        if scope:
            req_args['scope'] = scope

        return self.do_request('token', request_args=req_args)

    def refresh_access_token(self):
        return self.do_request('refresh_token')
