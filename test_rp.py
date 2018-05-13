import json

import pytest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcservice.client_auth import factory as ca_factory

from rp import RP

KEYDEF = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]


class TestRP():
    @pytest.fixture(autouse=True)
    def create_rp(self):
        config = {
            'client_id': 'client_id',
            'client_secret': 'client_secret',
            'provider_info': {
                'token_endpoint': 'https://example.com/token'
            }
        }
        key_jar_conf = {
            'public_path': 'public.json',
            'key_defs': KEYDEF,
            'private_path': 'private.json'
        }
        self.rp = RP(config=config, key_jar_conf=key_jar_conf,
                     client_authn_factory=ca_factory)

    def test_token_get_request(self):
        request_args = {'grant_type': 'client_credentials'}
        _srv = self.rp.service['token']
        _info = _srv.get_request_parameters(request_args=request_args)
        assert _info['method'] == 'POST'
        assert _info['url'] == 'https://example.com/token'
        assert _info['body'] == 'grant_type=client_credentials'
        assert _info['headers'] == {
            'Authorization': 'Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def test_refresh_token_get_request(self):
        _srv = self.rp.service['token']
        _srv.update_service_context({
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value"
        })
        _srv = self.rp.service['refresh_token']
        _info = _srv.get_request_parameters()
        assert _info['method'] == 'POST'
        assert _info['url'] == 'https://example.com/token'
        assert _info['body'] == 'grant_type=refresh_token'
        assert _info['headers'] == {
            'Authorization': 'Bearer tGzv3JOkF0XG5Qx2TlKWIA',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def test_get_access_token(self, httpserver):
        httpserver.serve_content(json.dumps({
            "access_token": "2YotnFZFEjr1zCsicMWpAA",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value"
        }))

        self.rp.service['token'].endpoint = httpserver.url

        resp = self.rp.get_access_token('client_credentials')
        assert isinstance(resp, AccessTokenResponse)

    def test_refresh_access_token(self, httpserver):
        httpserver.serve_content(json.dumps({
            "access_token": "ANewDifferentFromTheLastOne",
            "token_type": "example",
            "expires_in": 3600,
            "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
            "example_parameter": "example_value"
        }))

        self.rp.service['token'].endpoint = httpserver.url

        self.rp.get_access_token('client_credentials')
        self.rp.service['refresh_token'].endpoint = httpserver.url
        resp = self.rp.refresh_access_token()
        assert resp['access_token'] == "ANewDifferentFromTheLastOne"
