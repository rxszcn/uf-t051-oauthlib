import base64
import json
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749.endpoints import ResourceEndpoint
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.openid.connect.core.tokens import JWTToken

from tests.unittest import TestCase


def _b64url(data):
    """base64url 编码(无填充)一个可 JSON 序列化的对象。"""
    raw = json.dumps(data).encode('utf-8')
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def make_jwt(header, payload=None):
    """构造 compact 序列化令牌;payload 为 None 时生成五段式(JWE 形态)。"""
    if payload is None:
        return '.'.join([_b64url(header), '', '', '', ''])
    return '.'.join([_b64url(header), _b64url(payload), 'signature'])


class JWTTokenTestCase(TestCase):

    def test_create_token_callable_expires_in(self):
        """
        Test retrieval of the expires in value by calling the callable expires_in property
        """

        expires_in_mock = mock.MagicMock()
        request_mock = mock.MagicMock()

        token = JWTToken(expires_in=expires_in_mock, request_validator=mock.MagicMock())
        token.create_token(request=request_mock)

        expires_in_mock.assert_called_once_with(request_mock)

    def test_create_token_non_callable_expires_in(self):
        """
        When a non callable expires in is set this should just be set to the request
        """

        expires_in_mock = mock.NonCallableMagicMock()
        request_mock = mock.MagicMock()

        token = JWTToken(expires_in=expires_in_mock, request_validator=mock.MagicMock())
        token.create_token(request=request_mock)

        self.assertFalse(expires_in_mock.called)
        self.assertEqual(request_mock.expires_in, expires_in_mock)

    def test_create_token_calls_get_id_token(self):
        """
        When create_token is called the call should be forwarded to the get_id_token on the token validator
        """
        request_mock = mock.MagicMock()

        with mock.patch('oauthlib.openid.RequestValidator',
                        autospec=True) as RequestValidatorMock:

            request_validator = RequestValidatorMock()

            token = JWTToken(expires_in=mock.MagicMock(), request_validator=request_validator)
            token.create_token(request=request_mock)

            request_validator.get_jwt_bearer_token.assert_called_once_with(None, None, request_mock)

    def test_validate_request_token_from_headers(self):
        """
        Bearer token get retrieved from headers.
        """

        with mock.patch('oauthlib.common.Request', autospec=True) as RequestMock, \
                mock.patch('oauthlib.openid.RequestValidator',
                           autospec=True) as RequestValidatorMock:
            request_validator_mock = RequestValidatorMock()

            token = JWTToken(request_validator=request_validator_mock)

            request = RequestMock('/uri')
            # Scopes is retrieved using the __call__ method which is not picked up correctly by mock.patch
            # with autospec=True
            request.scopes = mock.MagicMock()
            request.headers = {
                'Authorization': 'Bearer some-token-from-header'
            }

            token.validate_request(request=request)

            request_validator_mock.validate_jwt_bearer_token.assert_called_once_with('some-token-from-header',
                                                                                     request.scopes,
                                                                                     request)

    def test_validate_request_token_from_headers_basic(self):
        """
        Wrong kind of token (Basic) retrieved from headers. Confirm token is not parsed.
        """

        with mock.patch('oauthlib.common.Request', autospec=True) as RequestMock, \
                mock.patch('oauthlib.openid.RequestValidator',
                           autospec=True) as RequestValidatorMock:
            request_validator_mock = RequestValidatorMock()

            token = JWTToken(request_validator=request_validator_mock)

            request = RequestMock('/uri')
            # Scopes is retrieved using the __call__ method which is not picked up correctly by mock.patch
            # with autospec=True
            request.scopes = mock.MagicMock()
            request.headers = {
                'Authorization': 'Basic some-token-from-header'
            }

            token.validate_request(request=request)

            request_validator_mock.validate_jwt_bearer_token.assert_called_once_with(None,
                                                                                     request.scopes,
                                                                                     request)

    def test_validate_token_from_request(self):
        """
        Token get retrieved from request object.
        """

        with mock.patch('oauthlib.common.Request', autospec=True) as RequestMock, \
                mock.patch('oauthlib.openid.RequestValidator',
                           autospec=True) as RequestValidatorMock:
            request_validator_mock = RequestValidatorMock()

            token = JWTToken(request_validator=request_validator_mock)

            request = RequestMock('/uri')
            # Scopes is retrieved using the __call__ method which is not picked up correctly by mock.patch
            # with autospec=True
            request.scopes = mock.MagicMock()
            request.access_token = 'some-token-from-request-object'
            request.headers = {}

            token.validate_request(request=request)

            request_validator_mock.validate_jwt_bearer_token.assert_called_once_with('some-token-from-request-object',
                                                                                     request.scopes,
                                                                                     request)

    def estimate(self, token):
        """对给定令牌执行分发判定(经 Authorization Bearer 头传输)。"""
        request = Request(
            '/uri', headers={'Authorization': 'Bearer {}'.format(token)}
        )
        return JWTToken().estimate_type(request=request)

    def test_estimate_type_identity_credential(self):
        """
        纯身份凭证场景不回退:未声明为访问令牌的 JWT 仍走身份凭证通道。
        """
        payload = {'iss': 'https://as.example', 'sub': 'alice',
                   'aud': 'client-1', 'exp': 1893456000}
        test_items = (
            # 三段式 JWS,typ 为普通 JWT
            (make_jwt({'alg': 'RS256', 'typ': 'JWT'}, payload), 10),
            # 三段式 JWS,无 typ 声明
            (make_jwt({'alg': 'RS256'}, payload), 10),
            # 五段式 JWE 形态的身份凭证
            (make_jwt({'alg': 'RSA-OAEP', 'enc': 'A256GCM'}), 10),
        )
        for token, expected_result in test_items:
            self.assertEqual(self.estimate(token), expected_result)

    def test_estimate_type_declared_access_token_not_hijacked(self):
        """
        回归:业务方通过 JOSE 头 typ 声明(RFC 9068)为普通访问令牌的
        三段式令牌,不得被劫持到身份凭证校验通道。
        """
        payload = {'iss': 'https://as.example', 'sub': 'alice',
                   'aud': 'resource-1', 'exp': 1893456000,
                   'client_id': 'client-1', 'scope': 'read'}
        test_items = (
            make_jwt({'alg': 'RS256', 'typ': 'at+jwt'}, payload),
            make_jwt({'alg': 'RS256', 'typ': 'application/at+jwt'}, payload),
            # typ 比较不区分大小写
            make_jwt({'alg': 'RS256', 'typ': 'AT+JWT'}, payload),
        )
        for token in test_items:
            self.assertEqual(self.estimate(token), 0)

    def test_estimate_type_non_jwt_tokens(self):
        """
        非 JWT(无 JSON JOSE 头或非三段/五段形态)的令牌不进入身份凭证通道。
        """
        test_items = (
            ('eyfoo.foo.foo', 0),          # 三段式但 JOSE 头不是合法 JSON
            ('eyfoo.foo.foo.foo.foo', 0),  # 五段式但 JOSE 头不是合法 JSON
            ('eyfoobar', 0),               # 非三段/五段形态
            ('opaque-token-value', 0),     # 普通不透明访问令牌
        )
        for token, expected_result in test_items:
            self.assertEqual(self.estimate(token), expected_result)


class TokenDispatchTestCase(TestCase):
    """
    资源端点(网关)令牌分发判定的回归测试:同时注册 Bearer 与 JWT
    两种令牌类型时,按传输形态与令牌声明选择校验通道。
    """

    def setUp(self):
        self.validator = mock.MagicMock()
        self.validator.validate_bearer_token.return_value = True
        self.validator.validate_jwt_bearer_token.return_value = True
        self.endpoint = ResourceEndpoint(
            default_token='Bearer',
            token_types={
                'Bearer': BearerToken(request_validator=self.validator),
                'JWT': JWTToken(request_validator=self.validator),
            },
        )

    def verify(self, token):
        uri = 'http://a.b/path'
        headers = {'Authorization': 'Bearer {}'.format(token)}
        valid, request = self.endpoint.verify_request(uri, headers=headers)
        self.assertTrue(valid)
        return request

    def test_declared_access_token_dispatched_to_bearer(self):
        """
        被劫持的访问令牌回到原有校验通道:typ 声明为 at+jwt 的令牌
        由 validate_bearer_token 校验。
        """
        token = make_jwt({'alg': 'RS256', 'typ': 'at+jwt'},
                         {'iss': 'https://as.example', 'sub': 'alice',
                          'aud': 'resource-1', 'exp': 1893456000,
                          'client_id': 'client-1', 'scope': 'read'})
        request = self.verify(token)
        self.assertEqual(request.token_type, 'Bearer')
        self.validator.validate_bearer_token.assert_called_once()
        self.validator.validate_jwt_bearer_token.assert_not_called()

    def test_identity_credential_dispatched_to_jwt(self):
        """
        纯身份凭证场景不回退:普通 JWT 身份凭证仍由
        validate_jwt_bearer_token 校验。
        """
        token = make_jwt({'alg': 'RS256', 'typ': 'JWT'},
                         {'iss': 'https://as.example', 'sub': 'alice',
                          'aud': 'client-1', 'exp': 1893456000})
        request = self.verify(token)
        self.assertEqual(request.token_type, 'JWT')
        self.validator.validate_jwt_bearer_token.assert_called_once()
        self.validator.validate_bearer_token.assert_not_called()

    def test_opaque_token_dispatched_to_bearer(self):
        """
        不透明访问令牌依旧走 Bearer 校验通道。
        """
        request = self.verify('opaque-token-value')
        self.assertEqual(request.token_type, 'Bearer')
        self.validator.validate_bearer_token.assert_called_once()
        self.validator.validate_jwt_bearer_token.assert_not_called()
