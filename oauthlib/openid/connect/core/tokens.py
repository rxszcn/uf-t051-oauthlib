"""
authlib.openid.connect.core.tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains methods for adding JWT tokens to requests.
"""
import base64
import binascii
import json

from oauthlib.oauth2.rfc6749.tokens import (
    TokenBase, get_token_from_header, random_token_generator,
)

# RFC 9068 第 2.1 节:JWT 访问令牌通过 JOSE 头中的 "typ" 声明自身类型,
# 取值为 "at+jwt" 或 "application/at+jwt"(比较时不区分大小写)。
_ACCESS_TOKEN_TYP_VALUES = frozenset(('at+jwt', 'application/at+jwt'))


def decode_jose_header(token):
    """解码 JWT 的 JOSE 头(不校验签名)。

    :param token: Unicode JWT(JWS 或 JWE 的 compact 序列化形式)。
    :return: JOSE 头字典;若令牌不携带可解码的 JSON JOSE 头则返回 None。
    """
    try:
        segment = token.split('.', 1)[0]
        segment += '=' * (-len(segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(segment.encode('ascii')))
    except (binascii.Error, UnicodeDecodeError, UnicodeEncodeError, ValueError):
        return None
    return header if isinstance(header, dict) else None


class JWTToken(TokenBase):
    __slots__ = (
        'request_validator', 'token_generator',
        'refresh_token_generator', 'expires_in'
    )

    def __init__(self, request_validator=None, token_generator=None,
                 expires_in=None, refresh_token_generator=None):
        self.request_validator = request_validator
        self.token_generator = token_generator or random_token_generator
        self.refresh_token_generator = (
            refresh_token_generator or self.token_generator
        )
        self.expires_in = expires_in or 3600

    def create_token(self, request, refresh_token=False):
        """Create a JWT Token, using requestvalidator method."""

        expires_in = self.expires_in(request) if callable(self.expires_in) else self.expires_in

        request.expires_in = expires_in

        return self.request_validator.get_jwt_bearer_token(None, None, request)

    def validate_request(self, request):
        token = get_token_from_header(request)
        return self.request_validator.validate_jwt_bearer_token(
            token, request.scopes, request)

    def estimate_type(self, request):
        token = get_token_from_header(request)
        # 传输形态:JWT 的 compact 序列化只能是三段式(JWS)或五段式(JWE)。
        if not token or token.count('.') not in (2, 4):
            return 0
        header = decode_jose_header(token)
        if header is None:
            # 形似三段式/五段式但 JOSE 头不是合法 JSON,并非 JWT,
            # 交回默认(Bearer)校验通道。
            return 0
        # 令牌声明:JOSE 头 typ 显式声明为访问令牌(RFC 9068)时,
        # 不得劫持到身份凭证(JWT bearer / ID token)校验通道。
        typ = str(header.get('typ', '')).lower()
        if typ in _ACCESS_TOKEN_TYP_VALUES:
            return 0
        return 10
