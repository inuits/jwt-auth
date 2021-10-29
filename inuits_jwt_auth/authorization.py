import base64
import functools
import json

from abc import ABC
import requests
from flask import request as _req
from authlib.oauth2 import HttpRequest, OAuth2Error
from authlib.oauth2.rfc6750 import BearerTokenValidator, InvalidTokenError
from authlib.oauth2.rfc7523 import JWTBearerToken
from authlib.jose import jwt, JoseError
from authlib.integrations.flask_oauth2 import ResourceProtector, token_authenticated
from authlib.oauth2.rfc6749 import MissingAuthorizationError, UnsupportedTokenTypeError
from authlib.integrations.flask_oauth2 import current_token as current_token_authlib
from contextlib import contextmanager
from flask import _app_ctx_stack


class MyResourceProtector(ResourceProtector):
    def __init__(self, static_jwt, role_permission_mapping: dict):
        super().__init__()
        self.static_jwt = static_jwt
        self.role_permission_mapping = role_permission_mapping

    def parse_request_authorization(self, request):
        """Parse the token and token validator from request Authorization header.
        Here is an example of Authorization header::

            Authorization: Bearer a-token-string

        This method will parse this header, if it can find the validator for
        ``Bearer``, it will return the validator and ``a-token-string``.

        :return: validator, token_string
        :raise: MissingAuthorizationError
        :raise: UnsupportedTokenTypeError
        """
        auth = request.headers.get('Authorization')
        if not auth:
            raise MissingAuthorizationError(self._default_auth_type, self._default_realm)
        # https://tools.ietf.org/html/rfc6749#section-7.1
        token_parts = auth.split(None, 1)
        if len(token_parts) != 2:
            raise UnsupportedTokenTypeError(self._default_auth_type, self._default_realm)

        token_type, token_string = token_parts
        validator = self.get_token_validator(token_type)
        return validator, token_string

    def acquire_token(self, permissions=None):
        """A method to acquire current valid token with the given scope.

        :param permissions: a list of required permissions
        :return: token object
        """
        request = HttpRequest(
            _req.method,
            _req.full_path,
            _req.data,
            _req.headers
        )
        request.req = _req
        # backward compatible
        if isinstance(permissions, str):
            permissions = [permissions]
        token = self.validate_request(permissions, request)
        token_authenticated.send(self, token=token)
        ctx = _app_ctx_stack.top
        ctx.authlib_server_oauth2_token = token
        return token

    @contextmanager
    def acquire(self, permissions=None):
        try:
            yield self.acquire_token(permissions)
        except OAuth2Error as error:
            self.raise_error_response(error)

    def __call__(self, permissions=None, optional=False):
        def wrapper(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                try:
                    self.acquire_token(permissions)
                except MissingAuthorizationError as error:
                    if optional:
                        return f(*args, **kwargs)
                    self.raise_error_response(error)
                except OAuth2Error as error:
                    self.raise_error_response(error)
                return f(*args, **kwargs)

            return decorated

        return wrapper

    def validate_request(self, permissions, request):
        """Validate the request and return a token."""
        validator, token_string = self.parse_request_authorization(request)
        validator.validate_request(request)
        token = validator.authenticate_token(token_string)
        validator.validate_token(token, permissions, request)
        return token


def _get_permissions_by_roles(roles):
    # todo read role-permission mapping from file
    return []


class JWT(JWTBearerToken):
    def has_permissions(self, permissions):
        if "roles" in self and permissions is not None:
            user_permissions = _get_permissions_by_roles(self["roles"])
            for permission in permissions:
                if permission not in user_permissions:
                    return False
        elif "roles" not in self and permissions is not None:
            return False

        return True


class JWTValidator(BearerTokenValidator, ABC):
    TOKEN_TYPE = 'bearer'
    token_cls = JWT

    def __init__(self, logger, static_jwt=False, static_issuer=False, static_public_key=False, realms=None
                 , disable_auth=False, **extra_attributes):
        super().__init__(**extra_attributes)
        self.static_jwt = static_jwt
        self.static_issuer = static_issuer
        self.static_public_key = static_public_key
        self.logger = logger
        self.public_key = None
        self.realms = [] if realms is None else realms
        claims_options = {
            'exp': {'essential': True},
            'aud': {'essential': True},
            'sub': {'essential': True},
        }
        self.claims_options = claims_options
        self.disable_auth = disable_auth

    def authenticate_token(self, token_string):
        if self.disable_auth and self.static_jwt is not False:
            token_string = self.static_jwt
        elif self.static_jwt is not False and token_string != self.static_jwt:
            token_string = ""

        issuer = self._get_unverified_issuer(token_string)
        if not issuer:
            return None
        realm_config = self._get_realm_config_by_issuer(issuer)
        if "public_key" in realm_config:
            self.public_key = realm_config["public_key"]
        else:
            self.public_key = ""
        try:
            claims = jwt.decode(
                token_string, self.public_key,
                claims_options=self.claims_options,
                claims_cls=self.token_cls,
            )
            claims.validate()
            return claims
        except JoseError as error:
            self.logger.info('Authenticate token failed. %r', error)
            return None

    def _get_realm_config_by_issuer(self, issuer):
        if issuer == self.static_issuer:
            return {"public_key": self.static_public_key}
        for realm in self.realms:
            if issuer == realm:
                return requests.get(realm).json()
        return {}

    def validate_token(self, token, permissions, request):
        """Check if token is active and matches the requested permissions."""
        if not token:
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if token.is_expired():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if token.is_revoked():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if not token.has_permissions(permissions):
            raise InsufficientPermissionError()

    @staticmethod
    def _get_unverified_issuer(token_string):
        payload = token_string.split(".")[1] + "=="  # "==" needed for correct b64 padding
        decoded = json.loads(base64.b64decode(payload.encode('utf-8')))
        if "iss" in decoded:
            return decoded["iss"]
        else:
            return False


class InsufficientPermissionError(OAuth2Error):
    """The request requires higher privileges than provided by the
    access token. The resource server SHOULD respond with the HTTP
    403 (Forbidden) status code and MAY include the "scope"
    attribute with the scope necessary to access the protected
    resource.

    https://tools.ietf.org/html/rfc6750#section-3.1
    """
    error = 'insufficient_permission'
    description = 'The request requires higher privileges than provided by the access token.'
    status_code = 403


current_token = current_token_authlib
