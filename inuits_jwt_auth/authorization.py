import base64
import functools
import json

from abc import ABC
from json import JSONDecodeError

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
from werkzeug.exceptions import Unauthorized, Forbidden


class MyResourceProtector(ResourceProtector):
    def __init__(self, require_token=True):
        super().__init__()
        self.require_token = require_token

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
        if self.require_token:
            token = self.validate_request(permissions, request)
        else:
            token = ""
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
                    raise Unauthorized(str(error))
                except InsufficientPermissionError as error:
                    raise Forbidden(str(error))
                except OAuth2Error as error:
                    raise Unauthorized(str(error))
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


class JWT(JWTBearerToken):
    def has_permissions(self, permissions, role_permission_mapping=None, super_admin_role="role_super_admin"):
        if role_permission_mapping is None:
            role_permission_mapping = []
        if permissions is not None and "azp" in self and "resource_access" in self and self["azp"] in \
                self["resource_access"]:
            resource_access = self["resource_access"][self["azp"]]
            if "roles" in resource_access and permissions is not None:
                user_permissions = []
                for role in resource_access["roles"]:
                    if role == super_admin_role:
                        return True
                    if role in role_permission_mapping:
                        for permission in role_permission_mapping[role]:
                            user_permissions.append(permission)
                for permission in permissions:
                    if permission in user_permissions:
                        return True
            elif "roles" not in resource_access and permissions is not None:
                return False
        elif permissions is None:
            return True
        return False


class JWTValidator(BearerTokenValidator, ABC):
    TOKEN_TYPE = 'bearer'
    token_cls = JWT

    def __init__(self, logger, static_issuer=False, static_public_key=False, realms=None, role_permission_file_location=False, super_admin_role="role_super_admin",
                 remote_token_validation=False, **extra_attributes):
        super().__init__(**extra_attributes)
        self.static_issuer = static_issuer
        self.static_public_key = static_public_key
        self.logger = logger
        self.public_key = None
        self.realms = [] if realms is None else realms
        claims_options = {
            'exp': {'essential': True},
            'azp': {'essential': True},
            'sub': {'essential': True},
        }
        self.claims_options = claims_options
        self.role_permission_mapping = None
        self.super_admin_role = super_admin_role
        self.remote_token_validation = remote_token_validation
        if role_permission_file_location:
            try:
                role_permission_file = open(role_permission_file_location)
                self.role_permission_mapping = json.load(role_permission_file)
            except IOError:
                logger.error("Could not read role_permission file: {}".format(role_permission_file_location))
            except JSONDecodeError:
                logger.error("Invalid json in role_permission file: {}".format(role_permission_file_location))

    def authenticate_token(self, token_string):
        issuer = self._get_unverified_issuer(token_string)
        if not issuer:
            return None
        realm_config = self._get_realm_config_by_issuer(issuer)
        if "public_key" in realm_config:
            self.public_key = "-----BEGIN PUBLIC KEY-----\n" + realm_config["public_key"] + "\n-----END PUBLIC KEY-----"
        else:
            self.public_key = ""
        try:
            claims = jwt.decode(
                token_string, self.public_key,
                claims_options=self.claims_options,
                claims_cls=self.token_cls,
            )
            claims.validate()
            if self.remote_token_validation:
                try:
                    result = requests.get("{}/protocol/openid-connect/userinfo".format(issuer),
                                          headers={"Authorization": "Bearer {}".format(token_string)})
                    if result.status_code != 200:
                        self.logger.info('Authenticate token failed. %r', result.content)
                        return None
                except Exception as error:
                    self.logger.info('Authenticate token failed. %r', error)
                    return None
            return claims
        except JoseError as error:
            self.logger.info('Authenticate token failed. %r', error)
            return None
        except ValueError as error:
            self.logger.info('Authenticate token failed. %r', error)
            return None

    def _get_realm_config_by_issuer(self, issuer):
        if issuer == self.static_issuer:
            return {"public_key": self.static_public_key}
        if issuer in self.realms:
            return requests.get(issuer).json()
        return {}

    def validate_token(self, token, permissions, request):
        """Check if token is active and matches the requested permissions."""
        if not token:
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if token.is_expired():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if token.is_revoked():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if not token.has_permissions(permissions, self.role_permission_mapping, self.super_admin_role):
            raise InsufficientPermissionError()

    @staticmethod
    def _get_unverified_issuer(token_string):
        try:
            payload = token_string.split(".")[1] + "=="  # "==" needed for correct b64 padding
        except:
            return False
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
