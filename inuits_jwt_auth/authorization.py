import base64
import functools
import json
import logging
import requests

from abc import ABC
from authlib.integrations.flask_oauth2 import (
    ResourceProtector,
    token_authenticated,
    current_token as current_token_authlib,
)
from authlib.jose import jwt
from authlib.oauth2 import HttpRequest, OAuth2Error
from authlib.oauth2.rfc6749 import MissingAuthorizationError
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7523 import JWTBearerToken
from contextlib import contextmanager
from datetime import datetime
from flask import _app_ctx_stack, request as _req
from werkzeug.exceptions import Unauthorized, Forbidden


class MyResourceProtector(ResourceProtector):
    def __init__(self, logger, require_token=True):
        super().__init__()
        self.require_token = require_token
        self.logger = logger

    def check_permission(self, permission: str) -> bool:
        try:
            self.acquire_token(permission)
            return True
        except Exception as error:
            self.logger.error(f"Acquiring token failed {error}")
            return False

    def acquire_token(self, permissions=None):
        """A method to acquire current valid token with the given scope.

        :param permissions: a list of required permissions
        :return: token object
        """
        request = HttpRequest(_req.method, _req.full_path, _req.data, _req.headers)
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
    def __init__(self, payload, header, options=None, params=None):
        super().__init__(payload, header, options, params)
        logging.basicConfig(
            format="%(asctime)s %(process)d,%(threadName)s %(filename)s:%(lineno)d [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.INFO,
        )
        self.logger = logging.getLogger(__name__)

    def has_permissions(
        self,
        permissions,
        role_permission_mapping=None,
        super_admin_role="role_super_admin",
    ):
        if not permissions:
            self.logger.info("NO PERMISSIONS REQUESTED")
            return True
        if any(x not in self for x in ["azp", "resource_access"]):
            self.logger.info(f'AZP NOT IN SELF: {"azp" not in self}')
            self.logger.info(f'R_A NOT IN SELF: {"resource_access" not in self}')
            return False
        if self["azp"] not in self["resource_access"]:
            self.logger.info("AZP NOT IN R_A")
            return False
        resource_access = self["resource_access"][self["azp"]]
        if "roles" not in resource_access:
            self.logger.info("NO ROLES IN R_A")
            return False
        if super_admin_role in resource_access["roles"]:
            self.logger.info("IS SUPER ADMIN")
            return True
        if not role_permission_mapping:
            self.logger.info("NO ROLE MAPPING")
            return False
        user_permissions = []
        for role in resource_access["roles"]:
            self.logger.info(f"ROLE: {role}")
            if role in role_permission_mapping:
                self.logger.info(f"{role} IS IN MAPPING")
                user_permissions.extend([x for x in role_permission_mapping[role]])
        self.logger.info(f"USER HAS PERMISSIONS: {user_permissions}")
        if all(x in user_permissions for x in permissions):
            self.logger.info("USER HAS ALL REQUESTED PERMISSIONS")
            return True
        self.logger.info(f"REQUESTED PERMISSIONS {permissions} ARE NOT ALL IN USER PERMISSIONS {user_permissions}")
        return False


class JWTValidator(BearerTokenValidator, ABC):
    TOKEN_TYPE = "bearer"
    token_cls = JWT

    def __init__(
        self,
        logger,
        static_issuer=None,
        static_public_key=None,
        realms=None,
        role_permission_file_location=None,
        super_admin_role="role_super_admin",
        remote_token_validation=False,
        remote_public_key=None,
        realm_cache_sync_time=1800,
        **extra_attributes,
    ):
        super().__init__(**extra_attributes)
        self.static_issuer = static_issuer
        self.static_public_key = static_public_key
        self.logger = logger
        self.public_key = ""
        self.realms = realms if realms else []
        claims_options = {
            "exp": {"essential": True},
            "azp": {"essential": True},
            "sub": {"essential": True},
        }
        self.claims_options = claims_options
        self.role_permission_mapping = None
        self.super_admin_role = super_admin_role
        self.remote_token_validation = remote_token_validation
        self.remote_public_key = remote_public_key
        self.realm_cache_sync_time = realm_cache_sync_time
        self.realm_config_cache = {}
        if role_permission_file_location:
            try:
                with open(role_permission_file_location, "r") as file:
                    self.role_permission_mapping = json.load(file)
            except IOError:
                self.logger.error(
                    f"Could not read role_permission file: {role_permission_file_location}"
                )
            except json.JSONDecodeError:
                self.logger.error(
                    f"Invalid json in role_permission file: {role_permission_file_location}"
                )

    def authenticate_token(self, token_string):
        issuer = self.__get_unverified_issuer(token_string)
        if not issuer:
            return None
        realm_config = self.__get_realm_config_by_issuer(issuer)
        if "public_key" in realm_config:
            self.public_key = (
                "-----BEGIN PUBLIC KEY-----\n"
                + realm_config["public_key"]
                + "\n-----END PUBLIC KEY-----"
            )
        try:
            claims = jwt.decode(
                token_string,
                self.public_key,
                claims_options=self.claims_options,
                claims_cls=self.token_cls,
            )
            claims.validate()
            if self.remote_token_validation:
                result = requests.get(
                    f"{issuer}/protocol/openid-connect/userinfo",
                    headers={"Authorization": f"Bearer {token_string}"},
                )
                if result.status_code != 200:
                    raise Exception(result.content.strip())
            return claims
        except Exception as error:
            self.logger.error(f"Authenticate token failed: {error}")
            return None

    def __get_realm_config_by_issuer(self, issuer):
        if issuer == self.static_issuer:
            return {"public_key": self.static_public_key}
        if issuer not in self.realms:
            return {}
        if self.remote_public_key:
            return {"public_key": self.remote_public_key}
        current_time = datetime.timestamp(datetime.now())
        if (
            issuer in self.realm_config_cache
            and current_time - self.realm_config_cache[issuer]["last_sync_time"]
            < self.realm_cache_sync_time
        ):
            return self.realm_config_cache[issuer]
        self.realm_config_cache[issuer] = requests.get(issuer).json()
        self.realm_config_cache[issuer]["last_sync_time"] = current_time
        return self.realm_config_cache[issuer]

    def validate_token(self, token, permissions, request):
        """Check if token is active and matches the requested permissions."""
        super().validate_token(token, None, request)
        if not token.has_permissions(
            permissions, self.role_permission_mapping, self.super_admin_role
        ):
            raise InsufficientPermissionError()

    @staticmethod
    def __get_unverified_issuer(token_string):
        try:
            # Adding "=="  is necessary for correct base64 padding
            payload = f'{token_string.split(".")[1]}=='
        except:
            return None
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
        if "iss" in decoded:
            return decoded["iss"]
        return None


class InsufficientPermissionError(OAuth2Error):
    """The request requires higher privileges than provided by the
    access token. The resource server SHOULD respond with the HTTP
    403 (Forbidden) status code and MAY include the "scope"
    attribute with the scope necessary to access the protected
    resource.

    https://tools.ietf.org/html/rfc6750#section-3.1
    """

    error = "insufficient_permission"
    description = (
        "The request requires higher privileges than provided by the access token."
    )
    status_code = 403


current_token = current_token_authlib
