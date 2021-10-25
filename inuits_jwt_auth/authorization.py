import base64
import json
from abc import ABC
import requests
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc7523 import JWTBearerToken
from authlib.jose import jwt, JoseError
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6749 import MissingAuthorizationError, UnsupportedTokenTypeError


class MyResourceProtector(ResourceProtector):
    def __init__(self, static_jwt):
        super().__init__()
        self.static_jwt = static_jwt

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
        if not auth and (self.static_jwt is not False):
            auth = "Bearer " + self.static_jwt
        elif not auth:
            raise MissingAuthorizationError(self._default_auth_type, self._default_realm)
        # https://tools.ietf.org/html/rfc6749#section-7.1
        token_parts = auth.split(None, 1)
        if len(token_parts) != 2:
            raise UnsupportedTokenTypeError(self._default_auth_type, self._default_realm)

        token_type, token_string = token_parts
        validator = self.get_token_validator(token_type)
        return validator, token_string


class JWTValidator(BearerTokenValidator, ABC):
    TOKEN_TYPE = 'bearer'
    token_cls = JWTBearerToken

    def __init__(self, logger, static_jwt=False, static_issuer=False, static_public_key=False, realms=None, **extra_attributes):
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

    def authenticate_token(self, token_string):
        if self.static_jwt is not False:
            token_string = self.static_jwt
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

    @staticmethod
    def _get_unverified_issuer(token_string):
        payload = token_string.split(".")[1] + "=="  # "==" needed for correct b64 padding
        decoded = json.loads(base64.b64decode(payload.encode('utf-8')))
        if "iss" in decoded:
            return decoded["iss"]
        else:
            return False
