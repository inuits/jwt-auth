# readme

## install
pip install inuits-jwt-auth
## config
Example configuration with env variables
```python
import os
import logging
from inuits_jwt_auth.authorization import JWTValidator, MyResourceProtector

logging.basicConfig(
    format="%(asctime)s %(process)d,%(threadName)s %(filename)s:%(lineno)d [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)

logger = logging.getLogger(__name__)

require_oauth = MyResourceProtector(
    os.getenv("REQUIRE_TOKEN", True) == ("True" or "true" or True),
)
validator = JWTValidator(
    logger,
    os.getenv("STATIC_ISSUER", False),
    os.getenv("STATIC_PUBLIC_KEY", False),
    os.getenv("REALMS", "").split(","),
    os.getenv("ROLE_PERMISSION_FILE", "role_permission.json"),
    os.getenv("SUPER_ADMIN_ROLE", "role_super_admin"),
    os.getenv("REMOTE_TOKEN_VALIDATION", False),
)
require_oauth.register_token_validator(validator)
```
REQUIRE_TOKEN: boolean, if set to false then your application will work without authorization token, same as without this library.
ROLE_PERMISSION_FILE: json file with mapping for roles and permissions used in your application.
SUPER_ADMIN_ROLE: a role that can do everything without defining any permission mapping.
REMOTE_TOKEN_VALIDATION: boolean, if set to true then the library will check remotely if the jwt is really logged in
REALMS: comma separated list, here you define all realms that are allowed to authenticate with your application, same as "iss" in jwt token. Not needed when using static issuer and public key.

STATIC_ISSUER and STATIC_PUBLIC_KEY: these can be set if you use a token that cannot be remotely validated (usefull for local development without auth provider)
The static issuer should be the same as in the token (iss) you want to use.
The public key should be the same public key that is used to validate the token.
For example this jwt can be validated with static issuer "my-issuer" and public key "test-pub-key-1234"
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJteS1pc3N1ZXIiLCJpYXQiOjE2MzQ3MTQ1NzYsImV4cCI6MTY2NjIyNDAwMCwiYXVkIjoidGVzdCIsInN1YiI6InRlc3QiLCJHaXZlbk5hbWUiOiJ0ZXN0IiwiU3VybmFtZSI6InRlc3QiLCJFbWFpbCI6InRlc3QifQ.XX0OrQDh-vJMUXNqb7BG1qom9MI78W7xX3yTpTTYdCg
```
decoded:
```json
{
  "iss": "my-issuer",
  "iat": 1634714576,
  "exp": 1666224000,
  "aud": "test",
  "sub": "test",
  "GivenName": "test",
  "Surname": "test",
  "Email": "test"
}
```
Without setting the static issuer and public key in the env config, the library will try to get the realm config remotely which will ofcourse not work with "my-issuer".
As you can see in the code from this library:
```python
def _get_realm_config_by_issuer(self, issuer):
    if issuer == self.static_issuer:
        return {"public_key": self.static_public_key}
    if issuer in self.realms:
        return requests.get(issuer).json()
    return {}
```
Remote validation is also not possible due to the same reason, unless the issuer is remotely/locally available


### env example remote:
```dotenv
REALMS="https://foo.bar.test/auth/realms/foobar,https://rab.oof.test/auth/realms/raboof"
ROLE_PERMISSION_FILE="my_role_permission_mapping.json"
SUPER_ADMIN_ROLE="my_super_admin_role"
REMOTE_TOKEN_VALIDATION=True

```

### env example local:
```dotenv
ROLE_PERMISSION_FILE="my_role_permission_mapping.json"
SUPER_ADMIN_ROLE="my_super_admin_role"
REMOTE_TOKEN_VALIDATION=False
STATIC_ISSUER=local-dev
STATIC_PUBLIC_KEY=test-key
```

### example role permission mapping json:
```json
{
  "role_reader": [
    "read-item"
  ],
  "role_editor": [
    "read-item", 
    "update-item"
  ],
  "role_administrator": [
    "create-item",
    "read-item", 
    "update-item",
    "delete-item"
  ]
}
```
### example permission usage
You can use the require_oauth decorator to define what permission(s) are needed, can be a string,array or empty if you only need authentication but no permissions (for a user info endpoint etc.)
```python
class ItemDetail():
    @app.require_oauth("read-item")
    def get(self, id):
        return self.getItemById(id)
```
Or inside a function:

```python
import app

def do_something():
    if app.require_oauth.check_permission("can_do_something"):
        print("Do it")
    else:
        print("Don't do it")
```



