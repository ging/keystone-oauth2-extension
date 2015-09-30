If you want to run the tests to verify that the extension is installed correctly, you need to modify the file **keystone/tests/core.py**
- In the function `auth_plugin_config_override`:
 - Add **oauth2** to the methods: `methods = ['external', 'password', 'token', 'oauth1', 'saml2', 'oauth2']`
 - Add the plugin to method_classes:
```
              method_classes = dict(
                  external='keystone.auth.plugins.external.DefaultDomain',
                  password='keystone.auth.plugins.password.Password',
                  token='keystone.auth.plugins.token.Token',
                  oauth1='keystone.auth.plugins.oauth1.OAuth',
                  saml2='keystone.auth.plugins.saml2.Saml2',
                  oauth2='keystone.auth.plugins.oauth2.OAuth2'
              )
```
  
Run the tests using:
`$ sudo tox -e py27 keystone.tests.test_v3_oauth2`
