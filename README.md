# keystone-oauth2-extension
OpenStack Keystone extension to enable OAuth 2.0

## How to Install
To install this extension in Keystone, you have to do the following:
1. Place the `oauth2` folder inside the `keystone/contrib` folder in your Keystone project.
2. Place the `test_v3_oauth2.py` file inside the `keystone/tests` folder in your Keystone project.
3. Edit the `[auth]` section in your `keystone.conf` file (the one placed in the `etc` folder in your Keystone project), to include oauth2 auth method, just like this:
```
# Default auth methods. (list value)
methods=external,password,token,**oauth2**
```
At the end of the section you have to add this:
```
# The oauth2 plugin module (string value)
oauth2=keystone.auth.plugins.oauth2.OAuth2
```