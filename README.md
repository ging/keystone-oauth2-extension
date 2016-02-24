# keystone-oauth2-extension
OpenStack Keystone extension to enable OAuth 2.0.

## How to Install
To install this extension in Keystone, you have to do the following:

1. Place the `oauth2` folder inside the `keystone/contrib` folder in your Keystone project.

2. Place the files in `tests/` inside the `keystone/tests` folder in your Keystone project.

3. This extension implements an auth plugin. You need to add the `plugins/oauth2.py` module to the `keystone/auth/plugins` folder in your Keystone project.

   > The files inside the `config` folder contain everything you need to **add** to your Keystone settings files (`etc/keystone.conf` and `etc/keystone-paste.ini`). If you are an experienced user, you can check those files and **skip steps 4-6**. Should you prefer to set up everything step by step, please read on.

4. Since this extension is augmenting a pipeline (see [Keystone docs](http://docs.openstack.org/developer/keystone/extension_development.html#modifying-the-keystone-paste-ini-file) for more info), a corresponding `filter:` section is necessary to be introduced in your `etc/keystone-paste.ini` file. Just place the following:
   ```
   [filter:oauth2_extension]
   paste.filter_factory = keystone.contrib.oauth2.routers:OAuth2Extension.factory
   ``` 
5. In order for the extension to work, it must be placed in the `pipeline`.

6. Edit the `[auth]` section in your `keystone.conf` file (the one placed in the `etc` folder in your Keystone project), to include OAuth 2.0 auth method, just like this:
   <pre>
   # Default auth methods. (list value)
   methods=external,password,token,<b>oauth2</b>
   </pre>

   At the end of the section you have to add this:
   ```
   # The oauth2 plugin module (string value)
   oauth2=keystone.auth.plugins.oauth2.OAuth2
   ```

7. Define new policies in your `policy.json` file (the one placed in the `etc` folder in your Keystone project) for the following targets: 
   ```
   identity:list_authorization_codes
   identity:revoke_access_token
   identity:request_authorization_code
   ```
The file `config/policy.json` contains default values you can use, as well as other required policies which Keystone should include by default.

8. Check Python dependencies. This extension uses [OAuthLib](https://oauthlib.readthedocs.org/en/latest/), tested to work with versions >=0.7.2, <=1.0.3. This is already a dependency in Keystone and you should not need to install it again, but if you are not using the standard Keystone installation, make sure to add it.

