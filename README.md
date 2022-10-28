# springrts matrix synapse uberserver xmlrpc password provider


## Configure
Add or amend the `password_providers` entry like so:
```
password_providers:
  - module: "spring_auth_provider.SpringRTSAuthProvider"
    config:
      enabled: true
      endpoint: "http://127.0.0.1:8300/"
      domain: "springrts.com"
```
