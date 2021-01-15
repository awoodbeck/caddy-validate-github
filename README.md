# caddy-validate-github

Caddy v2 middleware for validating a GitHub webhook request

## Installation

```
xcaddy build \
    --with github.com/awoodbeck/caddy-validate-github
```

## Usage

This middleware functions as a gatekeeper for any succeeding directives in a route.
The request is only passed on to the next directive if its signature is valid.
Otherwise, the client receives a 403 status code.

### Caddyfile
```
validate_github <secret>
```
* **secret** - shared secret between you and GitHub

You could use something like this bash command to generate a secure secret:

```bash
LC_ALL=C tr -dc '[:alnum:]' < /dev/urandom | head -c32; echo
```

Copy and paste the results into your Caddyfile.

#### Example

`validate_github` is middleware meant to precede other directives.

An example of this directive in context looks like this:

```
route /update {
    validate_github KcuP9N0iEqYHFBRUda6oHLP4UUub6EMz
    exec * /path/to/bin/update.sh
}
```

Here, you're using `validate_github` to validate the request before passing
it along to [caddy-exec](https://github.com/abiosoft/caddy-exec), runs the
`/path/to/bin/update.sh` script. Since `caddy-exec` does not support chaining
commands at this time, it's necessary to perform multiple commands in a script
or Go binary and invoke it from the `exec` directive.

### JSON

The `validate_github` JSON look like this, minus succeeding middleware:
```json
{
  "routes": [
    {
      "handle": [
        {
          "handler": "validate_github",
          "secret": "KcuP9N0iEqYHFBRUda6oHLP4UUub6EMz"
        }
      ],
      "match": [
        {
          "path": [
            "/refresh"
          ]
        }
      ]
    }
  ]
}
```