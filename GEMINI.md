# GEMINI.md - Project Context

This file provides instructional context for the `haproxy-auth-request` project.

## Project Overview

`haproxy-auth-request` is a Lua script for HAProxy that enables external authentication by performing subrequests to a configured backend. It is inspired by Nginx's `ngx_http_auth_request_module`.

### Main Technologies
- **Lua**: The core logic is implemented in `auth-request.lua`.
- **HAProxy**: The target platform (requires HAProxy 1.8.4+ with `USE_LUA=1`).
- **haproxy-lua-http**: A dependency for making HTTP requests within the HAProxy Lua environment (included as a git submodule).

### Architecture
- The script registers two HAProxy actions: `auth-request` and `auth-intercept`.
- It communicates results back to HAProxy via variables like `txn.auth_response_successful` and `req.auth_response_header.*`.
- It selects a server from the specified backend that is either UP or has no checks.

## Building and Running

### Requirements
- HAProxy with Lua support.
- `lua-json` library installed on the system.
- `haproxy-lua-http` available in the Lua path.

### Installation
Use the `Makefile` to install the script to `/usr/share/haproxy`:
```bash
sudo make install
```

### Usage
Load the script in the `global` section of `haproxy.cfg`:
```haproxy
global
    lua-load /usr/share/haproxy/auth-request.lua
```

## Testing

The project uses `vtest` (Varnish Test) for integration testing.

### Running Tests
To run all tests locally (requires `vtest` and `haproxy` to be installed):
```bash
vtest -k -t 10 test/*.vtc
```

### Test Structure
- Tests are located in the `test/` directory as `.vtc` files.
- Each `.vtc` file defines an HAProxy configuration, mock servers, and clients to verify specific behaviors (e.g., `allow.vtc`, `deny.vtc`).

## Development Conventions

- **Indentation**: Uses tabs for indentation.
- **Licensing**: All files should include the MIT License header.
- **Error Handling**: Uses HAProxy's `txn:Alert` and `txn:Warning` for logging errors.
- **Compatibility**: The script includes logic to handle differences between HAProxy versions (e.g., variable setting pre/post 2.2).
- **Submodules**: The `haproxy-lua-http` dependency is managed as a git submodule. Ensure submodules are initialized: `git submodule update --init --recursive`.

## Key Files
- `auth-request.lua`: The main Lua script.
- `Makefile`: Installation script.
- `test/`: Integration tests using `vtest`.
- `.github/workflows/test.yml`: CI configuration for testing across multiple HAProxy versions.
