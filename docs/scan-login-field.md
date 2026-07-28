# Add a configurable login field to `scan` (`--login-field`)

crAPI's login expects the identity under an **`email`** field, not `username`.
`LoginConfig` already supports `username_field`, so this is a tiny, backward-
compatible change to the `scan` command in `apistrike/cli.py` (default stays
`username`, so VAmPI and existing behavior are unchanged).

## 1. Add the option to the `scan(...)` signature

Find this parameter in `def scan(`:

```python
    login_path: str = typer.Option("/users/v1/login", help="Login endpoint path on the target."),
```

and add the new option **right after** it:

```python
    login_field: str = typer.Option(
        "username", "--login-field",
        help="Body field name for the identity on login (e.g. 'email' for crAPI).",
    ),
```

## 2. Thread it into the `LoginConfig`

Inside `scan`'s inner `_run`, change:

```python
            engine = AuthEngine(
                client, base_url=target, login_config=LoginConfig(login_path=login_path)
            )
```

to:

```python
            engine = AuthEngine(
                client, base_url=target,
                login_config=LoginConfig(login_path=login_path, username_field=login_field),
            )
```

## 3. Verify

```bash
python -m apistrike scan --help | grep login-field
# crAPI: sends {"email": ..., "password": ...}
python -m apistrike scan http://localhost:8888 --scope scope.crapi.yaml \
    -u user@example.com -p pass --login-path /identity/api/auth/login --login-field email
```

> Note: `scan` currently runs the **broken-auth** module once authenticated.
> Deep authenticated BOLA / mass-assignment coverage against crAPI is a natural
> v1.1 follow-up (those modules have their own commands).
