# APIStrike Labs

Authorized, local-only vulnerable targets for developing and testing APIStrike.
Everything here runs on `localhost` inside Docker -- never point APIStrike at a
system you do not own or are not explicitly authorized to test.

## VAmPI (Vulnerable API)

[VAmPI](https://github.com/erev0s/VAmPI) is a deliberately vulnerable REST API
built to mirror the OWASP API Security Top 10 -- an ideal first target.

### Run it

```bash
cd labs
docker compose up -d
```

- Base URL: `http://localhost:5000`
- Swagger UI: `http://localhost:5000/ui/`
- OpenAPI spec: `http://localhost:5000/openapi.json`

### Seed / reset the demo data

```bash
curl http://localhost:5000/createdb
```

### Useful endpoints (for manual poking)

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/` | Welcome + mode (vulnerable/secure) |
| GET | `/createdb` | (Re)create and seed the SQLite demo DB |
| POST | `/users/v1/register` | Register a user |
| POST | `/users/v1/login` | Log in -> returns a JWT |
| GET | `/users/v1` | List users |
| GET | `/users/v1/{username}` | Get a user (BOLA playground) |
| GET | `/users/v1/_debug` | Excessive data exposure |
| GET | `/books/v1` | List books |
| POST | `/books/v1` | Add a book |
| GET | `/books/v1/{title}` | Get a book (BOLA playground) |

### Modes

- `vulnerable=1` (default here): intentionally vulnerable -- what we test against.
- `vulnerable=0`: hardened -- use later to check APIStrike for false positives.

Edit `vulnerable` in `docker-compose.yml`, then `docker compose up -d` again.

### Stop / clean up

```bash
docker compose down
```
