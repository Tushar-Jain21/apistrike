import json

import yaml

from apistrike.recon.spec_parser import APISpec, load_spec, parse_spec

VAMPI_LIKE = {
    "openapi": "3.0.1",
    "info": {"title": "VAmPI", "version": "1.0"},
    "servers": [{"url": "/"}],
    "paths": {
        "/users/v1": {
            "get": {"operationId": "list_users", "summary": "List users"},
        },
        "/users/v1/{username}": {
            "get": {
                "operationId": "get_user",
                "parameters": [
                    {"name": "username", "in": "path", "required": True,
                     "schema": {"type": "string"}}
                ],
                "security": [{"bearerAuth": []}],
            },
        },
        "/users/v1/register": {
            "post": {
                "operationId": "register",
                "requestBody": {"content": {"application/json": {"schema": {}}}},
            },
        },
    },
}


def test_parse_spec_from_dict():
    api = parse_spec(VAMPI_LIKE, base_url="http://localhost:5000")
    assert isinstance(api, APISpec)
    assert api.title == "VAmPI"
    assert api.base_url == "http://localhost:5000"
    assert len(api) == 3
    # path param detection
    getters = api.by_method("GET")
    user_ep = next(e for e in getters if e.path == "/users/v1/{username}")
    assert [p.name for p in user_ep.path_params] == ["username"]
    assert user_ep.requires_auth
    # request body detection
    post = api.by_method("POST")[0]
    assert post.has_request_body
    assert not post.requires_auth


def test_load_spec_from_json_file(tmp_path):
    f = tmp_path / "openapi.json"
    f.write_text(json.dumps(VAMPI_LIKE), encoding="utf-8")
    api = load_spec(str(f))
    assert len(api) == 3
    assert api.title == "VAmPI"


def test_load_spec_from_yaml_file(tmp_path):
    f = tmp_path / "openapi.yaml"
    f.write_text(yaml.safe_dump(VAMPI_LIKE), encoding="utf-8")
    api = load_spec(str(f))
    assert len(api) == 3
    assert api.with_path_params()[0].path == "/users/v1/{username}"


def test_swagger2_base_url():
    swagger = {
        "swagger": "2.0",
        "info": {"title": "Legacy", "version": "2.0"},
        "host": "api.example.com",
        "basePath": "/v2",
        "schemes": ["https"],
        "paths": {"/ping": {"get": {"operationId": "ping"}}},
    }
    api = parse_spec(swagger)
    assert api.base_url == "https://api.example.com/v2"
    assert len(api) == 1
