import pytest
from requests import PreparedRequest
from responses import RequestsMock

from testsutils import loader


def _get_request(responses: RequestsMock, url: str) -> PreparedRequest:
    for call in responses.calls:
        if call.request.url == url:
            # Pop out verified request (to be able to check multiple requests)
            responses.calls._calls.remove(call)
            return call.request


@pytest.fixture
def base_path_ending_with_slash_service(responses: RequestsMock):
    responses.add(
        responses.GET,
        url="http://localhost:8957/",
        json={
            "swagger": "2.0",
            "basePath": "//",
            "paths": {
                "/method": {
                    "get": {
                        "operationId": "get_method",
                        "responses": {
                            "200": {
                                "description": "return value",
                                "schema": {"type": "string"},
                            }
                        },
                    },
                    "post": {
                        "operationId": "post_method",
                        "responses": {
                            "200": {"description": "POST performed properly"}
                        },
                    },
                    "put": {
                        "operationId": "put_method",
                        "responses": {"200": {"description": "PUT performed properly"}},
                    },
                    "delete": {
                        "operationId": "delete_method",
                        "responses": {
                            "200": {"description": "DELETE performed properly"}
                        },
                    },
                }
            },
        },
        match_querystring=True,
    )


def test_get_base_path_ending_with_slash(
    responses: RequestsMock, base_path_ending_with_slash_service, tmpdir
):
    pyxelrestgenerator = loader.load(
        tmpdir,
        {
            "base_path_ending_with_slash": {
                "open_api": {"definition": "http://localhost:8957/"},
                "udf": {"return_types": ["sync_auto_expand"], "shift_result": False},
            }
        },
    )
    responses.add(
        responses.GET,
        url="http://localhost:8957/method",
        json={},
        match_querystring=True,
    )

    assert pyxelrestgenerator.base_path_ending_with_slash_get_method() == [[""]]


def test_post_base_path_ending_with_slash(
    responses: RequestsMock, base_path_ending_with_slash_service, tmpdir
):
    pyxelrestgenerator = loader.load(
        tmpdir,
        {
            "base_path_ending_with_slash": {
                "open_api": {"definition": "http://localhost:8957/"},
                "udf": {"return_types": ["sync_auto_expand"], "shift_result": False},
            }
        },
    )
    responses.add(
        responses.POST,
        url="http://localhost:8957/method",
        json={},
        match_querystring=True,
    )

    assert pyxelrestgenerator.base_path_ending_with_slash_post_method() == [[""]]


def test_put_base_path_ending_with_slash(
    responses: RequestsMock, base_path_ending_with_slash_service, tmpdir
):
    pyxelrestgenerator = loader.load(
        tmpdir,
        {
            "base_path_ending_with_slash": {
                "open_api": {"definition": "http://localhost:8957/"},
                "udf": {"return_types": ["sync_auto_expand"], "shift_result": False},
            }
        },
    )
    responses.add(
        responses.PUT,
        url="http://localhost:8957/method",
        json={},
        match_querystring=True,
    )

    assert pyxelrestgenerator.base_path_ending_with_slash_put_method() == [[""]]


def test_delete_base_path_ending_with_slash(
    responses: RequestsMock, base_path_ending_with_slash_service, tmpdir
):
    pyxelrestgenerator = loader.load(
        tmpdir,
        {
            "base_path_ending_with_slash": {
                "open_api": {"definition": "http://localhost:8957/"},
                "udf": {"return_types": ["sync_auto_expand"], "shift_result": False},
            }
        },
    )
    responses.add(
        responses.DELETE,
        url="http://localhost:8957/method",
        json={},
        match_querystring=True,
    )

    assert pyxelrestgenerator.base_path_ending_with_slash_delete_method() == [[""]]
