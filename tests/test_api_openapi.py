from blackice.api.app import app


def test_run_endpoint_openapi_includes_409_example():
    spec = app.openapi()
    paths = spec.get("paths", {})
    assert "/v1/run" in paths

    post = paths["/v1/run"].get("post", {})
    responses = post.get("responses", {})
    assert "409" in responses, "Expected 409 response in OpenAPI for /v1/run"

    resp_409 = responses["409"]
    content = resp_409.get("content", {})
    app_json = content.get("application/json", {})
    example = app_json.get("example")
    assert example is not None, "Expected application/json example for 409 response"
    assert example.get("error", {}).get("code") == "AUDIT_NORMALIZATION"


def test_run_request_has_example():
    spec = app.openapi()

    # Try requestBody example first
    post = spec.get("paths", {}).get("/v1/run", {}).get("post", {})
    request_body = post.get("requestBody", {})
    rb_content = request_body.get("content", {}).get("application/json", {})
    rb_example = rb_content.get("example")

    # Fallback: look in components.schemas.RunRequest.example
    comp_example = spec.get("components", {}).get("schemas", {}).get("RunRequest", {}).get("example")

    assert (rb_example or comp_example), "Expected an example for RunRequest in OpenAPI"
