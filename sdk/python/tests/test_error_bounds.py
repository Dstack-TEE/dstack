# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""How much of a failed response ends up in the exception message.

An agent with no route for the path answers with an HTML page, and pasting a
whole page into an exception helps nobody. Rust caps the quoted body at 512
characters and JS at 300, both with comments saying why; Python quoted all of
it.
"""

import httpx
import pytest

from dstack_sdk.dstack_client_v0 import raise_for_status


def _response(status: int, body: str, content_type: str = "text/html") -> httpx.Response:
    request = httpx.Request("POST", "http://localhost/v1/Version")
    return httpx.Response(
        status, content=body.encode(), headers={"Content-Type": content_type}, request=request
    )


def test_quotes_a_bounded_slice_of_the_body():
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        raise_for_status(_response(400, "E" * 20_000))
    message = str(excinfo.value)
    assert len(message) < 1024, f"message is {len(message)} characters"
    assert "400" in message


def test_prefers_the_prpc_error_field():
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        raise_for_status(
            _response(400, '{"error":"algorithm is not supported"}', "application/json")
        )
    message = str(excinfo.value)
    assert "algorithm is not supported" in message
    assert '{"error"' not in message


def test_quotes_a_short_body_whole():
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        raise_for_status(_response(404, "<!DOCTYPE html>404"))
    assert "<!DOCTYPE html>404" in str(excinfo.value)


def test_a_success_status_raises_nothing():
    raise_for_status(_response(200, '{"version":"0.6.0"}', "application/json"))
