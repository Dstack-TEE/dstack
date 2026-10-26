# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import httpx
import pytest

from dstack_sdk.dstack_client_v0 import MAX_ERROR_BODY_CHARS
from dstack_sdk.dstack_client_v0 import raise_for_status

TRUNCATED = "E" * MAX_ERROR_BODY_CHARS + "..."


@pytest.mark.parametrize(
    ("body", "said"),
    [
        ("<!DOCTYPE html>404", "<!DOCTYPE html>404"),
        ("E" * 20_000, TRUNCATED),
        ('{"error":"algorithm is not supported"}', "algorithm is not supported"),
        ('{"error":"' + "E" * 8_000 + '"}', TRUNCATED),
    ],
)
def test_error_quotes_bounded_server_text(body, said):
    request = httpx.Request("POST", "http://localhost/v1/Version")
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        raise_for_status(httpx.Response(400, content=body.encode(), request=request))
    assert str(excinfo.value).endswith(f"\nguest agent said: {said}")
