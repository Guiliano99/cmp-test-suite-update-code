# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Client test logic for CMP operations."""

import os

from jinja2 import Template
from robot.api.deco import keyword

# Default location of the Rust `gencmpclient-rs` binary, relative to the
# `client_tests/` directory. Override with the GENCMPCLIENT_RS_BIN env var.
DEFAULT_GENCMPCLIENT_RS_BIN = "../../gencmpclient-rs/target/release/gencmpclient-rs"

# Jinja2 templates for CMP CLI commands, define your template here
# This translates the tests in cmp_tests_jinja.robot to the actual commands that your CMP client will execute.
openssl = """
openssl cmp
 -cmd {{ cmd }}
 -server {{ server }}
 -subject {{ subject }}
 -secret {{ secret }}
 -ref {{ ref | default('NULL-DN') }}
{% if recipient %}-recipient {{ recipient }}{% endif %}
{% if csr %}-csr {{ csr }}{% endif %}
{% if newkey %}-newkey {{ newkey }}{% endif %}
{% if certout %}-certout {{ certout }}{% endif %}
{% if unprotected_requests %}-unprotected_requests{% endif %}
"""

gencmpclient = """
gencmpclient  {{ cmd }}
 --server {{ server }}
 --ref {{ ref }}
 --subject "{{ subject }}"
 --secret "{{ secret }}"
 {% if csr %}--csr {{ csr }}{% endif %}
 {% if newkey %}--newkey {{ newkey }}{% endif %}
 {% if certout %}--certout {{ certout }}{% endif %}
"""

embedded_cmp = """
./build/embedded_cmp
{% if cmd == "ir" %}-i{% endif %}
{% if cmd == "p10cr" or cmd == "cr" %}-c{% endif %}
{% if cmd == "kur" %}-k{% endif %}
"""

# Rust reference client (https://github.com/Guiliano99/gencmpclient-rs).
# The binary path comes from `bin` (injected in get_cmp_command from the
# GENCMPCLIENT_RS_BIN env var). Unlike the `gencmpclient` template above this one
# maps every keyword argument the test cases pass, including `recipient` and
# `unprotected_requests`.
gencmpclient_rs = """
{{ bin }} {{ cmd }}
 --server {{ server }}
{% if ref %}--ref {{ ref }}{% endif %}
{% if subject %}--subject {{ subject }}{% endif %}
{% if secret %}--secret {{ secret }}{% endif %}
{% if recipient %}--recipient {{ recipient }}{% endif %}
{% if csr %}--csr {{ csr }}{% endif %}
{% if newkey %}--newkey {{ newkey }}{% endif %}
{% if certout %}--certout {{ certout }}{% endif %}
{% if unprotected_requests %}--unprotected_requests{% endif %}
"""


@keyword(name="Get CMP Command")
def get_cmp_command(client: str = "openssl", **kwargs) -> list:  # noqa: D417
    """Construct a CMP command based on the client and keyword arguments.

    Arguments:
    ---------
    - `client`: The CMP client to use (e.g. "openssl").
    - `**kwargs`: Keyword arguments like cmd, server, ref, subject, etc.

    Returns:
    -------
    - List of command-line arguments suitable for use with Run Process

    Example:
    -------
    | ${args}= | Get CMP Command | openssl | cmd=ir | server=http://localhost:5000 | ... |

    """
    try:
        template = Template(globals()[client])
    except KeyError as e:
        raise ValueError(f"Unsupported CMP client: {client}") from e

    # Resolve the gencmpclient-rs binary path from the environment so the suite
    # can point at any build without editing the template.
    kwargs.setdefault("bin", os.environ.get("GENCMPCLIENT_RS_BIN", DEFAULT_GENCMPCLIENT_RS_BIN))

    rendered = template.render(**kwargs)
    return rendered.strip().split()
