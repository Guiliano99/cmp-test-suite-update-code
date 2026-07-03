# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Client test logic for CMP operations."""

import shlex

from jinja2 import Template
from robot.api.deco import keyword

# Jinja2 templates for CMP CLI commands, define your template here
# This translates the tests in cmp_tests_jinja.robot to the actual commands that your CMP client will execute.
openssl = """
openssl cmp
 -cmd {{ cmd }}
 -server {{ server }}
 -subject {{ subject }}
 -secret {{ secret }}
{% if ref %}-ref {{ ref }}{% endif %}
{% if recipient %}-recipient "{{ recipient }}"{% endif %}
{% if csr %}-csr {{ csr }}{% endif %}
{% if newkey %}-newkey {{ newkey }}{% endif %}
{% if certout %}-certout {{ certout }}{% endif %}
{% if implicit_confirm %}-implicit_confirm{% endif %}
{% if unprotected_requests %}-unprotected_requests{% endif %}
"""

# The genCMPClient CLI (https://github.com/siemens/gencmpclient), built as `cmpClient`.
# `-config ""` disables loading its default config file, so that all options
# are given explicitly on the command line and the tests are self-contained.
# `-unprotected_errors` lets the client accept and report CMP error messages
# that it cannot authenticate (e.g., on wrong-secret or unprotected requests).
gencmpclient = """
{{ bin | default('../../gencmpclient/cmpClient') }}
 -config ""
 -cmd {{ cmd }}
 -server {{ server }}
{% if ref %} -ref {{ ref }}{% endif %}
{% if subject %} -subject {{ subject }}{% endif %}
{% if secret %} -secret {{ secret }}{% endif %}
{% if recipient %} -recipient "{{ recipient }}"{% endif %}
{% if csr %} -csr {{ csr }}{% endif %}
{% if newkey %} -newkey {{ newkey }}{% endif %}
{% if certout %} -certout {{ certout }}{% endif %}
{% if implicit_confirm %} -implicit_confirm{% endif %}
 -unprotected_errors
{% if unprotected_requests %} -unprotected_requests{% endif %}
"""

embedded_cmp = """
./build/embedded_cmp
{% if cmd == "ir" %}-i{% endif %}
{% if cmd == "p10cr" or cmd == "cr" %}-c{% endif %}
{% if cmd == "kur" %}-k{% endif %}
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

    rendered = template.render(**kwargs)
    return shlex.split(rendered)
