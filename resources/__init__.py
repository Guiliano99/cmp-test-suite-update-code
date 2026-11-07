# noqa D104 Missing docstring in public package
# SPDX-FileCopyrightText: Copyright 2024 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

import sys

# When dealing with post-quantum crypto algorithms, we encounter big numbers, which wouldn't be pretty-printed
# otherwise. This is just for cosmetic convenience. It lives in the package so that it runs whichever module is
# imported first.
sys.set_int_max_str_digits(0)
