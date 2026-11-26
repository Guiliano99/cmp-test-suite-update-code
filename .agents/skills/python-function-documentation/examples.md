# Docstring examples

Copy these patterns. They are real functions of the cmp-test-suite.

## Private or `@not_keyword` function: one line

`resources/convertutils.py`:

```python
@not_keyword
def ensure_is_sign_key(key: Any) -> SignKey:
    """Ensure provided key is allowed to sign."""
```

## Private or `@not_keyword` function: Sphinx without `:rtype:`

`resources/prepareutils.py`:

```python
def _prepare_date_time_object(
    date: Optional[Union[str, float, datetime]] = None,
) -> datetime:
    """Prepare a date time object.

    :param date: The date to use. If None, the current date is used.
    :return: The populated `datetime` object.
    """
```

## Keyword: all four sections

`resources/keyutils.py`. The comment on the `def` line tells `ruff` that the docstring is written for RF.

```python
def load_public_key_from_file(filepath: str) -> PublicKey:  # noqa: D417 for RF docs
    """Load a public key from a file.

    Load a cryptographic public key from a PEM-encoded file.

    Arguments:
    ---------
        - `filepath`: the path to the file containing the key data.

    Returns:
    -------
        - An instance of the loaded public key, such as `RSAPublicKey`, `X448PublicKey`, or `X25519PublicKey`.

    Raises:
    ------
        - `FileNotFoundError`: If the file does not exist.
        - `ValueError`: If the file content is not a valid public key format.

    Examples:
    --------
    | ${public_key}= | Load Public Key From File | /path/to/public_key.pem |
    | ${x448_key}= | Load Public Key From File | /path/to/x448_public_key.pem | key_type=x448 |

    """
```

## Keyword that returns nothing and raises nothing: Arguments and Examples

`resources/cmputils.py`:

```python
def try_to_log_pkimessage(data: Union[str, bytes, base.Asn1Type]):  # noqa: D417 for RF docs
    """Try to decode a DER-encoded PKIMessage and log the ASN1 structure in a human-readable way.

    Will also accept inputs that are pyasn1 objects or strings, for the convenience of invocation from RF tests.

    Arguments:
    ---------
        - `data`: something that is assumed to be a PKIMessage structure, either DER-encoded or a pyasn1 object.

    Examples:
    --------
    | Try To Log PKIMessage | ${der_data} |
    | Try To Log PKIMessage | ${message} |

    """
```

## Keyword that raises nothing itself: no Raises

`resources/httputils.py`, `http_response_contains_pki_message`, has `Arguments:`, `Returns:` and `Examples:`.

## Document the errors that callers see

When the function validates input, name the error and the condition in `Raises:`:

```text
    Raises:
    ------
        - `ValueError`: If value is not numeric or less than 1.
```

## Run the checker

```bash
.venv/bin/python .agents/skills/python-function-documentation/scripts/check_docstring_style.py resources/keyutils.py
.venv/bin/python .agents/skills/python-function-documentation/scripts/check_docstring_style.py resources pq_logic --since origin/main
```

The script lists the violations and exits 1 if there is one.
