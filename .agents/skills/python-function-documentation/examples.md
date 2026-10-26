# Python Function Documentation Examples

Copy and adapt these patterns when adding or updating Python functions.

## Example 1: Private or `@not_keyword` helper with one-line docstring

Use for straightforward internal helpers.

```python
@not_keyword
def _normalize_sender_kid(sender_kid: str | bytes) -> bytes:
    """Normalize senderKID to bytes."""
    if isinstance(sender_kid, str):
        sender_kid = sender_kid.encode("utf-8")
    if not sender_kid:
        raise ValueError("senderKID must not be empty.")
    return sender_kid
```

## Example 2: Internal helper with Sphinx docstring (no `:rtype:`)

Use for low-level helpers not called directly by Robot keywords.

```python
def _normalize_sender_kid(sender_kid: str | bytes) -> bytes:
    """Normalize senderKID to bytes.

    :param sender_kid: senderKID as `str` or `bytes`.
    :return: Normalized senderKID as bytes.
    :raises ValueError: If senderKID is empty.
    """
    if isinstance(sender_kid, str):
        sender_kid = sender_kid.encode("utf-8")
    if not sender_kid:
        raise ValueError("senderKID must not be empty.")
    return sender_kid
```

## Example 3: User-facing utility with RobotFramework docstring

Use for functions consumed by test authors or by higher-level public flows.

```python
def prepare_example_info_value(fill_value: bool = False) -> rfc9480.InfoTypeAndValue:
    """Prepare the `InfoTypeAndValue` structure for an example message.

    Arguments:
    ---------
        - `fill_value`: If set to `True`, includes placeholder data.

    Returns:
    -------
        - A populated `InfoTypeAndValue` structure.

    Raises:
    ------
        - `ValueError`: If a required field cannot be generated.

    Examples:
    --------
    | ${itv}= | Prepare Example Info Value |
    | ${itv}= | Prepare Example Info Value | fill_value=True |

    """
    value = rfc9480.InfoTypeAndValue()
    value["infoType"] = rfc9480.id_it_caCerts
    if fill_value:
        value["infoValue"] = univ.OctetString(b"example")
    return value
```

## Example 4: Error behavior must be documented explicitly

When input validation exists, name the exact failure condition.

```python
def parse_positive_int(value: str) -> int:
    """Parse a positive integer from string input.

    :param value: String expected to contain a positive integer.
    :return: Parsed integer.
    :raises ValueError: If value is not numeric or less than 1.
    """
    parsed = int(value)
    if parsed < 1:
        raise ValueError("value must be >= 1")
    return parsed
```

## Example 5: Test coverage for documentation-relevant behavior

```bash
python -m pytest unit_tests -k "normalize_sender_kid"
python -m pytest unit_tests -k "prepare_example_info_value"
```

Coverage to include:

- positive path
- invalid input path (`ValueError` message check when meaningful)
- output type/shape checks

## Example 6: Run the docstring style checker

```bash
python3 .github/skills/python-skills/python-function-documentation/scripts/check_docstring_style.py resources/my_module.py
```

The script returns violations as a list of error strings and exits with a non-zero status if any violations are found.

## Example 7: User-facing doc update snippet

When behavior is visible to test writers, include a short usage note in docs:

```markdown
### New helper: `prepare_example_info_value`

Added helper for constructing `InfoTypeAndValue` test payloads.

- Default call produces an empty `infoValue`.
- `fill_value=True` adds placeholder bytes for negative/path tests.
```
