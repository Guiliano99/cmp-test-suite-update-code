# Overview
A library of primitives for automating PKI- and CMP-related tests using RobotFramework.

## Structure
- `tests` - the test suites themselves
- `resources` - reusable keywords written in RF or Python
- `data` - pre-generated test data (e.g., keys, certificates), if required
- `config` - a place for storing configuration options (e.g., IP addresses, port numbers, etc.)


# Configuration
Prepare your environment by installing the dependencies from `requirements.txt`. Using a Python virtualenv is a good
practice. In this case you would run `pip install -r requirements.txt` inside the environment.

# Usage
1. Run `robot tests` to execute all the tests in the `tests/` directory.
2. Explore `report.html` to see the results.


Other useful commands
- `make test` - run all the tests
- `make doc` - generate HTML documentation for test suites and available keywords, store in `doc/`.


# Design considerations
## Constant data
In many cases it is better to use the same data across runs, instead of generating something on-the-fly. This supports
replicability, because the test will always send the same data, therefore it is easier for the authors of the system
under test to answer the question "what exactly happened when the error occurred?". Consider the example of sending a
CSR - if you generate it on-the-fly, its signature will be different, even if everything else in the CSR is identical.

Follow these principles when building your tests:
- if possible, use the same data all the time (e.g., by loading a payload from a file)
- include the tool (function, script, list of steps, etc.) that was used to generate the file
- allow exceptions to the rule if necessary, e.g. a nonce or timestamp might have to be unique in a particular scenario

A good practice is to generate new data on-demand once, e.g., by running a script that generates all the required data,
and then using the same data in subsequent runs.

## Plaintext vs binary
Prefer to store data in textual form, rather than binary. This makes it easier to visually inspect the data, copy some
chunks for experimentation, sharing with colleagues or logging.

For example, payloads in PKI are often DER-encoded, but you can also use PEM. The difference in storage size can be
neglected, while transforming one into the other is easy and can be automated (e.g., write keywords and functions that
convert automatically to whatever makes sense, and accept either format at the input).


# Supporting materials
- https://docs.robotframework.org/docs/getting_started/ide How to use this with an IDE.