# pystandalone

`pystandalone` is a utility to build opinionated standalone Python executables. This does not aim to be a generic "standalone Python" builder, it merely solves some niche use-cases.

Derived from the amazing `python-build-standalone`, precompiled distributions are provided by [`python-build-pystandalone`](https://github.com/fox-it/python-build-pystandalone). These distributions include some patches to make Python a little bit more "forensically sound", as well as adding some nice utilities:

- Ability to run Python code from memory (embedded inside the executable)
- Don't update file access times
- Fixes for subprocess execution in ESXi environments
- Easy access to OpenSSL/LibreSSL backed cryptographic ciphers.

For more information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/pystandalone/index.html).

## Installation

`pystandalone` is available on [PyPI](https://pypi.org/project/pystandalone/).

```bash
pip install pystandalone
```

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: Apache License 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>). For more information, see the LICENSE file.
