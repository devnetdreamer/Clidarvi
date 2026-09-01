# Third-party notices

Clidarvi is distributed under GPL-3.0-only. The official Clidarvi wheel and source distribution do
not vendor the runtime dependencies below. They are separately installed Python distributions and
retain their own copyrights, license terms, notices, and warranty disclaimers.

## Reviewed CPython 3.13 runtime snapshot

This table covers every distribution in `requirements-lock/runtime-py313.txt` for Clidarvi
0.1.0a1. The SPDX expressions describe the reviewed Python-distribution-level payload. They do not
replace the license files or nested-component notices provided by each upstream project.

| Distribution | Version | Reviewed SPDX expression | Upstream / important bundled material |
| --- | --- | --- | --- |
| bcrypt | 5.0.0 | Apache-2.0 | [PyPI](https://pypi.org/project/bcrypt/5.0.0/) |
| cffi | 2.1.1 | MIT-0 | [PyPI](https://pypi.org/project/cffi/2.1.1/) |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | [PyPI](https://pypi.org/project/cryptography/50.0.1/); wheels use OpenSSL 4.0.2 and can contain separately inventoried native/Rust material |
| defusedxml | 0.7.1 | PSF-2.0 | [PyPI](https://pypi.org/project/defusedxml/0.7.1/) |
| invoke | 3.0.3 | BSD-2-Clause | [PyPI](https://pypi.org/project/invoke/3.0.3/) |
| markdown-it-py | 4.2.0 | MIT | [PyPI](https://pypi.org/project/markdown-it-py/4.2.0/); includes a separate MIT markdown-it notice |
| mdurl | 0.1.2 | MIT | [PyPI](https://pypi.org/project/mdurl/0.1.2/) |
| netmiko | 4.7.0 | MIT AND Python-2.0 | [PyPI](https://pypi.org/project/netmiko/4.7.0/); includes vendored Python `telnetlib` material |
| ntc-templates | 9.2.0 | Apache-2.0 | [PyPI](https://pypi.org/project/ntc-templates/9.2.0/) |
| paramiko | 4.0.0 | LGPL-2.1-or-later | [PyPI](https://pypi.org/project/paramiko/4.0.0/); source headers grant LGPL-2.1-or-later although wheel metadata uses deprecated `LGPL-2.1` syntax |
| pycparser | 3.0 | BSD-3-Clause | [PyPI](https://pypi.org/project/pycparser/3.0/) |
| Pygments | 2.21.0 | BSD-2-Clause | [PyPI](https://pypi.org/project/Pygments/2.21.0/) |
| PyNaCl | 1.6.2 | Apache-2.0 AND ISC | [PyPI](https://pypi.org/project/PyNaCl/1.6.2/); bundled libsodium material is ISC-licensed |
| PyQt6 | 6.11.0 | GPL-3.0-only | [Riverbank](https://riverbankcomputing.com/software/pyqt/) |
| PyQt6-Qt6 | 6.11.2 | LGPL-3.0-only AND GPL-3.0-only | [Qt licensing](https://doc.qt.io/qt-6/licensing.html); the exact wheel labels Qt LGPL v3 but also contains modules that Qt documents as GPL-only, plus separately licensed third-party components |
| PyQt6-sip | 13.12.0 | BSD-2-Clause | [PyPI](https://pypi.org/project/PyQt6-sip/13.12.0/) |
| pyserial | 3.5 | BSD-3-Clause | [PyPI](https://pypi.org/project/pyserial/3.5/) |
| PyYAML | 6.0.3 | MIT | [PyPI](https://pypi.org/project/PyYAML/6.0.3/) |
| rich | 15.0.0 | MIT | [PyPI](https://pypi.org/project/rich/15.0.0/) |
| ruamel.yaml | 0.19.1 | MIT | [PyPI](https://pypi.org/project/ruamel.yaml/0.19.1/) |
| scp | 0.16.1 | LGPL-2.1-or-later | [PyPI](https://pypi.org/project/scp/0.16.1/) |
| textfsm | 2.1.0 | Apache-2.0 | [PyPI](https://pypi.org/project/textfsm/2.1.0/) |

`pyproject.toml` declares compatibility ranges for Clidarvi's four direct dependencies; those
ranges are not the official release snapshot and can resolve differently later. For Clidarvi
0.1.0a1, `requirements-lock/runtime-py313.txt` pins the complete official CPython 3.13 runtime set
to exact versions and allowlists upstream artifact SHA-256 hashes.

`sbom/clidarvi-0.1.0a1.cdx.json` records the same 22 distributions, every reviewed SPDX expression,
and the runtime-lock fingerprint as a CycloneDX SBOM. Its generator fails closed if the lock and the
reviewed license map differ. This is a Python-distribution-level inventory: native libraries,
vendored files, and other nested components remain governed by their upstream license files and
notices. Inspect those materials before deployment or redistribution.

A hash establishes only that bytes match a chosen digest; it does not authenticate who produced or
published that digest. Neither a hash nor an SBOM guarantees origin, security, fitness, absence of
telemetry, or absence of malicious or unexpected behavior. Inspect the exact package metadata,
source, behavior, and license files before deployment or redistribution, especially when creating
a standalone executable or installer.

## Tracked Paramiko advisory

The reviewed GitHub advisory for CVE-2026-44405 / PYSEC-2026-2858 classifies the RSA/SHA-1 issue as
low severity, lists Paramiko versions through 4.0.0 as affected, and lists **no patched release** as
of 2026-08-18. Paramiko's main branch contains commit `a448945`, and the Paramiko 5 changelog
describes removal of RSA/SHA-1 signing/verification, but this document does not relabel either as a
patched release while the advisory says otherwise. Netmiko 4.7.0 declares `paramiko>=3.5.0,<5.0`, so
this alpha remains on Paramiko 4.0.0.

As a scoped runtime mitigation, Clidarvi disables `ssh-rsa`/DSS host-key negotiation, SHA-1 key
exchange, SHA-1/MD5 MAC algorithms, and 3DES/CBC-mode ciphers on every Paramiko and Netmiko
transport. Live CLI also rejects SSH key/default-key and agent authentication. These controls are
designed to keep the affected public-key path out of Clidarvi's shipped connection flows, and tests
exercise those settings. They do not patch Paramiko, prove that every third-party path is
unreachable, or change the dependency's advisory status. CI allows only this named advisory and
must remove the exception as soon as Clidarvi can integrate and test a dependency revision that no
longer contains the affected code. Users whose policy prohibits any dependency with a known
advisory should not deploy this alpha. See
https://github.com/advisories/GHSA-r374-rxx8-8654 and Paramiko's upstream changelog.

## PyQt and Clidarvi licensing

This distribution uses PyQt6 under its GPLv3 option, which is compatible with Clidarvi's
GPL-3.0-only license. A commercial PyQt licence alone gives no right to relicense Clidarvi.
Replacing PyQt or obtaining commercial PyQt rights does not change Clidarvi's copyright terms; a
differently licensed edition would also require permission from every relevant Clidarvi copyright
holder and compatible rights for every dependency.

A future standalone executable or installer would bundle additional libraries and requires a fresh
license-compliance review, complete corresponding source, and all applicable notices and license
materials.

Vendor and product names used in compatibility descriptions belong to their respective owners.
Their mention does not imply affiliation, sponsorship, or endorsement.
