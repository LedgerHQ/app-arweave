# Ragger tests

These tests always use the fixed public test seed in `conftest.py`. Never point
them at a physical Ledger that holds funds.

Build the API-level-26 firmware and run it through Speculos with the current
Ledger development images:

```sh
make current_ragger
```

Test builds preload a disposable RSA key so Speculos does not spend several
minutes generating one during every run. Production builds do not include that
fixture and continue to derive the key from the device seed.

## Physical Nano S Plus

Use only a dedicated development device initialized with a test seed. Build and
load the production app, close Ledger Wallet and any browser WebHID session,
then leave the initialized Permaweb app open.

```sh
python3 -m venv /tmp/app-arweave-ledgerblue
/tmp/app-arweave-ledgerblue/bin/pip install -r tests_ragger/requirements-physical.txt
/tmp/app-arweave-ledgerblue/bin/python tests_ragger/physical_ans104.py
```

Review and approve the test data item on the device. The script retrieves the
signature, verifies it against the device owner, and does not broadcast data.
