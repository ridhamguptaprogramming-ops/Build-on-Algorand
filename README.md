# DAO Voting System

A simple DAO voting project with:

- Python backend logic (`dao_voting.py`)
- Browser demo UI (`index.html`)
- Unit tests (`test_dao_voting.py`)

It supports proposal creation, YES/NO voting, wallet-signature style identity checks, one-vote-per-member, deadlines, transparent vote records, and JSON import/export.

## Features

### Core

- Create proposals with title, description, deadline
- Vote YES/NO on proposals
- One member can vote only once per proposal
- Voting closes automatically after deadline
- Clear results (YES, NO, weighted totals)

### Access and Security

- Only registered members can vote
- Wallet-style signature verification (simulated)
- Immutable-style hash-linked vote ledger
- Vote integrity verification

### Transparency

- Public vote records per proposal
- Ledger blocks and hashes visible in UI

### Advanced

- Token-weighted voting (optional)
- Proposal comments
- Notifications
- Admin dashboard

## Project Structure

- `dao_voting.py`: Main Python DAO system and CLI import/export
- `test_dao_voting.py`: Unit tests
- `index.html`: Single-file interactive web demo (HTML/CSS/JS)
- `dao_state.json`: Example exported state (if present)

## Requirements

- Python 3.9+
- Any modern browser (Chrome, Safari, Edge, Firefox)

## Run Python Demo

```bash
PYTHONPYCACHEPREFIX=/tmp/pycache python3 dao_voting.py
```

If your machine does not need the pycache workaround, this also works:

```bash
python3 dao_voting.py
```

## Run Tests

```bash
PYTHONPYCACHEPREFIX=/tmp/pycache python3 -m unittest -v
```

## Python Import/Export JSON

Export current DAO state:

```bash
PYTHONPYCACHEPREFIX=/tmp/pycache python3 dao_voting.py --export-json dao_state.json
```

Import DAO state from JSON:

```bash
PYTHONPYCACHEPREFIX=/tmp/pycache python3 dao_voting.py --import-json dao_state.json
```

## Run HTML Demo

Open directly:

```bash
open index.html
```

Or serve locally:

```bash
python3 -m http.server 8000
```

Then open:

`http://localhost:8000/index.html`

## HTML Import/Export

In the web UI (Transparency and Admin panel):

- `Export DAO JSON` downloads state
- `Import DAO JSON` loads state

The HTML loader accepts both:

- HTML-style keys (`privateKey`, `proposalCounter`, etc.)
- Python-style keys (`private_key`, `proposal_counter`, `proposal_id`, etc.)

## Notes

- Wallet and signature logic here is simulated for educational/demo use.
- For production, replace with real wallet integration (MetaMask/Pera/Web3 signing).
