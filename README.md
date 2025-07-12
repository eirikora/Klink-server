# Klink Server (Knowledge-link)

Dette er en enkel Flask-basert backend for **Klink (Knowledge-link)** – et klient-server-system hvor brukere kan lagre, hente, oppdatere og slette dokumenter i et arkiv. Systemet bruker SQLite som database og baserer seg på autentisering gjennom header-baserte arkivnavn og passord.

## Funksjonalitet

- Opprette nye arkiv
- Lagring og oppdatering av dokumenter
- Hente dokumenter og relasjoner
- Liste ut dokumenter i et arkiv
- Slette dokumenter

## Komme i gang

Prosjektet bruker [uv](https://github.com/astral-sh/uv) som Python package manager.

### Forutsetninger

- Python 3.10 eller nyere
- `uv` installert:  
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

### Klone prosjektet og sette opp miljø

```bash
git clone https://github.com/eirikora/Klink-server
cd Klink-server
uv venv
source .venv/bin/activate  # eller .venv\Scripts\activate på Windows
uv pip install -r requirements.txt
```

### Starte lokal server

```bash
uv run main.py
```

Dette starter en ny server på `http://localhost:54827`.

### Bruke API-et

Alle kall krever to headers:
- `Archive`: navnet på arkivet
- `Password`: passord for arkivet

Eksempel med `curl` for å opprette et arkiv:

```bash
curl -X POST http://localhost:54827/create_archive \
  -H "Archive: testarkiv" \
  -H "Password: hemmelig"
```

## API-dokumentasjon

OpenAPI-spesifikasjonen finnes i filen [klink_api.yaml](./klink_api.yaml). Du kan åpne den i Swagger Editor på [https://editor.swagger.io](https://editor.swagger.io) for en interaktiv dokumentasjon.

---

© 2025 Klink Project – Eirik Øra