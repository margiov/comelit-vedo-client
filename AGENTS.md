# AGENTS.md

Istruzioni per agenti AI e contributori che lavorano su questo repository.

## Progetto

`vedo-client` è un client Python, **solo libreria standard**, per il protocollo
nativo delle centrali d'allarme Comelit VEDO (TCP 10012 in chiaro / 10022 TLS).
Tutto il codice è in `vedo_client.py` (file singolo). Vedi `README.md` per l'uso e
per la descrizione del protocollo.

## Eseguire e verificare

- Richiede Python 3.8+ senza dipendenze esterne.
- `python3 vedo_client.py --help` elenca i comandi.
- Controllo di sintassi: `python3 -c "import ast; ast.parse(open('vedo_client.py').read())"`.
- Non c'è ancora una suite di test automatici: le modifiche al protocollo vanno
  verificate contro una centrale reale, **partendo sempre dai comandi di sola lettura**
  (`--probe`, `--names`, `--status`, `--areas`, `--log`, `--monitor`).

## Sicurezza (importante)

- Il client opera su un **impianto d'allarme reale**. I comandi di scrittura
  (`--arm`, `--disarm`) richiedono il flag `--yes` e aprono una sessione che la
  centrale registra nel log eventi: non invocarli in test automatici o esempi eseguibili.
- **Non committare mai** dati di un impianto: file `vedo.json`, catture `*.pcap`,
  log della centrale, note di reverse engineering o certificati. Sono già coperti da
  `.gitignore`; verificarlo prima di ogni commit.
- Non inserire nel codice o nei file pubblici indirizzi IP, credenziali (`unit_id`),
  nomi di aree/zone o altri dati di installazioni reali: il repository deve restare generico.

## Convenzioni

- Codice e commenti in **italiano**, coerenti con lo stile esistente; nessuna
  dipendenza oltre la libreria standard.
- Messaggi di commit in italiano, brevi e descrittivi.
- Esegui i commit con l'identità `margiov <margiov@users.noreply.github.com>` e con
  **nessun'altra** identità o email.
- **Non** aggiungere righe di co-autore (es. `Co-Authored-By:`) di assistenti AI ai
  commit o alle pull request.

## Licenza

MIT (vedi `LICENSE`). I contributi si intendono rilasciati con la stessa licenza.
