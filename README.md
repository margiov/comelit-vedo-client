# vedo-client

Client Python, senza dipendenze esterne, per il **protocollo nativo delle centrali
d'allarme Comelit VEDO**. Parla con il modulo IP della centrale in rete locale, sulle
stesse porte usate dall'app ufficiale.

> **Progetto non ufficiale.** Non è affiliato, approvato o supportato da Comelit Group
> S.p.A. Il protocollo è stato ricostruito tramite reverse engineering a scopo di
> interoperabilità. "Comelit" e "VEDO" sono marchi dei rispettivi proprietari.
>
> **Opera su un impianto d'allarme reale.** Un uso sbagliato può inserire o disinserire
> l'impianto, o far scattare la sirena. Usalo a tuo rischio.

## Cosa fa

| Funzione | Opzione | Tipo |
|---|---|---|
| Verifica la connessione (handshake) | `--probe` | lettura |
| Nomi di aree e zone letti dalla centrale | `--names` | lettura |
| Istantanea dello stato delle zone | `--status` | lettura |
| Istantanea dello stato delle aree | `--areas` | lettura |
| Monitor continuo dello stato di zone (e aree) | `--monitor SEC` `[--with-areas]` | lettura |
| Ultimi N eventi del log della centrale | `--log N` | lettura |
| Inserimento totale di **una** area | `--arm AREA --yes` | **scrittura** |
| Disinserimento di **una** area | `--disarm AREA --yes` | **scrittura** |

Il comando di inserimento/disinserimento usato dal client contiene un **vettore
esplicito con un valore per ogni area** della centrale: "inserisci", "disinserisci"
oppure "non toccare". Le aree che non indichi restano esplicitamente invariate. Altri
canali di controllo (per esempio l'interfaccia web del modulo IP) indicano invece una
sola area e lasciano alla centrale il resto.

Nomi e numero di aree e zone **non vanno configurati**: il client li legge ogni volta
dalla centrale.

## Requisiti

- Python 3.8 o superiore (solo libreria standard).
- Una centrale Comelit VEDO con modulo IP raggiungibile in rete locale:
  - porta **10012**: protocollo in chiaro;
  - porta **10022**: stesso protocollo dentro TLS 1.2, con certificato self-signed.
- La credenziale `unit_id` della tua installazione (vedi [Ottenere `unit_id`](#ottenere-unit_id)).

Compatibilità: sviluppato e provato su una sola installazione, una centrale
**Comelit VEDO 34** con modulo IP, usando l'app Comelit per Android 7.5.0. Altri modelli o firmware potrebbero comportarsi diversamente.
Inizia sempre con i comandi di sola lettura.

## Installazione

```sh
git clone <url-del-repository> vedo-client
cd vedo-client
python3 vedo_client.py --help
```

Il client è un unico file, `vedo_client.py`. Non c'è nulla da installare.

## Configurazione: `vedo.json`

I parametri di connessione stanno in un file JSON, mai nel codice. Il client cerca il
file in quest'ordine:

1. il percorso passato con `--config PATH`;
2. `./vedo.json`, nella directory corrente;
3. `~/.config/vedo/vedo.json`.

Per creare un modello:

```sh
python3 vedo_client.py --init-config vedo.json
```

Esempio minimo:

```json
{
  "host": "192.168.1.50",
  "port": 10022,
  "unit_id": "a1b2c3"
}
```

| Campo | Obbligatorio | Descrizione |
|---|---|---|
| `host` | sì | Indirizzo IP o nome del modulo IP della centrale. |
| `port` | no | `10012` (in chiaro, default) oppure `10022` (TLS). |
| `tls` | no | `true`/`false`. Se manca, è attivo quando la porta è 10022. |
| `tls_cafile` | no | File PEM del certificato della centrale. Se indicato, il certificato viene verificato (pinning). Se manca, la connessione TLS è cifrata ma il certificato **non** viene verificato. |
| `unit_id` | solo per `--arm`/`--disarm` | Credenziale di 3 byte, in esadecimale, che apre la sessione dei comandi. Le operazioni di lettura non la richiedono. |

I campi che iniziano con `_` (per esempio `_commento_tls`) sono commenti e vengono
ignorati. Le opzioni `--host`, `--port`, `--unit-id`, `--tls` e `--no-tls` sulla riga di
comando hanno la precedenza sul file.

### Ottenere `unit_id`

La centrale non comunica mai `unit_id`: lo invia solo l'app ufficiale, quando apre la
sessione per i comandi. Puoi ricavarlo da una cattura del traffico dell'app:

1. Su Android installa [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) e avvia una
   cattura in formato PCAP, limitata all'app Comelit.
2. Nell'app collegati alla centrale **in rete locale** ed esegui un'azione su un'area
   (inserimento e subito dopo disinserimento). È il momento in cui l'app apre la
   sessione dei comandi.
3. Ferma la cattura e copia il file `.pcap` sul PC.
4. Estrai il valore con `tshark` e con le funzioni del client:

```sh
tshark -r cattura.pcap -Y 'tcp.dstport==10012 && tcp.len>0' -T fields -e tcp.payload > payloads.txt
python3 - <<'EOF'
import re
from vedo_client import parse_frame
data = b"".join(bytes.fromhex(l.strip().replace(":", "")) for l in open("payloads.txt") if l.strip())
for raw in re.findall(rb"\xf1([^\xf1\xf2]*)\xf2", data):
    f = parse_frame(raw)
    p = f["payload"]
    if f["crc_ok"] and f["msgtype"] == 0x4002 and f["session"] != b"\0\0" and len(p) == 6:
        print("unit_id =", p[1:4].hex())
EOF
```

Lancia lo snippet dalla directory che contiene `vedo_client.py`. Se non stampa nulla,
l'app ha probabilmente usato la porta TLS 10022, che non si può leggere da una cattura.
Ripeti la cattura con il telefono collegato alla stessa rete Wi-Fi della centrale.

Con un valore sbagliato la centrale rifiuta l'apertura della sessione (esito `0801`) e
il client lo segnala.

## Uso

```sh
# connessione e handshake
python3 vedo_client.py --probe

# nomi di aree e zone (indici 0-based)
python3 vedo_client.py --names

# stato delle zone, una volta sola
python3 vedo_client.py --status

# stato delle aree (inserita / disinserita), una volta sola
python3 vedo_client.py --areas

# monitor per 2 minuti, interrogando la centrale ogni 0,5 s
# (--with-areas segue anche lo stato delle aree)
python3 vedo_client.py --monitor 120 --interval 0.5 --with-areas

# ultimi 20 eventi
python3 vedo_client.py --log 20

# inserisce / disinserisce UNA area
python3 vedo_client.py --arm "Area 2" --yes
python3 vedo_client.py --disarm 1 --yes
```

Esempio di output di `--monitor --with-areas`:

```text
[*] monitor stato zone e aree per 120s (interrogazione ogni 0.5s)...
  stato iniziale aree:
    Area 1: disinserita
    Area 2: disinserita
  stato iniziale zone:
    Ingresso: riposo
    Finestra cucina: riposo
  18:02:11  zona Ingresso: riposo -> OPEN|READY
  18:02:14  zona Ingresso: OPEN|READY -> riposo
  18:03:02  AREA Area 2: disinserita -> inserita
```

### Scegliere l'area

`--arm` e `--disarm` accettano:

- il **nome** dell'area come lo restituisce `--names`, senza distinzione tra maiuscole
  e minuscole;
- l'**inizio del nome**, se identifica una sola area (per esempio `gar` per "Garage");
- l'**indice** numerico 0-based.

Se il nome è ambiguo, sconosciuto o fuori range, il client si ferma con un errore e
**non invia nulla**. Lo stesso accade se non riesce a leggere le aree dalla centrale.

### Stato delle aree

`--areas` (e `--monitor --with-areas`) mostra per ogni area presente se è
`disinserita` o `inserita`. Un'area con una zona aperta è segnalata come
`non pronta`. Lo stato "in allarme" non è ancora decodificato: per quello usa il
log eventi (`--log`).

### Stati delle zone

`--status` e `--monitor` mostrano i flag attivi di ogni zona presente. "riposo" indica
nessun flag attivo.

| Flag | Significato |
|---|---|
| `OPEN` | zona aperta / in rilevamento |
| `ALARM` | zona in allarme |
| `FAULTY` | guasto |
| `SABOTAGED` | manomissione |
| `READY` | pronta |
| `ACTIVE` | attiva (area inserita) |
| `CHIME` | campanello |
| `EXCLUDED` | esclusa |
| `ISOLATED` | isolata |
| `MASKED` | mascherata |
| `LOW_BATT` | batteria scarica (radio) |
| `SUPERV` | supervisione |

Le zone non presenti nella configurazione della centrale non vengono mostrate.

## Sicurezza

- **`unit_id` è una credenziale.** Chi la conosce e raggiunge la centrale in rete può
  inserire e disinserire le aree. Tieni `vedo.json` privato (`chmod 600 vedo.json`) e
  **non pubblicarlo mai**: è già escluso da `.gitignore`, controllalo prima di ogni
  commit.
- Anche le catture `.pcap` contengono credenziali e token: non condividerle.
- TLS (porta 10022) cifra il traffico, ma non aggiunge autenticazione. Preferiscilo
  comunque al canale in chiaro e, se puoi, usa `tls_cafile` per verificare il
  certificato.
- Le azioni richiedono sempre `--yes`. Senza `--yes` il client non apre nemmeno la
  sessione dei comandi.
- Ogni apertura riuscita della sessione dei comandi viene registrata nel log eventi
  della centrale ("Utente Loggato").

## Limiti noti

- È supportato solo l'inserimento **totale** di un'area. L'inserimento parziale
  (P1/P2/P12) non è implementato.
- Esclusione e isolamento delle zone e comando delle uscite non sono implementati.
- `--status`, `--monitor` e `--names` coprono le prime 30 posizioni zona della centrale.
  Le zone configurate in posizioni successive non vengono ancora mostrate.
- La centrale non invia aggiornamenti spontanei. `--monitor` la interroga a intervalli
  regolari: con `--interval` scegli il compromesso tra reattività e traffico.
- Il protocollo può cambiare con aggiornamenti del firmware della centrale o dell'app.

## Il protocollo in breve

Riassunto tecnico per chi vuole estendere il client.

**Trasporto e framing**
- TCP 10012 in chiaro, oppure TCP 10022 con TLS 1.2. Il contenuto è identico.
- Ogni frame è `F1 <body escaped> F2`. I byte da `0xF0` a `0xFF` nel body vengono
  trasmessi come `F0, byte ^ 0xF0`.
- Body: `36 0C` (magic), sessione (2 byte), sequenza (1 byte), tipo di messaggio
  (2 byte), payload, checksum.
- Il checksum è un **CRC-16/CCITT-FALSE** (poly `0x1021`, init `0xFFFF`) calcolato sul
  body, in big-endian.

**Sessioni**
1. `0x4002` con sessione `0000` assegna la sessione di controllo, poi segue `0x4005`.
   Questa sessione basta per tutte le letture.
2. Per i comandi, `0x4002` sulla sessione di controllo con payload
   `00 <unit_id> 00 01` apre una *device session*.

**Messaggi**

| Tipo | Uso |
|---|---|
| `0x400a` | Lettura configurazione. Richiesta `<gruppo> <indice iniziale> <parametro> 6004 <quantità> 000000`. I nomi sono record da 16 byte completati con NUL. Gruppi: `0x0001` aree, `0x0004` tastiere, `0x0010` zone (l'indice 0 è il tamper di sistema), `0x001a` uscite, `0x0025` espansioni radio. |
| `0x4012` | Stato e log, sempre a domanda e risposta. Stato aree (frame `6029`, 4 byte per area: byte 0 = `00` assente / `01` disinserita / `02` inserita; byte 1 = flag, `01` non pronta), pagine di stato zone (frame `60fd`, 8 byte per zona con una bitmask di flag), record del log eventi. |
| `0x4013` | Azione sulle aree, sulla device session. Payload `00 02 02 01 <n aree, 2 byte> <vettore>` con 1 byte per area: `00` non toccare, `01` inserisci, `05` disinserisci. Esito nei primi 2 byte della risposta: `0000` significa accettato. |

## Contribuire

Segnalazioni e pull request sono benvenute, soprattutto prove su altri modelli o
firmware. Non allegare mai catture, log o file di configurazione non anonimizzati.

## Licenza

[MIT](LICENSE) © 2026 Gianni Marzulli.
