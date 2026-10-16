#!/usr/bin/env python3
"""Client per il protocollo nativo delle centrali Comelit VEDO (TCP 10012 / TLS 10022).

Protocollo ricostruito via reverse engineering (vedi README.md). Permette di:
  - armare/disarmare SINGOLE aree con un vettore esplicito per area, che non
    tocca le aree non indicate;
  - leggere nomi di aree e zone dalla centrale;
  - leggere il log eventi;
  - monitorare lo stato delle zone.

ATTENZIONE: opera su un impianto d'allarme reale. Le azioni di arma/disarma
richiedono il flag --yes.

Configurazione: i parametri di connessione (host, porta, unit_id) stanno in un
file JSON, NON nel codice. Vedi vedo.example.json e l'opzione --init-config.
Cerca il config in: --config PATH, ./vedo.json, ~/.config/vedo/vedo.json.

Esempi:
  python3 vedo_client.py --probe
  python3 vedo_client.py --names
  python3 vedo_client.py --status
  python3 vedo_client.py --log 20
  python3 vedo_client.py --monitor 60
  python3 vedo_client.py --arm "Area 2" --yes     # nome area letto dalla centrale
  python3 vedo_client.py --disarm 1 --yes         # oppure indice (0-based)
"""
import socket, ssl, struct, sys, os, json, argparse, time, datetime

# ---------------------------------------------------------------- protocollo ---
MAGIC = b"\x36\x0c"

# codici azione per area (nel vettore del comando 0x4013)
ACT_NONE, ACT_ARM, ACT_DISARM = 0x00, 0x01, 0x05  # 0=non toccare 1=arma(TOT) 5=disarma

# bitmask stato zona (enum RtSpecZoneStatus dell'APK)
ZSTATUS = [(1, "OPEN"), (2, "ALARM"), (4, "FAULTY"), (8, "SABOTAGED"),
           (16, "READY"), (32, "ACTIVE"), (64, "CHIME"), (128, "EXCLUDED"),
           (256, "ISOLATED"), (512, "NOT_PRESENT"), (2048, "MASKED"),
           (4096, "LOW_BATT"), (8192, "SUPERV")]


def crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, xorout 0)."""
    c = 0xFFFF
    for b in data:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def escape(data: bytes) -> bytes:
    """Ogni byte 0xF0-0xFF -> 0xF0, (byte ^ 0xF0)."""
    o = bytearray()
    for b in data:
        if b >= 0xF0:
            o += bytes([0xF0, b ^ 0xF0])
        else:
            o.append(b)
    return bytes(o)


def unescape(data: bytes) -> bytes:
    o = bytearray(); esc = False
    for b in data:
        if esc:
            o.append(b ^ 0xF0); esc = False
        elif b == 0xF0:
            esc = True
        else:
            o.append(b)
    return bytes(o)


def build_frame(session: bytes, seq: int, msgtype: int, payload: bytes) -> bytes:
    """frame = F1 + escape(body + crc_be) + F2."""
    body = MAGIC + session + bytes([seq & 0xFF]) + struct.pack(">H", msgtype) + payload
    body += struct.pack(">H", crc16(body))
    return b"\xF1" + escape(body) + b"\xF2"


def parse_frame(raw_inner: bytes) -> dict:
    u = unescape(raw_inner)
    if len(u) < 9:
        return dict(session=b"", seq=-1, msgtype=-1, payload=b"", crc_ok=False, raw=u)
    body, trailer = u[:-2], u[-2:]
    return dict(session=body[2:4], seq=body[4],
                msgtype=struct.unpack(">H", body[5:7])[0],
                payload=body[7:], crc_ok=crc16(body) == struct.unpack(">H", trailer)[0])


class VedoError(Exception):
    pass


class Vedo:
    """Connessione a una centrale VEDO via protocollo nativo 10012."""

    def __init__(self, host, port=10012, unit_id="", timeout=5.0, verbose=False,
                 tls=None, tls_cafile=None):
        self.host, self.port, self.timeout, self.verbose = host, port, timeout, verbose
        # TLS: esplicito, oppure inferito dalla porta (10022 = variante cifrata)
        self.tls = (port == 10022) if tls is None else tls
        self.tls_cafile = tls_cafile
        self.unit_id = bytes.fromhex(unit_id) if unit_id else b""
        self.sock = None
        self.seq = 0xA0
        self.buf = bytearray()

    # --- contesto ---------------------------------------------------------
    def __enter__(self):
        self.connect(); return self

    def __exit__(self, *exc):
        self.close()

    def _log(self, *a):
        if self.verbose:
            print(*a)

    # --- I/O di basso livello --------------------------------------------
    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if self.tls:
            if self.tls_cafile:                      # verifica col certificato fornito
                ctx = ssl.create_default_context(cafile=self.tls_cafile)
                ctx.check_hostname = False
            else:                                    # cert self-signed Comelit: non verificato
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                self._log("  [TLS] certificato NON verificato (self-signed)")
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
            self._log(f"  [TLS] {sock.version()} {sock.cipher()[0]}")
        self.sock = sock

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _next_seq(self):
        self.seq = (self.seq + 1) & 0xFF
        return self.seq

    def send(self, session, msgtype, payload=b""):
        fr = build_frame(session, self._next_seq(), msgtype, payload)
        self._log(f"  TX mt={msgtype:#06x} pl={payload.hex()}")
        self.sock.sendall(fr)

    def recv_frame(self):
        """Estrae il prossimo frame F1..F2 dallo stream (blocca fino a timeout)."""
        while True:
            start = self.buf.find(0xF1)
            if start >= 0:
                end = self.buf.find(0xF2, start + 1)
                if end >= 0:
                    inner = bytes(self.buf[start + 1:end])
                    del self.buf[:end + 1]
                    fr = parse_frame(inner)
                    self._log(f"  RX mt={fr['msgtype']:#06x} sess={fr['session'].hex()} "
                              f"pl={fr['payload'].hex()} crc_ok={fr['crc_ok']}")
                    return fr
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connessione chiusa dalla centrale")
            self.buf += chunk

    def recv_matching(self, msgtype, pfx, tries=400):
        """Prossimo frame di dato tipo il cui payload inizia con pfx
        (scarta lo stream di stato non pertinente)."""
        for _ in range(tries):
            fr = self.recv_frame()
            if fr["msgtype"] == msgtype and fr["payload"].startswith(pfx):
                return fr
        raise TimeoutError("risposta attesa non ricevuta")

    # --- sessione ---------------------------------------------------------
    def handshake(self):
        """4002(0000)->sessione assegnata; 4005. Ritorna la sessione di controllo."""
        self.send(b"\x00\x00", 0x4002, bytes.fromhex("000000000000"))
        r = self.recv_frame()
        if not r["crc_ok"] or len(r["payload"]) < 4:
            raise VedoError("handshake fallito (risposta inattesa)")
        session = r["payload"][2:4]
        self._log(f"  sessione di controllo = {session.hex()}")
        self.send(session, 0x4005, b"\x00\x00")
        self.recv_frame()
        return session

    def open_device_session(self, ctrl_session):
        """4002 con l'id unita' VEDO -> device session per i comandi area."""
        if not self.unit_id:
            raise VedoError("unit_id non configurato (richiesto per le azioni)")
        self.send(ctrl_session, 0x4002, b"\x00" + self.unit_id + b"\x00\x01")
        r = self.recv_frame()
        if not r["crc_ok"] or len(r["payload"]) < 4:
            raise VedoError("apertura device session fallita")
        dev = r["payload"][2:4]
        if r["payload"][0] != 0 or dev == b"\x00\x00":   # es. esito 0801 = rifiutata
            raise VedoError(f"device session rifiutata (esito {r['payload'][:2].hex()}): "
                            "unit_id errato?")
        self._log(f"  device session = {dev.hex()}")
        return dev

    # --- azioni (scrittura) ----------------------------------------------
    def area_action(self, dev_session, vector, confirm=False):
        """Comando 0x4013: vettore con un byte di azione per area."""
        if not confirm:
            raise PermissionError("azione sull'allarme non confermata (manca --yes)")
        vector = bytes(vector)
        payload = bytes.fromhex("00020201") + struct.pack(">H", len(vector)) + vector
        self.send(dev_session, 0x4013, payload)
        return self.recv_frame()

    # --- letture ----------------------------------------------------------
    def read_log(self, session, n=20):
        """Ultimi n eventi dal log (sola lettura)."""
        LOGPFX = bytes.fromhex("000600000006c0ff")
        out = []
        self.send(session, 0x4012, bytes.fromhex("000600000006c00600050000000001"))
        try:
            fr = self.recv_matching(0x4012, LOGPFX)
        except TimeoutError:
            return out
        for _ in range(n):
            pl = fr["payload"]
            rid = pl[9]
            rec = pl[12:]
            ts = int.from_bytes(rec[2:6], "little")
            ln = rec[6]
            text = rec[8:8 + ln].decode("latin-1", "replace")
            when = datetime.datetime.fromtimestamp(ts).strftime("%d-%m-%Y %H:%M:%S")
            out.append((rid, when, text))
            self.send(session, 0x4012,
                      bytes.fromhex("000600000006c0060005") + bytes([rid]) + bytes.fromhex("0001ff01"))
            try:
                nfr = self.recv_matching(0x4012, LOGPFX)
            except TimeoutError:
                break
            if nfr["payload"][9] == rid:   # id invariato -> fine log
                break
            fr = nfr
        return out

    # gruppi di configurazione (msg 0x400a) che contengono descrizioni da 16 byte
    CFG_AREAS, CFG_ZONES, CFG_KEYPADS, CFG_OUTPUTS, CFG_RADIO_EXP = 0x0001, 0x0010, 0x0004, 0x001a, 0x0025
    CFG_PARAM_NAME = 0x0000
    CFG_CHUNK = 8          # elementi per richiesta (provato fino a 8)

    def read_config(self, session, group, start, count, param=CFG_PARAM_NAME):
        """Legge `count` record del parametro `param` del gruppo config `group`,
        a partire dall'indice `start`. Ritorna la lista dei record (bytes)."""
        req = struct.pack(">HHHHH", group, start, param, 0x6004, count) + b"\x00\x00\x00"
        self.send(session, 0x400a, req)
        pl = self.recv_matching(0x400a, req[:6])["payload"]
        # risposta: <grp><start><param> 60LL <count2> <recsz2> <maschera recsz B> <len2> <dati>
        n, recsz = struct.unpack(">HH", pl[8:12])
        off = 12 + recsz
        dlen = struct.unpack(">H", pl[off:off + 2])[0]
        data = pl[off + 2:off + 2 + dlen]
        return [data[i * recsz:(i + 1) * recsz] for i in range(min(n, dlen // max(recsz, 1)))]

    def read_names(self, session, group, start, count):
        """Descrizioni testuali (16 byte, NUL-padded) di `count` elementi del gruppo."""
        out = []
        for s in range(start, start + count, self.CFG_CHUNK):
            n = min(self.CFG_CHUNK, start + count - s)
            out += [r.split(b"\x00")[0].decode("latin-1").strip()
                    for r in self.read_config(session, group, s, n)]
        return out

    AREAS_STATUS_PFX = bytes.fromhex("000100000000")

    def read_num_areas(self, session):
        """Numero di aree della centrale. Alla richiesta di stato aree (0x4012,
        gruppo 0x0001) la centrale risponde sempre con il numero reale di aree,
        qualunque sia il count richiesto (provato 8, 32, 255 -> 8)."""
        self.send(session, 0x4012, self.AREAS_STATUS_PFX + bytes.fromhex("60040020000000"))
        pl = self.recv_matching(0x4012, self.AREAS_STATUS_PFX)["payload"]
        return struct.unpack(">H", pl[8:10])[0]

    def read_area_names(self, session, num_areas=None):
        """Nomi delle aree, per indice area (0-based, come nel vettore 0x4013)."""
        if num_areas is None:
            num_areas = self.read_num_areas(session)
        return self.read_names(session, self.CFG_AREAS, 0, num_areas)

    def read_zone_names(self, session, num_zones):
        """Nomi zona indicizzati come nello stream di stato: nel gruppo config
        l'indice 0 e' il tamper di sistema, quindi la zona z e' il record z+1."""
        return self.read_names(session, self.CFG_ZONES, 1, num_zones)

    # richieste di sottoscrizione dello stream realtime (osservate dall'app)
    SUBS = [
        "00010000000060040008000000",   # stato aree
        "0002000000006004008b000000",   # blocco zone
        "0000000000026004003d000000",   # pagine stato zone live (frame 60fd)
        "0000003d00026004003d000000",
        "0000007a00026004003d000000",
        "000000b700026004003d000000",
        "000000f400026004003d000000",
    ]
    ZONE_FRAME_PFX = bytes.fromhex("00000000000260fd")
    STATUS_ZONES = 30      # zone coperte dalla prima pagina di stato (frame 60fd)

    def _decode_zones(self, payload, names=None):
        """Frame ZONES_STATUS_SPEC: record 8 byte/zona, u16 specmask (RtSpecZoneStatus).
        Ritorna {etichetta: [flag...]} escludendo le zone non presenti."""
        body = payload[20:]
        out = {}
        for z in range(len(body) // 8):
            spec = int.from_bytes(body[8 * z + 6:8 * z + 8], "little")
            if spec & 512:                 # NOT_PRESENT
                continue
            label = names[z] if names and z < len(names) and names[z] else f"Zona {z}"
            out[label] = [n for bit, n in ZSTATUS if spec & bit]
        return out

    def read_status_once(self, session, names=None, wait=4.0):
        """Legge un singolo snapshot dello stato zone."""
        for s in self.SUBS:
            self.send(session, 0x4012, bytes.fromhex(s))
        self.sock.settimeout(wait)
        try:
            fr = self.recv_matching(0x4012, self.ZONE_FRAME_PFX)
        except (TimeoutError, socket.timeout):
            return None
        return self._decode_zones(fr["payload"], names)

    ZONE_PAGE_REQ = bytes.fromhex("0000000000026004003d000000")   # prima pagina stato zone

    def monitor(self, session, seconds=30, names=None, on_change=None, interval=1.0):
        """Monitora lo stato zone per N secondi, chiamando on_change(zona, prima, dopo).
        La centrale non invia aggiornamenti spontanei: risponde solo alle richieste,
        quindi la pagina di stato zone viene richiesta ogni `interval` secondi
        (l'app lo fa ogni ~4.5 s quando e' aperta la schermata zone)."""
        for s in self.SUBS:
            self.send(session, 0x4012, bytes.fromhex(s))
        t0 = time.time()
        next_poll = t0 + interval
        state = None
        while time.time() - t0 < seconds:
            now = time.time()
            if now >= next_poll:
                self.send(session, 0x4012, self.ZONE_PAGE_REQ)
                next_poll = now + interval
            self.sock.settimeout(max(0.05, next_poll - time.time()))
            try:
                fr = self.recv_frame()
            except socket.timeout:
                continue
            if fr["msgtype"] == 0x4012 and fr["payload"].startswith(self.ZONE_FRAME_PFX):
                z = self._decode_zones(fr["payload"], names)
                if state is None:
                    state = z
                    if on_change:
                        on_change(None, None, z)   # snapshot iniziale
                else:
                    for k, v in z.items():
                        if state.get(k) != v and on_change:
                            on_change(k, state.get(k), v)
                    state = z


# ------------------------------------------------------------------- config ---
CONFIG_PATHS = ["vedo.json", os.path.expanduser("~/.config/vedo/vedo.json")]

EXAMPLE_CONFIG = {
    "host": "192.168.1.50",
    "port": 10012,
    "_commento_tls": "true per cifrare (porta 10022); se omesso, inferito dalla porta",
    "tls": False,
    "tls_cafile": "",
    "unit_id": "000000",
    "_commento_aree": "i nomi delle aree si leggono dalla centrale (vedi --names)",
}


def load_config(path=None):
    for p in ([path] if path else []) + CONFIG_PATHS:
        if p and os.path.isfile(p):
            with open(p) as f:
                return json.load(f), p
    return None, None


# --------------------------------------------------------------------- main ---
def main():
    ap = argparse.ArgumentParser(description="Client protocollo nativo Comelit VEDO")
    ap.add_argument("--config", help="percorso del file di configurazione JSON")
    ap.add_argument("--init-config", metavar="PATH", help="scrive un config di esempio e esce")
    ap.add_argument("--host"); ap.add_argument("--port", type=int)
    ap.add_argument("--unit-id", help="credenziale device session (hex, 3 byte), sovrascrive il config")
    ap.add_argument("--tls", dest="tls", action="store_true", default=None, help="forza TLS")
    ap.add_argument("--no-tls", dest="tls", action="store_false", help="forza no-TLS")
    ap.add_argument("--probe", action="store_true", help="solo handshake (lettura)")
    ap.add_argument("--status", action="store_true", help="snapshot stato zone (lettura)")
    ap.add_argument("--names", action="store_true",
                    help="nomi di aree e zone letti dalla centrale (lettura)")
    ap.add_argument("--log", type=int, metavar="N", help="ultimi N eventi (lettura)")
    ap.add_argument("--monitor", type=int, metavar="SEC", help="monitor stato zone (lettura)")
    ap.add_argument("--interval", type=float, default=1.0, metavar="SEC",
                    help="intervallo di interrogazione per --monitor (default 1s)")
    ap.add_argument("--arm", metavar="AREA", help="arma l'area (nome dalla centrale, anche solo l'inizio, o indice)")
    ap.add_argument("--disarm", metavar="AREA", help="disarma l'area (nome dalla centrale, anche solo l'inizio, o indice)")
    ap.add_argument("--yes", action="store_true", help="autorizza l'azione sull'allarme")
    ap.add_argument("-v", "--verbose", action="store_true", help="output di debug del protocollo")
    args = ap.parse_args()

    if args.init_config:
        with open(args.init_config, "w") as f:
            json.dump(EXAMPLE_CONFIG, f, indent=2, ensure_ascii=False)
        print(f"[+] config di esempio scritto in {args.init_config}")
        return

    cfg, cfg_path = load_config(args.config)
    cfg = cfg or {}
    host = args.host or cfg.get("host")
    port = args.port or cfg.get("port", 10012)
    unit_id = args.unit_id or cfg.get("unit_id", "")
    tls = args.tls if args.tls is not None else cfg.get("tls")
    tls_cafile = cfg.get("tls_cafile") or None

    if not host:
        sys.exit("Errore: host non specificato (usa --host o un file di config; "
                 "crea un esempio con --init-config vedo.json)")

    def resolve_area(name, panel_areas):
        """Indice area dal nome letto dalla centrale (senza maiuscole/minuscole;
        basta l'inizio del nome se non e' ambiguo, es. "gar" per "Garage") o dall'indice numerico."""
        if str(name).isdigit():
            return int(name)
        key = name.strip().lower()
        exact = [i for i, n in enumerate(panel_areas) if n.lower() == key]
        if len(exact) == 1:
            return exact[0]
        pref = [i for i, n in enumerate(panel_areas) if n.lower().startswith(key)]
        if len(pref) == 1:
            return pref[0]
        known = ", ".join(f"{i}={n}" for i, n in enumerate(panel_areas))
        why = "ambigua" if pref else "non trovata"
        sys.exit(f"Errore: area '{name}' {why} tra quelle della centrale ({known})")

    def make_vector(idx, code, num_areas):
        v = bytearray(num_areas)
        if not 0 <= idx < num_areas:
            sys.exit(f"Errore: indice area {idx} fuori range (0..{num_areas-1})")
        v[idx] = code
        return bytes(v)

    v = Vedo(host, port, unit_id=unit_id, verbose=args.verbose, tls=tls, tls_cafile=tls_cafile)
    try:
        v.connect()
        print(f"[*] connesso a {host}:{port}{' (TLS)' if v.tls else ''}, handshake...")
        ctrl = v.handshake()
        print(f"[+] handshake OK (sessione {ctrl.hex()})")
        if cfg_path:
            print(f"[*] config: {cfg_path}")

        def panel_zone_names():
            """Nomi zona dalla centrale; se la lettura fallisce, "Zona N"."""
            try:
                return v.read_zone_names(ctrl, v.STATUS_ZONES)
            except (TimeoutError, socket.timeout, struct.error) as e:
                print(f"[!] nomi zona non letti dalla centrale ({e}), uso 'Zona N'")
                return None

        if args.names:
            print("[*] aree (indice: nome):")
            for i, n in enumerate(v.read_area_names(ctrl)):
                print(f"  {i}: {n}")
            names = v.read_zone_names(ctrl, v.STATUS_ZONES)
            present = v.read_status_once(ctrl)
            print("[*] zone presenti (indice: nome):")
            for i, n in enumerate(names):
                if present is None or f"Zona {i}" in present:
                    print(f"  {i}: {n}")
            return

        if args.log:
            print(f"[*] ultimi {args.log} eventi:")
            for _, when, text in v.read_log(ctrl, args.log):
                print(f"  {when}  {text}")
            return

        if args.status:
            z = v.read_status_once(ctrl, panel_zone_names())
            if z is None:
                print("[!] nessun dato di stato ricevuto")
            else:
                print("[*] stato zone:")
                for k, flags in z.items():
                    print(f"  {k}: {'|'.join(flags) or 'riposo'}")
            return

        if args.monitor:
            print(f"[*] monitor stato zone per {args.monitor}s (interrogazione ogni {args.interval}s)...")

            def on_change(zona, prima, dopo):
                if zona is None:
                    print("  stato iniziale:")
                    for k, fl in dopo.items():
                        print(f"    {k}: {'|'.join(fl) or 'riposo'}")
                else:
                    ts = time.strftime("%H:%M:%S")
                    print(f"  {ts}  {zona}: {'|'.join(prima or ['riposo'])} -> {'|'.join(dopo or ['riposo'])}")
            v.monitor(ctrl, args.monitor, panel_zone_names(), on_change, args.interval)
            return

        if args.arm or args.disarm:
            name = args.arm or args.disarm
            code = ACT_ARM if args.arm else ACT_DISARM
            try:
                panel_areas = v.read_area_names(ctrl)   # numero e nomi dalla centrale
            except (TimeoutError, socket.timeout, struct.error) as e:
                sys.exit(f"[!] aree non lette dalla centrale ({e}): nessuna azione inviata")
            idx = resolve_area(name, panel_areas)
            vector = make_vector(idx, code, len(panel_areas))
            area_label = panel_areas[idx] if idx < len(panel_areas) else f"Area {idx + 1}"
            verb = "arma" if args.arm else "disarma"
            print(f"[*] {verb} area '{area_label}' (indice {idx}) vettore={vector.hex()}")
            if not args.yes:   # prima di aprire la device session: la centrale la registra
                raise PermissionError("azione sull'allarme non confermata (manca --yes)")
            dev = v.open_device_session(ctrl)
            r = v.area_action(dev, vector, confirm=args.yes)
            ok = r["payload"][:2] == b"\x00\x00"
            print(f"[{'+' if ok else '!'}] risposta: {r['payload'][:2].hex()} "
                  f"({'accettato' if ok else 'rifiutato/PIN richiesto'})")
            return

        print("[*] modalità sola lettura: nessuna azione (usa --probe/--status/--names/--log/--monitor/--arm/--disarm)")
    except (PermissionError, VedoError) as e:
        sys.exit(f"[!] {e}")
    finally:
        v.close()


if __name__ == "__main__":
    main()
