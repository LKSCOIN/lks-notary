# Installazione di LKS Notary

## Come è disposto

Il servizio gira su una macchina che ospita anche un nodo LKSCOIN, e viene
esposto da un reverse proxy che può stare altrove.

```
internet ──▶ nginx (reverse proxy) ──▶ uvicorn APP_HOST:8010 ──▶ MariaDB (locale)
                                              │
                                              └──▶ RPC 127.0.0.1:3344 (nodo LKSCOIN)
```

Nei comandi che seguono, sostituisci:

| Segnaposto | Significato |
|---|---|
| `APP_HOST` | indirizzo della macchina che esegue il servizio |
| `PROXY_HOST` | indirizzo della macchina che esegue nginx |
| `NOTARY_DOMAIN` | nome pubblico del servizio, es. `notary.example.org` |
| `SITE_DOMAIN` | nome del sito istituzionale |
| `EXPLORER_HOST` | macchina che esegue il block explorer |
| `EXPLORER_DB` | database del block explorer |
| `ADMIN_USER` | utenza amministrativa con cui aggiorni i file |
| `RPC_USER` | utenza RPC del nodo |

## Scelta della macchina

Serve **Ubuntu 22.04 o successiva**: la 18.04 ha Python 3.6, troppo vecchio per
FastAPI, Pydantic v2 e SQLAlchemy 2.0, e non è più supportata — accettabile per
compilare binari con una glibc antica, meno per un servizio esposto su
internet. Su bionic servirebbe il PPA `ppa:deadsnakes/ppa` (che arriva al 3.10)
e il venv creato con `python3.10 -m venv`.

Il nodo LKSCOIN conviene sia sulla stessa macchina: l'RPC resta su loopback e
non va mai esposto in rete.

---

## 1. Nodo LKSCOIN di servizio

Il notary richiede una sola aggiunta obbligatoria alla configurazione del nodo,
`fallbackfee`. In `lks.conf`:

```
fallbackfee=0.0001
server=1
rpcuser=notary_rpc
rpcpassword=<password lunga e casuale>
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
```

`fallbackfee` non è opzionale: con la mempool quasi sempre vuota la stima
automatica delle fee fallisce e `fundrawtransaction` restituisce *"Fee
estimation failed"*, bloccando il batcher.

**`txindex=1` non serve.** Il watcher legge lo stato delle transazioni con
`gettransaction` del wallet — le transazioni di batch le crea il nodo stesso,
quindi il suo wallet le conosce — invece che con `getrawtransaction`, che
richiederebbe l'indice completo. È una scelta deliberata: attivare `txindex` su
un nodo che ne è privo comporta una reindicizzazione di ore, inaccettabile su
un nodo che serve un pool di mining o un explorer. Se il nodo ha già `txindex`
per altri motivi, tanto meglio, ma il notary non lo pretende.

Come effetto collaterale utile, `gettransaction` di Dash riporta direttamente
il campo `chainlock`, cioè esattamente il segnale di finalità che ci interessa
registrare.

Riavvia e verifica:

```bash
systemctl restart lksd
lks-cli getblockchaininfo | grep -E 'blocks|verificationprogress'
```

### Convivenza con Miningcore sullo stesso nodo

Il nodo è già interrogato da Miningcore, che chiama `getblocktemplate` a ritmo
serrato. Non è un problema — il carico del notary è trascurabile, poche
chiamate ogni dieci minuti — ma servono tre accorgimenti, e il primo è
importante perché quel nodo custodisce il wallet dei pagamenti del pool.

**Wallet separato, senza toccare `lks.conf`.** Se due processi attingono allo
stesso wallet possono selezionare gli stessi UTXO e produrre transazioni in
conflitto — e sul nodo del mining il wallet predefinito è quello che il pool usa
per i pagamenti.

Non aggiungere righe `wallet=` alla configurazione: appena ne compare una, il
nodo carica **soltanto** i wallet elencati e quello predefinito del pool
smetterebbe di essere disponibile. Usa invece `load_on_startup`, che registra
il wallet nelle impostazioni persistenti del nodo:

```bash
lks-cli createwallet "notary" false false "" false true
lks-cli listwallets
```

L'ultimo `true` è `load_on_startup`: da qui in poi il wallet `notary` viene
caricato a ogni avvio, accanto a quello esistente. `listwallets` deve mostrarli
entrambi, `""` e `notary`.

Da qui in avanti i comandi del wallet del notary vogliono `-rpcwallet=notary`.

**Credenziali RPC separate.** Meglio non condividere la password con
Miningcore: con credenziali distinte puoi revocare l'una senza fermare il pool
e i log dicono chi ha fatto cosa. Genera una voce con
`share/rpcauth/rpcauth.py` e aggiungi una seconda riga `rpcauth=` in
`lks.conf`, lasciando intatta la configurazione esistente.

**Coda RPC.** Il default è di 4 thread e 16 richieste in coda. Miningcore
interroga `getblocktemplate` di continuo, quindi va allargata: altrimenti le
chiamate del notary vanno in timeout ogni volta che il pool è impegnato.

```
rpcthreads=8
rpcworkqueue=64
```

Un timeout non perde nulla — il batcher ritenta al ciclo successivo con le
stesse righe pendenti, quindi lo stesso batch e la stessa root — ma è tempo
sprecato.

### Wallet operativo

```bash
lks-cli -rpcwallet=notary getnewaddress "notary-ops"
```

Manda a quell'indirizzo qualche decina di LKS. A 144 batch al giorno il consumo
è di circa **0,10 LKS al mese**: 50 LKS coprono anni, ma imposta comunque un
avviso quando il saldo scende sotto una soglia.

I fondi del collaudo (10.000 LKS) sono nel wallet predefinito di EXPLORER_HOST, sotto
l'etichetta `notary-ops`. Vanno spostati qui:

```bash
# su EXPLORER_HOST
lks-cli sendtoaddress <indirizzo_del_wallet_notary> 9990
```

Attenzione a non confondere le due cose: su EXPLORER_HOST `notary-ops` è
un'**etichetta** dentro il wallet predefinito, qui è un indirizzo dentro un
wallet separato chiamato `notary`.

**Backup del wallet.** Il wallet non contiene le prove — quelle sono sulla
chain — ma perderlo significa perdere i fondi operativi:

```bash
lks-cli -rpcwallet=notary backupwallet /var/backups/lks/notary-wallet-$(date +%F).dat
```

---

## 2. Database su MariaDB

Se il container non ha ancora MariaDB:

```bash
sudo apt install -y mariadb-server
sudo mysql_secure_installation
```

L'utenza amministrativa è `root`; la password è nelle credenziali interne della
Fondazione, non in questo file — questo repository è pubblico e la storia di git non dimentica.

I comandi qui sotto usano `sudo mysql`, che su Debian e Ubuntu entra come
`root` tramite il socket di sistema senza chiedere password. Se sulla tua
installazione l'autenticazione via socket è disattivata, sostituisci
`sudo mysql` con `mysql -u root -p`.

L'applicazione **non** userà mai `root`: si collega come `notary`, con
privilegi limitati al proprio database.

```bash
sudo mysql -e "CREATE DATABASE lks_notary CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
sudo mysql -e "CREATE USER 'notary'@'localhost' IDENTIFIED BY '<password>';"
sudo mysql lks_notary < /opt/lks-notary/sql/001_schema_mariadb.sql
```

Privilegi dell'utente applicativo: solo lettura e scrittura di righe, niente
DDL. Il servizio non deve poter alterare né svuotare le tabelle — in
particolare `audit_log`, protetta da trigger contro `UPDATE` e `DELETE` ma
**non** contro `TRUNCATE` e `DROP`, che sono DDL e i trigger non li vedono.

```bash
sudo mysql -e "GRANT SELECT, INSERT, UPDATE ON lks_notary.* TO 'notary'@'localhost'; FLUSH PRIVILEGES;"
```

Lo schema si applica da root una volta sola, come sopra; gli aggiornamenti
futuri allo schema si fanno allo stesso modo, non dall'applicazione.

Lo schema crea due trigger che rendono `audit_log` append-only: qualunque
`UPDATE` o `DELETE` su quella tabella viene rifiutato dal database, non solo
dall'applicazione.

Verifica che i trigger ci siano davvero:

```bash
sudo mysql lks_notary -e "SHOW TRIGGERS;"
```

---

## 3. Applicazione

```bash
sudo useradd --system --home-dir /opt/lks-notary --shell /usr/sbin/nologin notary
id notary                      # deve stampare uid e gid
sudo mkdir -p /opt/lks-notary/var
sudo git clone https://github.com/LKSCOIN/lks-notary.git /opt/lks-notary
cd /opt/lks-notary

sudo apt install -y python3-venv python3-pip
sudo python3 -m venv .venv          # su Ubuntu 22.04 python3 è già 3.10
sudo -H .venv/bin/pip install -U pip
sudo -H .venv/bin/pip install -e .
sudo -H .venv/bin/pip install pymysql opentimestamps-client
```

`opentimestamps-client` fornisce il comando `ots` usato per l'ancoraggio a
Bitcoin. Se non lo installi il servizio funziona lo stesso, ma i certificati
resteranno senza attestazione Bitcoin — cioè privi della garanzia che non
dipende dall'hashrate di LKSCOIN.

### Configurazione

```bash
sudo cp .env.example .env
sudo nano .env
```

```
LKS_RPC_URL=http://127.0.0.1:3344
LKS_RPC_USER=notary_rpc
LKS_RPC_PASSWORD=<la stessa di lks.conf>
LKS_FEE_RATE=0.0001
DATABASE_URL=mysql+pymysql://notary:<password>@127.0.0.1:3306/lks_notary
BATCH_INTERVAL_SECONDS=600
BATCH_MAX_LEAVES=4096
```

### Permessi

Il servizio deve **leggere** il proprio codice, non scriverlo: l'unica cartella
in cui scrive è `var/`. Rendere `notary` proprietario di tutto sarebbe sia meno
sicuro sia scomodo, perché è un account di sistema senza password e senza shell
— quindi non puoi aggiornare i file via FTP o SCB con quell'utenza.

```bash
sudo chown -R ADMIN_USER:notary /opt/lks-notary
sudo chmod -R g+rX /opt/lks-notary
sudo chown -R notary:notary /opt/lks-notary/var

sudo chown ADMIN_USER:notary /opt/lks-notary/.env
sudo chmod 640 /opt/lks-notary/.env
```

Il `.env` contiene la password RPC del nodo: leggibile dal gruppo, non dagli
altri utenti, e mai nel repository.

Dopo ogni aggiornamento dei file:

```bash
sudo chmod -R g+rX /opt/lks-notary
sudo systemctl restart lks-notary-api lks-notary-worker
```

---

## 4. Servizi

```bash
sudo cp deploy/lks-notary-api.service deploy/lks-notary-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lks-notary-api lks-notary-worker
systemctl status lks-notary-api lks-notary-worker --no-pager
```

Due processi separati di proposito: se il nodo rallenta o un calendar
OpenTimestamps non risponde, il worker aspetta ma l'API continua a rispondere.

---

## 5. nginx

Due scenari, a seconda di dove arrivano le porte 80 e 443.

### A — nginx sulla stessa macchina del notary

Usa `deploy/nginx-notary.conf`, che inoltra a `127.0.0.1:8010`, e lascia il
servizio in ascolto su loopback (`--host 127.0.0.1` nell'unit systemd).

### B — le porte pubbliche sono su un'altra macchina (caso attuale)

Il Proxmox gira 80 e 443 verso `PROXY_HOST`, dove nginx serve già il sito;
il notary sta su `APP_HOST`. Non serve un container proxy in più: si
aggiunge un virtual host a quello esistente.

Sul **front server (.250)**:

```bash
sudo cp nginx-notary-frontend.conf /etc/nginx/sites-available/notary
sudo ln -s /etc/nginx/sites-available/notary /etc/nginx/sites-enabled/
# in http{} di /etc/nginx/nginx.conf:
#   limit_req_zone $binary_remote_addr zone=notary_write:10m rate=10r/m;
sudo nginx -t && sudo systemctl reload nginx
```

**Niente certbot: il TLS passa da Cloudflare.** Quel server usa Origin
Certificate di Cloudflare, non Let's Encrypt, e installare certbot creerebbe un
secondo gestore in competizione per la porta 80 e per i rinnovi. In più, con il
record proxied la validazione HTTP-01 non arriverebbe mai all'origine.

Se il certificato già presente su PROXY_HOST copre un altro dominio, non vale per `SITE_DOMAIN`: serve un
Origin Certificate emesso dalla zona `SITE_DOMAIN` (SSL/TLS → Origin Server →
Create Certificate, hostname `*.SITE_DOMAIN` e `SITE_DOMAIN`, 15 anni). Si
incolla in `/etc/ssl/site/origin.pem` e `origin.key` (`chmod 600` la
chiave) e si verifica con:

```bash
sudo openssl x509 -in /etc/ssl/site/origin.pem -noout -ext subjectAltName
```

Lato Cloudflare: record **A** `notary` verso l'IP pubblico del Proxmox,
**proxied** (al contrario dei seed DNS del nodo, che devono restare non
proxied), e modalità SSL/TLS **Full (strict)**. Con "Flexible" Cloudflare
parlerebbe in HTTP con l'origine e il certificato non servirebbe a nulla.

Sul **container del notary (.252)** il servizio deve ascoltare sulla LAN
(`--host 0.0.0.0`, già impostato nell'unit) e va protetto dal firewall, perché
la porta 8010 non è autenticata:

```bash
sudo ufw allow from PROXY_HOST to any port 8010 proto tcp
sudo ufw deny 8010/tcp
sudo ufw status
```

L'ordine conta: `ufw` applica la prima regola che corrisponde, quindi il
permesso per il proxy deve precedere il divieto generale.

### Prova finale

```bash
curl -s https://NOTARY_DOMAIN/health
```

Deve rispondere `{"status":"ok","version":"0.1.0"}`. Un 502 indica un problema
fra `.250` e `.252`: controlla la regola ufw sul container. Un errore 526 di
Cloudflare significa che il certificato dell'origine non copre l'hostname.

Il rate limit è solo su `/api/v1/notarize`. La verifica resta libera e senza
autenticazione: una prova che solo noi possiamo controllare non è una prova.

---

## 6. Prima chiave e collaudo

```bash
cd /opt/lks-notary
sudo -u notary .venv/bin/python -m lks_notary.cli create-key "Foundation test"
```

Annota il segreto: viene mostrato una volta sola, il database ne conserva solo
lo SHA-256.

```bash
# 1. notarizza un hash
echo -n "prova" > /tmp/prova.txt
HASH=$(sha256sum /tmp/prova.txt | cut -d' ' -f1)
curl -s -X POST https://NOTARY_DOMAIN/api/v1/notarize \
     -H "X-API-Key: <segreto>" -H "Content-Type: application/json" \
     -d "{\"hash\":\"$HASH\"}" | tee /tmp/cert.json

# 2. attendi il batch successivo (fino a 10 minuti) e la conferma del blocco
CERT=$(python3 -c "import json;print(json.load(open('/tmp/cert.json'))['certificate_id'])")
curl -s https://NOTARY_DOMAIN/api/v1/verify/$CERT | python3 -m json.tool

# 3. verifica in modo indipendente, contro il tuo nodo
python3 lks_verify.py \
    --certificate https://NOTARY_DOMAIN/api/v1/verify/$CERT \
    --file /tmp/prova.txt \
    --rpc http://notary_rpc:<password>@127.0.0.1:3344
```

Infine apri `https://NOTARY_DOMAIN/` e trascina `/tmp/prova.txt` nella
pagina: l'impronta viene calcolata nel browser e i controlli Merkle vengono
rifatti in JavaScript, senza fidarsi delle risposte del server.

---

## 7. Indicizzazione nell'explorer (facoltativa ma consigliata)

**Questa parte si installa su EXPLORER_HOST, non sul container**: il database
`EXPLORER_DB` e l'applicativo dell'explorer stanno lì.

L'explorer legge già la chain via RPC, ma la sua tabella `vout` registra solo
indirizzo e importo — e un output `OP_RETURN` non ha né l'uno né l'altro. Per
mostrare le notarizzazioni serve una tabella dedicata, popolata leggendo i
blocchi.

Lo scanner è volutamente un file solo, senza dipendenze oltre `pymysql`, e gira
anche con il Python 3.6 di EXPLORER_HOST:

```bash
# su EXPLORER_HOST
sudo apt install -y python3-pymysql
sudo mkdir -p /opt/lks-scan && sudo cp scripts/scan_chain.py /opt/lks-scan/

sudo mysql EXPLORER_DB < 002_explorer_index.sql
sudo mysql -e "GRANT SELECT, INSERT, UPDATE ON EXPLORER_DB.notary_onchain TO 'explorer'@'localhost';"
sudo mysql -e "GRANT SELECT, INSERT, UPDATE ON EXPLORER_DB.notary_scan_state TO 'explorer'@'localhost';"
```

Primo passaggio, dall'altezza in cui è nato il servizio e non dal blocco zero
(scandire un milione di blocchi richiederebbe ore e non troverebbe nulla prima
di agosto 2026):

```bash
EXPLORER_DB_USER=explorer EXPLORER_DB_PASSWORD='<password>' \
python3 /opt/lks-scan/scan_chain.py \
    --rpc http://RPC_USER:<password>@127.0.0.1:3344 --from-height 995000
```

Poi ogni dieci minuti, via cron:

```
*/10 * * * * root EXPLORER_DB_USER=explorer EXPLORER_DB_PASSWORD='<password>' \
    python3 /opt/lks-scan/scan_chain.py --rpc http://RPC_USER:<password>@127.0.0.1:3344 \
    >> /var/log/lks-scan.log 2>&1
```

Lo scanner rilegge sempre gli ultimi 20 blocchi e riscrive le righe esistenti,
quindi una riorganizzazione si corregge da sola al passaggio successivo.

Nota che questo componente **non parla con il servizio notary**: legge solo la
blockchain. È voluto — dimostra concretamente che chiunque può ritrovare le
prove sulla chain senza passare da noi, che è ciò che rende credibile l'intero
impianto. La tabella `unfungible_token` già presente nell'explorer resta
inutilizzata: ha uno scopo diverso ed è vuota.

## 8. Sorveglianza

```bash
sudo -u notary /opt/lks-notary/.venv/bin/python -m lks_notary.cli status
sudo -u notary /opt/lks-notary/.venv/bin/python -m lks_notary.cli audit-check
journalctl -u lks-notary-worker -f
```

Da controllare periodicamente, meglio se automatizzato:

- saldo del wallet operativo sopra la soglia;
- nessun batch fermo senza `block_hash` da più di un'ora — significa che le
  transazioni non vengono minate;
- `audit-check` che riporta la catena integra;
- il nodo LKSCOIN allineato all'explorer.

## 9. Backup

Tre cose, in ordine di importanza:

1. **il database** (`mysqldump lks_notary`) — contiene i record canonici, senza
   i quali i certificati emessi non sono più ricostruibili;
2. **il wallet** del nodo di servizio;
3. il file `.env`.

Le prove `.ots` stanno nel database ma sono comunque riscaricabili dai calendar
finché l'attestazione è completa: il vero irrecuperabile è il record canonico.
