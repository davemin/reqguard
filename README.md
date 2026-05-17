# reqguard

`reqguard` e un monitor da terminale per server Ubuntu. Mostra traffico in ingresso e richieste web in una TUI, cioe una interfaccia testuale interattiva stile `htop`, e permette di bannare IP usando il firewall del server.

Il progetto nasce per lavorare via SSH, senza dashboard web e senza interfaccia grafica.

Versione documentata: `0.3.28`.

## Cosa Fa

`reqguard` offre due monitor separati:

- `reqguard monitor`: monitora connessioni TCP lette da `/proc/net/tcp` e `/proc/net/tcp6`.
- `reqguard web-monitor`: monitora richieste HTTP lette dagli access log di nginx, Apache o log JSON compatibili.

Funzioni principali:

- Vista raggruppata per IP remoto.
- Vista statistiche con totali, traffico live/bannato, richieste o connessioni per country e country piu bannati.
- Conteggio connessioni/richieste per IP.
- Ordinamento configurabile per arrivo piu recente, conteggio decrescente o conteggio crescente.
- Cambio ordinamento anche dentro l'interfaccia con il tasto `s`.
- Colonna `Last seen` con data e ora dell'ultima connessione/richiesta osservata.
- Header con `Last refresh`, aggiornato a ogni refresh effettivo della schermata.
- Country lookup configurabile: disabilitato, database locale, `ipwho.is`, oppure fallback automatico locale -> `ipwho.is`.
- Espansione dell'IP selezionato per vedere dettagli.
- Nel `web-monitor`, filtro dedicato per path combinabile con filtro IP e date range.
- I filtri testuali supportano wildcard `*`, per esempio `192.189.*` o `/api/*/login`.
- Tasto `x` per eliminare tutti i filtri in una sola azione.
- Stato `LIVE` o `BANNED`.
- Ban persistenti nel file configurato con `REQGUARD_BANS_FILE`, di default `/var/lib/reqguard/bans.json`.
- I ban creati da `web-monitor` con backend UFW sono limitati alle porte web configurate, di default `80,443`, per non bloccare SSH.
- Backend firewall selezionabile: `ufw` oppure `nftables`.
- Servizio systemd per riapplicare i ban al boot.
- Salvataggio ban coerente con il firewall: un IP viene salvato come bannato solo se il backend firewall accetta la regola.
- Sanitizzazione dell'output TUI per ridurre rischi da caratteri di controllo nei log HTTP, user-agent, header, payload o hostname.

## Cosa Non Fa

Il monitor TCP non vede URL, path, header o payload. Vede connessioni di rete:

```text
203.0.113.10:51234 -> 10.0.0.5:443
```

Il monitor HTTP vede path, metodo, status e user-agent solo se questi dati sono nei log del web server. Con HTTPS non puoi leggere path/header/payload sniffando la rete, perche il traffico e cifrato. Devi leggerli dopo la terminazione TLS, cioe da nginx, Apache, reverse proxy o applicazione.

Header completi e payload/body non sono presenti nei log standard. Vanno loggati esplicitamente e con cautela.

## Refresh E Country Lookup

Il refresh minimo e `1.2` secondi. Anche se configuri un valore piu basso, `reqguard` usa comunque `1.2` per evitare loop troppo aggressivi e per rispettare provider esterni.

Configurazione:

```bash
REQGUARD_REFRESH_SECONDS=1.2
```

Country provider:

```bash
REQGUARD_COUNTRY_PROVIDER=ipwhois
REQGUARD_IP_LOOKUP_URL=https://ipwho.is
```

Valori validi:

```text
none
local
ipwhois
auto
```

- `none`: non risolve il country.
- `local`: usa solo database GeoIP locale, se disponibile.
- `ipwhois`: usa `REQGUARD_IP_LOOKUP_URL`; se non configurato, usa `https://ipwho.is`.
- `auto`: prova prima il database locale, poi il servizio configurato in `REQGUARD_IP_LOOKUP_URL`.

La base URL del servizio IP e configurabile:

```bash
REQGUARD_IP_LOOKUP_URL=https://ipwho.is
```

Sono accettate base URL `https://...` e `http://...`, per esempio per usare un proxy o servizio interno:

```bash
REQGUARD_IP_LOOKUP_URL=http://127.0.0.1:8080/geo
```

Se il valore e vuoto, usa uno schema diverso, o non contiene un host valido, `reqguard` torna automaticamente al default `https://ipwho.is`.

`ipwho.is` documenta un limite medio di 60 richieste ogni 60 secondi e circa 1 richiesta al secondo per uso corretto. Per rispettarlo, `reqguard` usa una strategia globale, non una richiesta per ogni IP visto:

- massimo una lookup esterna per ciclo di refresh;
- con refresh minimo 1.2s si resta intorno a 50 lookup/minuto;
- cache persistente su disco;
- IP privati, loopback, multicast o non validi non vengono inviati;
- se compaiono 10 IP nuovi nello stesso aggiornamento, non vengono interrogati tutti insieme: vengono risolti progressivamente nei refresh successivi.

Stati mostrati nella colonna `Country`:

```text
--
```

nessun country disponibile o IP privato/locale.

```text
Pending
```

lookup in attesa per rispettare il rate limit.

```text
Err
```

chiamata al servizio IP fallita o risposta non valida. Non e un errore bloccante: il monitor continua a funzionare.

Cache:

```bash
REQGUARD_COUNTRY_CACHE_FILE=/var/lib/reqguard/country-cache.json
```

Nota privacy: usando il default `ipwho.is`, gli IP pubblici osservati vengono inviati a un servizio esterno. Se non vuoi questo comportamento, imposta `REQGUARD_COUNTRY_PROVIDER=local` o `none`, oppure usa `REQGUARD_IP_LOOKUP_URL` verso un servizio interno.

## Architettura

Componenti principali:

- `src/reqguard/cli.py`: entrypoint CLI.
- `src/reqguard/tui.py`: monitor TCP.
- `src/reqguard/web_tui.py`: monitor HTTP/access-log.
- `src/reqguard/procnet.py`: lettura connessioni TCP da `/proc`.
- `src/reqguard/weblog.py`: parsing access log standard e JSON.
- `src/reqguard/firewall.py`: backend `ufw` e `nftables`.
- `src/reqguard/banlist.py`: lista ban persistente.

File installati dal pacchetto `.deb`:

```text
/usr/bin/reqguard
/usr/lib/python3/dist-packages/reqguard
/usr/share/reqguard/reqguard.default
/lib/systemd/system/reqguard-firewall.service
/var/lib/reqguard/
```

Durante l'installazione il pacchetto crea `/etc/default/reqguard` dai default in `/usr/share/reqguard/reqguard.default` solo se il file non esiste gia. Se `/etc/default/reqguard` esiste, il pacchetto non lo modifica e stampa un messaggio con il path del file da editare.

## Backend Firewall

### UFW

Se sul server usi gia UFW, usa questo backend. Quando banni un IP, `reqguard` aggiunge una regola simile a:

```bash
ufw insert 1 deny from 203.0.113.10 to any comment reqguard
```

Da `web-monitor`, con backend UFW, il ban viene invece limitato alle porte TCP configurate:

```bash
ufw insert 1 deny from 203.0.113.10 to any port 80 proto tcp comment reqguard
ufw insert 1 deny from 203.0.113.10 to any port 443 proto tcp comment reqguard
```

Le porte si configurano in `/etc/default/reqguard`:

```bash
REQGUARD_WEB_BAN_PORTS=80,443
```

Se `REQGUARD_WEB_BAN_PORTS` non e presente, e vuoto o contiene solo valori non validi, `reqguard` usa automaticamente `80,443`. Questo vale per i ban creati da `web-monitor`; `monitor` e il comando `reqguard ban` restano ban globali sull'IP, perche non sono legati a uno specifico servizio HTTP.

`insert 1` serve a mettere il deny in alto, prima di eventuali allow verso nginx, Apache o altri servizi.

`reqguard` richiede che UFW sia attivo. Se `ufw status` risulta `inactive` o `inattivo`, il programma fallisce invece di salvare un ban che non verrebbe realmente applicato.

Verifica regole:

```bash
sudo ufw status numbered
```

### nftables

Se usi `nftables` diretto, `reqguard` crea una tabella dedicata:

```text
table inet reqguard
```

con set:

```text
banned_ipv4
banned_ipv6
```

Verifica regole:

```bash
sudo nft list table inet reqguard
```

Rimozione tabella `reqguard`:

```bash
sudo nft delete table inet reqguard
```

## Cautele Importanti

Non testare ban sul tuo IP SSH principale. Puoi chiuderti fuori dal server.

Se usi UFW e lo stato e inattivo:

```bash
sudo ufw status
```

e vedi:

```text
Status: inactive
```

allora UFW non sta filtrando traffico. Prima di abilitarlo assicurati di consentire SSH:

```bash
sudo ufw allow OpenSSH
sudo ufw enable
```

Se SSH usa una porta custom:

```bash
sudo ufw allow 2222/tcp
sudo ufw enable
```

Se usi `fail2ban`, puo convivere con `reqguard`, ma ricorda:

- `fail2ban` banna automaticamente.
- `reqguard` banna manualmente dalla TUI/CLI.
- Lo stesso IP puo essere bannato da entrambi.
- Se fai unban da `reqguard`, l'IP puo restare bannato da `fail2ban`.

Per sbloccare da fail2ban:

```bash
sudo fail2ban-client set sshd unbanip 203.0.113.10
```

Loggare payload HTTP puo salvare password, token, cookie e dati personali. Fallo solo in ambienti controllati o mascherando i campi sensibili.

## Comportamenti Di Sicurezza

`reqguard` esegue comandi firewall con argomenti separati, non con shell string. Gli IP vengono validati e normalizzati con le API standard `ipaddress`.

Quando banni un IP:

1. `reqguard` prova prima ad applicare il ban al firewall.
2. Se il firewall fallisce, il ban non viene salvato nel file configurato con `REQGUARD_BANS_FILE`.
3. Se il firewall accetta il ban ma il salvataggio su disco fallisce, `reqguard` prova a fare rollback rimuovendo la regola firewall.

Questo evita, per quanto possibile, lo stato incoerente in cui la TUI mostra `BANNED` ma il firewall non blocca realmente.

Con UFW:

- UFW deve essere attivo.
- Le regole create da `reqguard` hanno commento `reqguard`.
- I ban creati da `web-monitor` sono persistiti con la lista porte e vengono riapplicati come regole TCP port-specific anche dopo `sync-firewall` o riavvio.
- La rimozione cerca il match esatto dell'IP, non una sottostringa.
- Non viene creato fallback senza commento, per evitare regole non piu gestibili dal programma.

Con nftables:

- La tabella `inet reqguard` viene creata una volta.
- I ban sono mantenuti nei set `banned_ipv4` e `banned_ipv6`.
- L'inizializzazione evita di duplicare le regole drop se la tabella esiste gia.
- I ban port-specific creati da `web-monitor` richiedono backend UFW. Con backend nftables `reqguard` non li converte in ban globali, per evitare blocchi piu ampi del previsto.

Il file `/etc/default/reqguard` viene letto come file key/value dal codice Python. Non viene eseguito come script shell.

I campi mostrati nella TUI che arrivano da input non fidato, come user-agent, path, header, payload e hostname reverse DNS, vengono sanitizzati prima del rendering.

## Requisiti

### Server di destinazione

Sul server dove installi il `.deb` servono:

- `python3`.
- `ufw` oppure `nftables`.
- Permessi root per applicare ban firewall e gestire systemd.
- `tmux` opzionale, utile se vuoi lasciare il monitor aperto via SSH.

Server con UFW:

```bash
sudo apt update
sudo apt install -y python3 ufw
sudo ufw allow OpenSSH
sudo ufw enable
```

Server con nftables:

```bash
sudo apt update
sudo apt install -y python3 nftables
sudo systemctl enable --now nftables
```

Opzionale per sessioni SSH persistenti:

```bash
sudo apt install -y tmux
```

### Macchina di build

Sulla macchina Ubuntu dove costruisci il pacchetto serve `dpkg-deb`, fornito da `dpkg-dev`:

```bash
sudo apt update
sudo apt install -y python3 dpkg-dev
```

`dpkg-dev` non serve sui server dove installi un `.deb` gia costruito.

## Installazione Su Server Ubuntu

Metodo consigliato: costruisci il pacchetto `.deb` una volta su una macchina Ubuntu compatibile, poi distribuisci direttamente quel file sui server.

Il pacchetto Debian e dichiarato `Architecture: all`, quindi non contiene binari compilati per una CPU specifica. Lo stesso `.deb` va bene per server Ubuntu x86_64, ARM64 o ARM, purche abbiano Python 3 e il backend firewall scelto (`ufw` o `nftables`). La build va comunque fatta su Linux/Ubuntu, non su macOS, perche usa `dpkg-deb`.

Sulla macchina di build Ubuntu:

```bash
cd /tmp/reqguard
./scripts/build-deb.sh
```

Distribuisci solo il `.deb` al server:

```bash
scp build/deb/reqguard_0.3.28_all.deb user@SERVER:/tmp/
ssh user@SERVER
sudo apt install -y /tmp/reqguard_0.3.28_all.deb
```

Verifica:

```bash
which reqguard
dpkg -s reqguard | grep Version
reqguard --help
```

## Prima Installazione E Upgrade

### Prima installazione

1. Costruisci il `.deb` su una macchina Ubuntu compatibile:

```bash
cd /tmp/reqguard
./scripts/build-deb.sh
```

2. Copia solo il pacchetto sul server di destinazione:

```bash
scp build/deb/reqguard_0.3.28_all.deb user@SERVER:/tmp/
ssh user@SERVER
```

3. Installa il pacchetto sul server:

```bash
sudo apt install -y /tmp/reqguard_0.3.28_all.deb
```

4. Durante l'installazione il pacchetto controlla il file:

```text
/etc/default/reqguard
```

Se non esiste, viene creato con i default:

```text
reqguard: created default configuration file: /etc/default/reqguard
reqguard: edit this file to change defaults.
```

Se esiste gia, non viene sovrascritto:

```text
reqguard: configuration file already exists: /etc/default/reqguard
reqguard: edit this file to change defaults.
```

5. Modifica la configurazione, se necessario:

```bash
sudo nano /etc/default/reqguard
```

6. Inizializza o sincronizza il firewall:

```bash
sudo reqguard init-firewall
sudo reqguard sync-firewall
```

7. Abilita il servizio che riapplica i ban al boot:

```bash
sudo systemctl enable reqguard-firewall.service
sudo systemctl start reqguard-firewall.service
```

8. Avvia il monitor:

```bash
sudo reqguard monitor
```

oppure il monitor web:

```bash
sudo reqguard web-monitor --log-file /var/log/nginx/access.log
```

### Aggiornamento a una versione successiva

1. Sulla macchina di build Ubuntu, aggiorna il sorgente e ricostruisci il pacchetto con la nuova versione:

```bash
cd /tmp/reqguard
./scripts/build-deb.sh
```

2. Copia il nuovo `.deb` sul server:

```bash
scp build/deb/reqguard_0.3.28_all.deb user@SERVER:/tmp/
ssh user@SERVER
```

3. Installa il nuovo `.deb`:

```bash
sudo apt install -y /tmp/reqguard_0.3.28_all.deb
```

Se stai reinstallando la stessa identica versione:

```bash
sudo apt install --reinstall -y /tmp/reqguard_0.3.28_all.deb
```

Il file `/etc/default/reqguard` non viene sovrascritto durante l'upgrade. I nuovi default del pacchetto vengono installati come template in:

```text
/usr/share/reqguard/reqguard.default
```

Se una nuova versione introduce nuove opzioni, confronta manualmente:

```bash
diff -u /etc/default/reqguard /usr/share/reqguard/reqguard.default
```

e aggiungi a `/etc/default/reqguard` solo le variabili che vuoi adottare.

Per la versione `0.3.28` controlla in particolare questa variabile:

```bash
REQGUARD_WEB_BAN_PORTS=80,443
```

Se il file `/etc/default/reqguard` esisteva gia, l'upgrade non la aggiunge automaticamente. Puoi inserirla a mano:

```bash
sudo nano /etc/default/reqguard
```

Oppure, se manca, aggiungerla da shell:

```bash
grep -q '^REQGUARD_WEB_BAN_PORTS=' /etc/default/reqguard || echo 'REQGUARD_WEB_BAN_PORTS=80,443' | sudo tee -a /etc/default/reqguard
```

Attenzione ai ban creati con versioni precedenti: nel file ban non avevano ancora il campo `ports`, quindi vengono interpretati come ban globali sull'IP. Se vuoi trasformare un vecchio ban web in un ban limitato a `80,443`, rimuovilo e ricrealo da `web-monitor`:

```bash
sudo reqguard unban 203.0.113.10
sudo reqguard web-monitor --log-file /var/log/nginx/access.log
```

Poi seleziona l'IP e premi `b`. Il nuovo ban verra salvato con le porte configurate.

### Ricaricamento impostazioni

I comandi `reqguard` leggono `/etc/default/reqguard` a ogni avvio del processo. Quindi:

- se modifichi `/etc/default/reqguard`, chiudi e riapri `reqguard monitor` o `reqguard web-monitor`;
- `reqguard-firewall.service` e di tipo `oneshot`, quindi per applicare nuove impostazioni al servizio devi rilanciarlo;
- se aggiorni i file systemd del pacchetto, esegui anche `daemon-reload`.

Dopo un upgrade del pacchetto:

```bash
sudo systemctl daemon-reload
sudo systemctl restart reqguard-firewall.service
```

Dopo una sola modifica a `/etc/default/reqguard`, senza cambio dei file systemd:

```bash
sudo systemctl restart reqguard-firewall.service
```

Poi riavvia eventuali monitor TUI aperti, perche i monitor gia in esecuzione non ricaricano il file di configurazione in automatico.

## Configurazione

Il file principale di configurazione e:

```text
/etc/default/reqguard
```

Alla prima installazione viene creato automaticamente con i default. Se il file esiste gia, il pacchetto non lo sovrascrive e in fase di installazione stampa dove si trova:

```text
reqguard: configuration file already exists: /etc/default/reqguard
reqguard: edit this file to change defaults.
```

Se invece non esiste:

```text
reqguard: created default configuration file: /etc/default/reqguard
reqguard: edit this file to change defaults.
```

Esempio:

```bash
REQGUARD_FIREWALL_BACKEND=ufw
REQGUARD_BANS_FILE=/var/lib/reqguard/bans.json
REQGUARD_COUNTRY_PROVIDER=ipwhois
REQGUARD_IP_LOOKUP_URL=https://ipwho.is
REQGUARD_COUNTRY_CACHE_FILE=/var/lib/reqguard/country-cache.json
REQGUARD_REFRESH_SECONDS=1.2
REQGUARD_SORT=arrival
REQGUARD_WEB_BAN_PORTS=80,443
```

Backend validi:

```text
auto
ufw
nftables
```

`auto` sceglie UFW se e installato e attivo; altrimenti usa nftables se il comando `nft` e disponibile. Se sul server usi UFW, puoi comunque forzarlo con `REQGUARD_FIREWALL_BACKEND=ufw`.

Ordinamenti validi:

```text
arrival
count-desc
count-asc
```

Per usare UFW come backend predefinito:

```bash
sudo sed -i 's/REQGUARD_FIREWALL_BACKEND=.*/REQGUARD_FIREWALL_BACKEND=ufw/' /etc/default/reqguard
```

Per usare nftables:

```bash
sudo sed -i 's/REQGUARD_FIREWALL_BACKEND=.*/REQGUARD_FIREWALL_BACKEND=nftables/' /etc/default/reqguard
```

Per cambiare ordinamento predefinito:

```bash
sudo sed -i 's/REQGUARD_SORT=.*/REQGUARD_SORT=count-desc/' /etc/default/reqguard
```

Puoi anche passare opzioni da CLI:

```bash
sudo reqguard --firewall-backend ufw monitor --sort arrival
sudo reqguard --firewall-backend ufw web-monitor --sort count-desc
```

## Inizializzare Il Firewall

Dopo installazione:

```bash
sudo reqguard init-firewall
sudo reqguard sync-firewall
```

`init-firewall` prepara o verifica il backend firewall configurato.

Con UFW:

- controlla che `ufw` sia disponibile e attivo.
- le regole vengono create quando banni IP.

Con nftables:

- crea tabella e set dedicati `reqguard`.

`sync-firewall` legge:

```text
/var/lib/reqguard/bans.json
```

e riapplica i ban al backend firewall.

## Servizio systemd

Abilita il ripristino automatico dei ban al boot:

```bash
sudo systemctl enable --now reqguard-firewall.service
sudo systemctl status reqguard-firewall.service
```

Questo servizio non apre la TUI. Esegue solo:

```bash
reqguard sync-firewall
```

al boot.

Il servizio e `oneshot`, quindi e normale vederlo come:

```text
active (exited)
```

## Avvio Monitor TCP

Avvio base:

```bash
sudo reqguard monitor
```

Con ordinamento iniziale:

```bash
sudo reqguard monitor --sort arrival
sudo reqguard monitor --sort count-desc
sudo reqguard monitor --sort count-asc
```

Con backend esplicito:

```bash
sudo reqguard --firewall-backend ufw monitor
```

## Avvio Monitor HTTP

Avvio base:

```bash
sudo reqguard web-monitor
```

Se non trova log standard, specifica il file:

```bash
sudo reqguard web-monitor --log-file /var/log/nginx/access.log
sudo reqguard web-monitor --log-file /var/log/apache2/access.log
```

Con ordinamento:

```bash
sudo reqguard web-monitor --sort arrival
sudo reqguard web-monitor --sort count-desc
sudo reqguard web-monitor --sort count-asc
```

Con backend UFW:

```bash
sudo reqguard --firewall-backend ufw web-monitor --log-file /var/log/nginx/access.log
```

## Tasti Nella TUI

Valgono per entrambi i monitor:

```text
Up/Down          seleziona IP
Shift+Up/Down    estende selezione su piu righe
Enter/Space      espande o chiude dettagli
s                cambia ordinamento
b                banna IP selezionati, o quello corrente
u                rimuove ban degli IP selezionati, o quello corrente
r                refresh manuale
q                esce
Ctrl+C           esce senza traceback
```

La selezione multipla funziona sia nella vista principale sia nella vista ban. Le righe selezionate sono marcate con `*`; `b` applica il ban in bulk dalla vista principale, `u` fa unban in bulk dalla vista ban.

## Guida Ai Filtri

I filtri si applicano in AND: se imposti IP, data e path, vengono mostrate solo le righe che rispettano tutti i filtri attivi.

Valgono per entrambi i monitor:

```text
/             ricerca generale
i             filtro IP
d             filtro data o intervallo data
c             filtro country
x             elimina tutti i filtri in una sola azione
```

Solo per `monitor`:

```text
h             filtro hostname
p             filtro porta locale
```

Solo per `web-monitor`:

```text
p             filtro path
```

Esempi filtro IP:

```text
203.0.113.10
192.189.*
2001:db8:*
```

Esempi filtro hostname nel `monitor`:

```text
scanner.example.com
scanner*
*.example.com
```

Esempi filtro porta locale nel `monitor`:

```text
80
443
8*
44*
```

Esempi filtro path nel `web-monitor`:

```text
/login
/admin*
/api/*/login
```

Esempi date:

```text
2026-05-17
2026-05-17 10:00:00..2026-05-17 12:00:00
2026-05-17 10:00:00..
..2026-05-17 12:00:00
```

Wildcard:

- `*` corrisponde a zero o piu caratteri.
- Senza `*`, i filtri IP, country e porta sono esatti.
- Senza `*`, i filtri hostname, path e ricerca generale cercano testo contenuto.
- Con `*`, il filtro diventa un pattern: `192.189.*` trova tutti gli IP che iniziano con `192.189.`.

Esempio pratico nel `monitor`:

```text
i 192.189.*
h *.example.com
p 44*
```

mostra solo le connessioni da IP `192.189.*`, con hostname compatibile con `*.example.com`, verso porte locali compatibili con `44*`.

Esempio pratico nel `web-monitor`:

```text
i 192.189.*
p /api/*/login
d 2026-05-17 10:00:00..2026-05-17 12:00:00
```

mostra solo le richieste da IP `192.189.*`, verso path compatibili con `/api/*/login`, osservate nell'intervallo indicato.

## Gestione Ban Da CLI

Lista ban:

```bash
sudo reqguard bans
```

Banna IP:

```bash
sudo reqguard ban 203.0.113.10 --reason "scanner"
```

Rimuovi ban:

```bash
sudo reqguard unban 203.0.113.10
```

Sincronizza firewall:

```bash
sudo reqguard sync-firewall
```

Con backend esplicito:

```bash
sudo reqguard --firewall-backend ufw ban 203.0.113.10 --reason "manual block"
sudo reqguard --firewall-backend ufw unban 203.0.113.10
sudo reqguard --firewall-backend ufw sync-firewall
```

## Uso Con tmux

Per lasciare il monitor aperto dopo la disconnessione SSH:

```bash
tmux new -s reqguard
sudo reqguard monitor
```

Oppure:

```bash
tmux new -s reqguard-web
sudo reqguard web-monitor --log-file /var/log/nginx/access.log
```

Per rientrare:

```bash
tmux attach -t reqguard
```

## Configurare Log HTTP Aggregato

Se hai piu virtualhost con access log diversi, il modo piu pratico e creare un log aggregato per `reqguard`.

Esempio nginx JSON:

```nginx
log_format reqguard_json escape=json
  '{"remote_addr":"$remote_addr",'
  '"method":"$request_method",'
  '"path":"$request_uri",'
  '"protocol":"$server_protocol",'
  '"status":$status,'
  '"host":"$host",'
  '"server_name":"$server_name",'
  '"user_agent":"$http_user_agent",'
  '"referer":"$http_referer",'
  '"headers":{"x_forwarded_for":"$http_x_forwarded_for","content_type":"$content_type"}}';
```

Dentro ogni `server { ... }` puoi aggiungere:

```nginx
access_log /var/log/nginx/reqguard_access.log reqguard_json;
```

Poi:

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo reqguard web-monitor --log-file /var/log/nginx/reqguard_access.log
```

Puoi mantenere anche i log specifici dei virtualhost:

```nginx
access_log /var/log/nginx/site1.access.log combined;
access_log /var/log/nginx/reqguard_access.log reqguard_json;
```

## Payload E Header HTTP

I log standard di nginx/apache mostrano di solito:

- IP remoto.
- timestamp.
- request line.
- status.
- byte inviati.
- referer.
- user-agent.

Non includono payload/body.

Per header selezionati puoi usare log JSON come sopra.

Per payload/body:

- meglio farlo a livello applicativo.
- evita di loggare password, token, cookie, carte, dati personali.
- valuta mascheramento o logging solo temporaneo.

## Test Locale Senza Web Server

### Test Monitor TCP

Avvia un server HTTP temporaneo:

```bash
mkdir -p /tmp/reqguard-web-test
cd /tmp/reqguard-web-test
echo "ok" > index.html
python3 -m http.server 8080
```

In un'altra shell:

```bash
sudo reqguard monitor
```

In una terza shell:

```bash
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/login
curl -X POST http://127.0.0.1:8080/login -d "username=test"
```

### Test Monitor HTTP Con Log Finto

Crea un log:

```bash
touch /tmp/access.log
sudo reqguard web-monitor --log-file /tmp/access.log
```

In un'altra shell:

```bash
echo '127.0.0.1 - - [14/May/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl/8.0"' >> /tmp/access.log
echo '127.0.0.1 - - [14/May/2026:12:00:01 +0000] "POST /login HTTP/1.1" 401 34 "-" "curl/8.0"' >> /tmp/access.log
echo '127.0.0.1 - - [14/May/2026:12:00:02 +0000] "GET /admin HTTP/1.1" 404 20 "-" "curl/8.0"' >> /tmp/access.log
```

Test JSON con header/payload simulati:

```bash
echo '{"remote_addr":"127.0.0.1","method":"POST","path":"/login","status":401,"user_agent":"curl/8.0","headers":{"content_type":"application/x-www-form-urlencoded"},"request_body":"username=test"}' >> /tmp/access.log
```

Non testare il ban su `127.0.0.1`. Per verificare il ban usa un'altra macchina nella LAN o un secondo server.

## Compilazione E Build

### Ambiente sviluppo Python

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e .
```

Esecuzione locale:

```bash
PYTHONPATH=src python3 -m reqguard.cli --help
```

### Wheel Python

```bash
python -m pip install build
python -m build
```

### Pacchetto Debian

Su una macchina Ubuntu usata come build host:

```bash
./scripts/build-deb.sh
```

Output:

```text
build/deb/reqguard_0.3.28_all.deb
```

Installazione:

```bash
scp build/deb/reqguard_0.3.28_all.deb user@SERVER:/tmp/
ssh user@SERVER
sudo apt install -y /tmp/reqguard_0.3.28_all.deb
```

Se `apt` dice che e gia installato alla versione piu recente, incrementa la versione del pacchetto oppure forza la reinstallazione:

```bash
sudo apt install --reinstall -y /tmp/reqguard_0.3.28_all.deb
```

Nota architettura: il pacchetto e `Architecture: all`, quindi e indipendente dalla CPU. Puoi usare lo stesso `.deb` su x86_64, ARM64 o ARM se il sistema e Ubuntu/Linux compatibile e dispone delle dipendenze richieste.

## Aggiornamento

Per aggiornare il pacchetto a una versione successiva, segui la sezione `Prima Installazione E Upgrade`.

In sintesi:

- ricostruisci il `.deb` sulla macchina Ubuntu usata come build host;
- copia il `.deb` sul server di destinazione;
- installa il nuovo pacchetto con `sudo apt install -y /tmp/reqguard_VERSION_all.deb`;
- controlla eventuali nuove opzioni confrontando `/etc/default/reqguard` con `/usr/share/reqguard/reqguard.default`;
- esegui `sudo systemctl daemon-reload` se sono cambiati file systemd;
- esegui `sudo systemctl restart reqguard-firewall.service`;
- riavvia i monitor TUI aperti, perche non ricaricano la configurazione mentre sono gia in esecuzione.

## Troubleshooting

### `sync-firewall` fallisce al boot

Controlla il journal della unit:

```bash
sudo systemctl status reqguard-firewall.service --no-pager -l
sudo journalctl -u reqguard-firewall.service -b --no-pager -o short-iso
```

Se vedi:

```text
error: no active firewall backend found
```

significa che al momento del boot `REQGUARD_FIREWALL_BACKEND=auto` non ha trovato UFW attivo ne `nft` disponibile. Verifica il backend:

```bash
sudo sed -n '1,80p' /etc/default/reqguard
sudo ufw status verbose
command -v ufw
command -v nft
```

Se usi UFW, assicurati che sia attivo e abilitato al boot:

```bash
sudo ufw status
sudo systemctl is-enabled ufw
sudo systemctl enable ufw
```

Poi ricarica systemd e riprova:

```bash
sudo systemctl daemon-reload
sudo systemctl restart reqguard-firewall.service
sudo systemctl status reqguard-firewall.service --no-pager -l
```

La unit `reqguard-firewall.service` include retry brevi su failure, cosi un avvio temporaneamente anticipato rispetto al firewall non lascia subito i ban non sincronizzati.

### UFW e inattivo

```bash
sudo ufw status
```

Se vedi:

```text
Status: inactive
```

abilita UFW dopo aver permesso SSH:

```bash
sudo ufw allow OpenSSH
sudo ufw enable
```

### Vedo traceback all'uscita

Le versioni recenti gestiscono `Ctrl+C`. Aggiorna il pacchetto e usa:

```text
q
```

oppure:

```text
Ctrl+C
```

### `web-monitor` non mostra richieste

Controlla il file log:

```bash
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/apache2/access.log
```

Poi avvia specificando il file:

```bash
sudo reqguard web-monitor --log-file /path/to/access.log
```

### Non vedo header o payload

Normale con log standard. Devi configurarli nel web server o nell'applicazione.

### Un IP resta bannato dopo `unban`

Potrebbe essere bannato anche da `fail2ban` o da regole manuali:

```bash
sudo ufw status numbered
sudo fail2ban-client status
sudo nft list ruleset
```

Con UFW controlla anche che la regola abbia commento `reqguard`. Le regole senza quel commento potrebbero essere state create manualmente o da altri strumenti e non vengono rimosse da `reqguard`.

### Ho inizializzato nftables ma voglio usare solo UFW

Rimuovi solo la tabella dedicata di `reqguard`:

```bash
sudo nft delete table inet reqguard
```

Poi configura UFW:

```bash
sudo sed -i 's/REQGUARD_FIREWALL_BACKEND=.*/REQGUARD_FIREWALL_BACKEND=ufw/' /etc/default/reqguard
sudo reqguard sync-firewall
```

## Disinstallazione

Rimuovi pacchetto:

```bash
sudo apt remove reqguard
```

Se vuoi eliminare anche stato e ban:

```bash
sudo rm -rf /var/lib/reqguard
```

Se usavi nftables:

```bash
sudo nft delete table inet reqguard
```

Se usavi UFW, rimuovi le regole `reqguard` manualmente:

```bash
sudo ufw status numbered
sudo ufw delete NUMERO_REGOLA
```

## Wiki Rapida Post Installazione Con UFW

Usa questa checklist dopo aver copiato e installato il pacchetto `.deb` su un server dove UFW e gia attivo.

### 1. Controlla la configurazione

```bash
sudo cat /etc/default/reqguard
```

Modifica il file se necessario:

```bash
sudo nano /etc/default/reqguard
```

Per usare UFW:

```bash
REQGUARD_FIREWALL_BACKEND=ufw
REQGUARD_BANS_FILE=/var/lib/reqguard/bans.json
REQGUARD_WEB_BAN_PORTS=80,443
```

`REQGUARD_WEB_BAN_PORTS` controlla solo i ban creati da `web-monitor`. Se manca, il default e `80,443`.

Se stai aggiornando da una versione precedente, controlla anche `sudo reqguard bans`: i ban gia salvati senza campo `ports` restano globali sull'IP. Per renderli limitati al web, rimuovili e ribannali da `web-monitor`.

### 2. Proteggi SSH prima di testare i ban

Verifica le regole UFW:

```bash
sudo ufw status numbered
```

Assicurati che la porta SSH sia consentita. Se SSH usa la porta `22`:

```bash
sudo ufw allow 22/tcp comment 'allow ssh'
```

Se SSH usa una porta diversa, per esempio `2222`:

```bash
sudo ufw allow 2222/tcp comment 'allow ssh custom port'
```

Da `web-monitor`, con UFW, i ban vengono applicati solo alle porte configurate in `REQGUARD_WEB_BAN_PORTS`, quindi non dovrebbero chiudere SSH se SSH usa una porta diversa da quelle web. Da `monitor` e da `reqguard ban`, invece, il ban e globale sull'IP: non bannare l'IP da cui sei collegato in SSH. Tieni aperta la sessione attuale e, se possibile, apri una seconda sessione SSH di test prima di chiudere la prima.

### 3. Inizializza e sincronizza reqguard

```bash
sudo reqguard init-firewall
sudo reqguard sync-firewall
```

Output atteso per UFW:

```text
reqguard firewall backend ready: ufw
```

### 4. Abilita il servizio al boot

```bash
sudo systemctl enable reqguard-firewall.service
sudo systemctl restart reqguard-firewall.service
sudo systemctl status reqguard-firewall.service
```

Il servizio riapplica al firewall la lista ban persistente quando il server riparte.

### 5. Avvia il monitor

Monitor TCP generale:

```bash
sudo reqguard monitor
```

Monitor web da access log nginx:

```bash
sudo reqguard web-monitor --log-file /var/log/nginx/access.log
```

Se il virtualhost usa un log diverso, prima cercalo:

```bash
sudo nginx -T | grep -nE "server_name|access_log"
```

### 6. Comandi utili

Lista ban salvati:

```bash
sudo reqguard bans
```

Regole UFW:

```bash
sudo ufw status numbered
```

Stato fail2ban:

```bash
sudo fail2ban-client status
```

### 7. Tasti nel monitor

```text
Frecce su/giu  seleziona IP
Enter          espande dettagli
v oppure Tab   cambia vista richieste/ban
/              cerca nei campi visibili: IP, data, country, host, porte o top path
i              filtra per IP esatto
d              filtra per intervallo data/ora
c              filtra per country
x              cancella filtri
b              banna IP selezionato
u              rimuove ban nella vista ban
s              cambia ordinamento
q              esce
```
