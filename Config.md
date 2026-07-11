# Konfigurationshandbuch (`Config.toml`)

Dieses Handbuch beschreibt alle verfügbaren Parameter der `Config.toml` und deren mögliche Ausprägungen. Die Konfiguration steuert das globale Verhalten des Gateways sowie die detaillierten Einstellungen einzelner Server-Instanzen (Listener, Routen, Middleware).

## Starten mit einer alternativen Konfigurationsdatei

Standardmäßig sucht der Server beim Start nach einer Datei namens `Config.toml` im aktuellen Verzeichnis. Sie können dem Server jedoch eine alternative Konfigurationsdatei übergeben, indem Sie den Pfad als erstes Kommandozeilenargument angeben:

```bash
# Beim Ausführen der kompilierten Binary
./server /pfad/zur/anderen_config.toml

# Beim Starten über Cargo (während der Entwicklung)
cargo run --bin server -- /pfad/zur/anderen_config.toml
```

---

## Globale Systemeinstellungen

Diese Parameter befinden sich auf der obersten Ebene der Datei und beeinflussen das Gesamtsystem.

| Parameter | Datentyp | Beschreibung | Mögliche Werte / Standardwert |
| :--- | :--- | :--- | :--- |
| `tokio_threads` | Integer | Legt die Anzahl der Worker-Threads für die asynchrone Tokio-Runtime fest. Nützlich für Performance-Tuning auf dedizierter Hardware. | **Standard:** `Verfügbare CPU-Kerne * 2`<br>**Beispiel:** `50` |
| `pki_base_oid` | String | Die Basis-OID (Object Identifier) zur Sicherheitsvalidierung. Dient als Wurzel für die Interpretation von Zertifikatserweiterungen (Private Enterprise Number). | **Beispiel:** `"1.3.6.1.4.1.65111"` |
| `log_dir` | String | Verzeichnispfad für persistente Log-Dateien. Wenn auskommentiert oder nicht vorhanden, wird nur auf die Standardausgabe (`stdout`) geloggt. | **Beispiel:** `"log"` |

### `[oid_mapping]`
Ordnet OID-Suffixe, die bei der Authentifizierung (mTLS oder JWT) gefunden werden, internen Rollen (`UserRole`) zu. Dies ist die Grundlage für die rollenbasierte Zugriffskontrolle (RBAC) des Proxys.

**Wie kommen die OIDs in die Anfrage?**
1. **Bei mTLS (Client-Zertifikate):** Die OIDs werden als benutzerdefinierte X.509-Erweiterungen (Custom Extensions) in das Client-Zertifikat eingebettet. Der Server sucht nach Erweiterungen, die mit der `pki_base_oid` beginnen. Der Rest der OID (das Suffix) wird extrahiert. *Beispiel:* Ist die Base-OID `1.3.6.1.4.1.65111` und das Zertifikat enthält die OID `1.3.6.1.4.1.65111.1`, wird das Suffix `"1"` ausgelesen.
2. **Bei JWT (JSON Web Tokens):** Der Payload des JWT enthält ein Array-Feld namens `oids` (z. B. `"oids": ["1", "2"]`). Diese Strings werden direkt als Suffixe interpretiert.

**Was bewirken sie bei der Ausführung?**
1. **Mapping:** Während der Anfrageverarbeitung werden die gefundenen Suffixe anhand dieser Tabelle in stark typisierte Rollen übersetzt. Fehlt das Suffix in der Tabelle (oder fehlt die OID komplett), wird der Client automatisch auf die Rolle `"Guest"` zurückgestuft.
2. **Routing & Autorisierung:** Der Proxy (`RouterService`) gleicht die zugewiesenen Rollen mit den `allowed_roles` ab, die bei den jeweiligen Reverse-Proxy-Routen konfiguriert sind. Nur wenn der Request eine zugelassene Rolle besitzt, wird die Anfrage an das Backend weitergeleitet. Andernfalls wird der Zugriff verweigert (HTTP 401/403).

* **Format:** `"Suffix" = "Rolle"`
  
  **Beispiel in der `Config.toml`:**
  ```toml
  [oid_mapping]
  # Mapping der OID-Suffixe auf interne Rollen
  "1" = "Admin"
  "2" = "Operator"
  "3" = "Viewer"
  "4" = "Guest"
  ```

* **Mögliche Rollen:**
  * `"Admin"`: Voller Zugriff auf administrative Endpunkte.
  * `"Operator"`: Eingeschränkter Zugriff auf operative Endpunkte.
  * `"Viewer"`: Nur-Lese-Zugriff.
  * `"Guest"`: Standardrolle für unidentifizierte Clients oder Fallback, wenn keine gültige OID vorliegt.

#### Client-Zertifikate mit OIDs generieren
Um selbst gültige Client-Zertifikate für Test- oder Produktionszwecke zu erstellen, liegt dem Projekt das Skript [`client_certs/generate_mtls_oid_certs.sh`](file:///Users/fredi/Data/Projekte/Rust/260225_Tower_Hyper_Rustls_refactor_client_gprc/client_certs/generate_mtls_oid_certs.sh) bei.

**Was macht das Skript?**
1. Es liest vollautomatisch die `pki_base_oid` aus Ihrer aktuellen `Config.toml` aus (z.B. `1.3.6.1.4.1.65111`).
2. Es generiert eine lokale Root-CA (`ca.cert.pem`), die Sie später im Server als Trust-Anchor (`Server.mtls_client_ca_file`) hinterlegen können.
3. Es injiziert die OID-Suffixe dynamisch in das neue Zertifikat. Zum Beispiel baut es das Suffix `.1` zusammen (`1.3.6.1.4.1.65111.1`).
4. Da in Ihrer `Config.toml` definiert ist, dass `"1" = "Admin"` bedeutet, bekommt das erstellte Zertifikat durch diese OID automatisch Admin-Rechte auf dem Proxy!
5. Am Ende spuckt das Skript eine `client.p12` Datei aus, die Sie direkt in Postman, cURL oder den Browser importieren können.

---

## Server-Instanzen (`[[Server]]`)

Sie können mehrere `[[Server]]`-Blöcke definieren, um mehrere Listener gleichzeitig zu betreiben (z. B. einen für API, einen für Onboarding).

### Netzwerkkonfiguration & Basis

| Parameter | Datentyp | Beschreibung | Mögliche Werte |
| :--- | :--- | :--- | :--- |
| `name` | String | Eindeutiger Name der Instanz (für Logs und Metriken). | **Beispiel:** `"first_server"` |
| `ip` | String | Die IP-Adresse, an die gebunden wird. | `"0.0.0.0"` (alle), `"192.168.x.x"`, `"local"` (automatische lokale IP) |
| `port` | Integer | Der TCP-Port des Listeners. | **Beispiel:** `1336` |
| `enabled` | Boolean | Hauptschalter, um den Server ein- oder auszuschalten. | `true`, `false` (**Standard:** `true`) |
| `protocol` | String | Transportprotokoll. (Bei `https` muss `[Server.server_certs]` konfiguriert werden). | `"http"`, `"https"` (**Standard:** `"http"`) |
| `authentication` | String | Authentifizierungsmethode für eingehende Verbindungen. | `"None"` (Öffentlich)<br>`"ClientCert"` oder `"mTLS"` (Zertifikatsbasiert)<br>`"JWT"` (Tokenbasiert) |
| `service` | String | Der Basisservice, der die Anfrage nach der Middleware verarbeitet. | `"Echo"` (Gibt Anfrage zurück)<br>`"Router"` (Reverse-Proxy) |

### Zertifikatskonfigurationen (TLS & mTLS)

#### `[Server.server_certs]` (Erforderlich bei `protocol = "https"`)
* `ssl_certificate`: String. Pfad zur öffentlichen Zertifikatsdatei (PEM oder Fullchain).
* `ssl_certificate_key`: String. Pfad zur unverschlüsselten privaten Schlüsseldatei (PEM).

#### `[[Server.client_certs]]` (Erforderlich bei `authentication = "ClientCert"`)
Array von Tabellen (mehrere CAs können vertraut werden).
* `ssl_client_ca`: String. Pfad zum CA-Zertifikat, um Client-Zertifikate zu überprüfen.
* `ssl_client_crl`: String (Optional). Pfad zur Certificate Revocation List (Sperrliste).

#### `[Server.client_cert_forwarding]` (Optional)
Diese Konfiguration steuert die sichere Weitergabe von Client-Identitäten an Backend-Server. Sie erfüllt zwei essenzielle Aufgaben:
1. **Security / Header Sanitizing (Schutz vor Spoofing):** Bevor die Anfrage ans Backend geht, entfernt der Proxy strikt alle eingehenden Header, die diesen konfigurierten Namen entsprechen. Dies verhindert, dass ein Angreifer manuell Header (z. B. `x-client-san: <fremde-id>`) an einem öffentlichen Port sendet und sich als jemand anderes ausgibt (Identitäts-Spoofing).
2. **Injection:** Hat sich der Client erfolgreich per mTLS authentifiziert, extrahiert der Proxy das Zertifikat sowie den SAN (Subject Alternative Name) und injiziert diese vertrauenswürdigen Werte unter den angegebenen Headernamen neu in die Anfrage ans Backend.

* `header_cert`: String. HTTP-Header-Name für das URL-codierte Client-Zertifikat.
* `header_san`: String. HTTP-Header-Name für den SAN (Subject Alternative Name).

---

## Middleware Layer (`[Server.Layers]`)

Definiert die Ausführungspipeline der Middleware. Die Layer werden in der angegebenen Reihenfolge abgearbeitet.

* **`enabled`**: Array von Strings. Definiert die aktivierten Layer in der angegebenen Reihenfolge.

### Verfügbare Middleware Layer
Jeder Layer übernimmt eine spezifische Aufgabe im Anfrage-Lebenszyklus:

| Layer-Name | Kurze Erläuterung |
| :--- | :--- |
| `"Timing"` | Misst die Verarbeitungsdauer jeder Anfrage (nützlich für Metriken). |
| `"Counter"` | Zählt die Anzahl der aktuell verarbeiteten Anfragen. |
| `"Logger"` | Protokolliert Details zu Request und Response (z.B. Pfad, Statuscode, IP). |
| `"Inspection"` | Überprüft den URL-Pfad der Anfrage anhand einer Regex-Whitelist und blockiert unerlaubte Aufrufe. |
| `"Compression"` | Komprimiert die HTTP-Antworten (z. B. Gzip), um Bandbreite zu sparen. |
| `"Decompression"` | Dekomprimiert den eingehenden Request-Body (inklusive Schutz vor "Decompression Bombs"). |
| `"RateLimiter:Simple"` | Begrenzt die Anfragen pro Sekunde über ein hartes Limit (Fixed-Window Algorithmus). |
| `"RateLimiter:TokenBucket"` | Erlaubt kurzzeitige Spitzen (Bursts) und füllt das Limit periodisch wieder auf. |
| `"Delay"` | Verzögert jede Anfrage künstlich um eine definierte Zeit (für Debugging / Throttling). |
| `"JwtAuth"` | Prüft die Authentifizierung über ein JSON Web Token im `Authorization`-Header. |
| `"ConcurrencyLimit"` | Begrenzt die maximale Anzahl an gleichzeitigen Verbindungen in der Verarbeitung (Überlastungsschutz). |
| `"MaxPayload"` | Verwirft Anfragen, deren Request-Body eine festgelegte Bytegröße überschreitet. |
| `"AltSvc"` | Injiziert den `Alt-Svc`-Header in Antworten, um dem Client mitzuteilen, dass HTTP/3 (QUIC) verfügbar ist. |

Zusätzliche Konfigurationsblöcke für spezifische Layer:

#### `[Server.Layers.Decompression]`
* `max_decompressed_bytes`: Integer. Maximale Größe des dekomprimierten Bodys in Bytes (Schutz vor Decompression Bombs).

#### `[Server.Layers.MaxPayload]`
* `max_bytes`: Integer. Maximale erlaubte Payload-Größe in Bytes.

#### `[Server.Layers.ConcurrencyLimit]`
* `max_concurrent_requests`: Integer. Maximale Anzahl an gleichzeitigen Verbindungen in der Verarbeitung.

#### `[Server.Layers.JWT]`
* `jwt_public_keys`: Array von Strings. Dateipfade zu öffentlichen Schlüsseln (PEM), um JWT-Signaturen zu prüfen.

#### `[Server.Layers.RateLimiter]` (Simple)
* `requests_per_second`: Integer. Striktes Limit der Anfragen pro Sekunde.

#### `[Server.Layers.TokenBucketRateLimiter]`
* `max_capacity`: Integer. Maximale Burst-Größe (Anzahl Tokens).
* `refill`: Integer. Anzahl hinzugefügter Tokens pro Intervall.
* `duration_micros`: Integer. Nachfüll-Intervall in Mikrosekunden.

#### `[Server.Layers.Delay]`
* `delay_micros`: Integer. Verzögert jede Anfrage künstlich (für Debugging).

---

## Inspection Layer (Pfad-Whitelist)

Wenn der `Inspection`-Layer aktiviert ist, fungiert er als leichtgewichtige Web Application Firewall (WAF). Er überprüft den URL-Pfad (und Query-String) jeder eingehenden Anfrage anhand von regulären Ausdrücken (Regex). Nur Requests, die explizit erlaubt sind, passieren den Layer. Alle anderen werden sofort mit `403 Forbidden` abgewiesen.

Die Konfiguration ist nach HTTP-Methoden unterteilt:
* `[Server.AllowedPathes.GET]`
* `[Server.AllowedPathes.POST]`
* `[Server.AllowedPathes.PUT]`
* `[Server.AllowedPathes.DELETE]`

### Funktionsweise & Syntax

**Format:** `"/exakter_pfad" = ["Regex1", "Regex2"]`

1. **Der Schlüssel (Linke Seite):** Muss der *exakte* Base-Path der URL sein (ohne Query-Parameter). Der Proxy sucht in seiner internen Map exakt nach diesem String. Ist der Pfad hier nicht gelistet, wird die Anfrage sofort blockiert.
2. **Der Wert (Rechte Seite):** Ist ein Array von regulären Ausdrücken. 
3. **Das Matching:** Der Proxy setzt den Base-Path und den Query-String wieder zusammen (z.B. `/api/search?q=test`) und prüft diesen kompletten String gegen alle im Array definierten regulären Ausdrücke. Sobald *mindestens ein* Regex matcht, wird die Anfrage durchgelassen.

> [!TIP]
> **Warum erlaubt der Schlüssel (Base-Path) keine Regex? (Performance)**
> Dies ist eine bewusste Architekturentscheidung für extrem hohe Performance. Die Schlüssel werden beim Start in eine sogenannte Hash-Map (`HashMap`) geladen. Ein exakter Pfad-Abgleich (`map.get(path)`) in einer Hash-Map benötigt nahezu `0` Rechenzeit ($O(1)$). Würde der Server für den Schlüssel Regex erlauben, müsste er bei *jeder* eingehenden Anfrage eine Schleife über *alle* konfigurierten Routen ziehen und rechenintensive Regex-Operationen durchführen ($O(N)$). Durch den exakten Schlüssel wird die richtige Regex-Liste blitzschnell gefunden, und erst danach wird die (teurere) Regex-Prüfung durchgeführt.

### Beispiele

```toml
[Server.AllowedPathes.GET]
# Erlaubt den Root-Pfad "/" und optional einen Query-Parameter "name" (z.B. /?name=Fredi)
"/" = ["^/?$", "^/\\?name=.*$"]

# Erlaubt den Pfad "/name", aber NUR wenn zwingend eine numerische ID übergeben wird (z.B. /name?id=123).
# Erklärung zur Syntax "\\?id":
# 1. '\\'   : In TOML muss ein Backslash verdoppelt werden.
# 2. '\\?'  : Entspricht im Regex '\?', was für ein zwingendes wörtliches Fragezeichen (in der URL) steht.
"/name" = ["^/name\\?id=\\d+$"]

[Server.AllowedPathes.POST]
# Bei gRPC-Aufrufen gibt es normalerweise keine Query-Parameter.
# ".*" erlaubt hier schlichtweg alles auf diesem exakten Pfad.
"/chat.ChatService/SendMessage" = [".*"]
```

---

## Reverse Proxy Routing (`[Server.ReverseRoutes."/prefix"]`)

*Dieser Abschnitt ist nur aktiv, wenn für die Server-Instanz `service = "Router"` gesetzt ist.*

Ein Reverse-Proxy nimmt eingehende Anfragen von Clients entgegen und leitet sie – für den Client völlig transparent – an einen oder mehrere Hintergrund-Server (Upstreams) weiter. Die Antwort des Hintergrund-Servers wird anschließend über den Proxy an den Client zurückgespielt. Dies ist das Herzstück des Gateways und ermöglicht zentrale Authentifizierung, intelligente Lastverteilung (Load Balancing) und Ausfallsicherheit.

### Wie funktioniert das Prefix-Routing?
Jeder Block definiert eine Route basierend auf einem URL-Präfix (der Pfad, der in eckigen Klammern steht). Wenn ein Request eingeht, vergleicht der Proxy den Pfad mit allen konfigurierten Routen und wählt **immer den längsten (spezifischsten) Match**.

* **Beispiel:** Sie konfigurieren zwei Routen: `[Server.ReverseRoutes."/"]` (Catch-All) und `[Server.ReverseRoutes."/api/v1"]`.
* Eine Anfrage an `/api/v1/users` wird von der spezifischen Route `/api/v1` verarbeitet.
* Eine Anfrage an `/help` fällt auf den Catch-All `/` zurück.

### Kernfunktionen pro Route
Jede Route agiert isoliert und bietet vier wesentliche Funktionen:
1. **Load Balancing:** Sie können ein Array von Backend-Servern (Upstreams) angeben. Der Traffic wird nach einer gewählten Strategie auf diese verteilt.
2. **Health-Checks:** Der Proxy kann tote Server dynamisch erkennen, sie für eine Zeit (Cooldown) pausieren und bei Wiedererreichbarkeit automatisch wieder in die Rotation aufnehmen.
3. **Autorisierung (RBAC):** Sie können Routen auf spezifische Rollen (siehe `[oid_mapping]`) begrenzen.
4. **URL-Stripping:** Der konfigurierte Präfix wird beim Weiterleiten (Forwarding) aus der URL *entfernt* und durch den Pfad des Backend-Servers ersetzt.
   * *Beispiel:* Ein Request an `/api/v1/users` (Präfix `/api/v1`) wird an einen Upstream mit der Adresse `http://backend:8080/` als `http://backend:8080/users` weitergeleitet. 
   * Ein Request an `/help` (Präfix `/`) geht entsprechend als `/help` ans Backend.

### Parameter einer Route

| Parameter | Datentyp | Beschreibung | Mögliche Werte |
| :--- | :--- | :--- | :--- |
| `upstreams` | Array | Liste der Backend-Server-URLs. <br><br>**Hinweis:** Wenn mehr als ein Server angegeben wird, betreibt der Proxy automatisch Load Balancing zwischen diesen Servern. | **Beispiel:** `["https://backend1:50051", "https://backend2:50051"]` |
| `strategy` | String | Lastverteilungsstrategie. | `"RoundRobin"` (Standard, sequentiell)<br>`"LeastConnections"` (Wenigste aktive Verbindungen)<br>`"Random"` (Zufällig)<br>`"Sticky"` (Hash auf Client-IP)<br>`"HighestScore"` (Basierend auf Health-Checks) |
| `backend_type` | String | Art des Backends. | `"rest"` (Standard HTTP)<br>`"grpc_passthrough"` (Reines gRPC/HTTP2)<br>`"grpc"` (gRPC mit JSON-Transcoding) |
| `allowed_roles` | Array | **RBAC (Role-Based Access Control):** Legt fest, welche Rollen auf diese Route zugreifen dürfen. <br><br>• Ist das Array **leer** `[]`, ist die Route komplett öffentlich (die Autorisierungsprüfung wird übersprungen).<br>• Werden Rollen eingetragen (z.B. `["Admin", "Operator"]`), muss der Client exakt eine dieser Rollen zugewiesen bekommen haben. **Achtung: Das System ist nicht hierarchisch!** Ein Client mit Rolle `"Admin"` darf *nicht* automatisch auf Routen zugreifen, bei denen *nur* `"Guest"` steht, es sei denn, Sie tragen explizit `["Admin", "Guest"]` ein. | `["Admin", "Operator", "Viewer", "Guest"]` |
| `active_health_check_interval` | Integer | Intervall in Sekunden für aktives Polling. `0` bedeutet deaktiviert. | **Beispiel:** `15` |
| `grpc_pool_refresh_secs` | Integer | (Nur bei Typ `"grpc"`) Wie oft das gRPC-Reflection-Schema im Hintergrund aktualisiert werden soll. | `60` |
| `cooldown_seconds` | Integer | Dauer in Sekunden, wie lange ein toter Knoten nicht angesteuert wird. | **Standard:** `10` |
| `max_retries` | Integer | Maximale automatische Wiederholungsversuche bei fehlgeschlagenen Anfragen. | **Standard:** `2` |


#### Exkurs: Backend-Typen (`backend_type`)
Die Wahl des Backend-Typs entscheidet maßgeblich darüber, wie der Proxy mit den Datenströmen umgeht, insbesondere wenn das Backend ein gRPC-Server ist:

* **`"rest"`:** Standardverhalten für klassische Webserver und REST-APIs. Die HTTP-Aufrufe (inkl. Header und Body) werden 1:1 weitergereicht.
* **`"grpc_passthrough"`:** Reines Durchleiten von gRPC. 
  * *Client:* Muss ein echter gRPC-Client sein (spricht HTTP/2 und Protobuf).
  * *Verhalten:* Der Proxy leitet die reinen gRPC-Frames auf TCP/HTTP2-Ebene an das Backend durch, ohne in den Payload zu schauen oder diesen zu verändern. Das ist extrem schnell und performant.
* **`"grpc"` (JSON-Transcoding):** Der Proxy agiert als Übersetzer zwischen der REST/JSON-Welt und der gRPC-Welt.
  * *Client:* Kann ein normaler Webbrowser, ein Frontend (JavaScript/Fetch) oder `curl` sein, der normales HTTP(s) mit JSON spricht.
  * *Verhalten:* Der Proxy empfängt den JSON-Request, übersetzt ihn "on the fly" in das binäre Protobuf-Format (anhand des vom Server per Reflection geladenen Schemas) und sendet es per HTTP/2 an den gRPC-Server. Die gRPC-Antwort des Servers wird vom Proxy wieder in lesbares JSON übersetzt und an den Client zurückgeschickt. Das ermöglicht es, moderne gRPC-Backends ohne spezielle Client-Bibliotheken anzusprechen.

### Health-Checks & Ausfallsicherheit

Der Proxy schützt Ihre Anwendungen durch zwei kombinierte Überwachungssysteme, um Ausfälle von Backend-Servern (Upstreams) abzufangen und den Traffic intelligent umzuleiten:

**1. Passive Health-Checks (Circuit Breaker)**
Dieses System ist immer automatisch aktiv, sobald Traffic fließt.
* Wenn der Proxy eine Anfrage an ein Backend sendet und dieses nicht erreichbar ist (z.B. Connection Refused oder Timeout), wird der Fehler sofort registriert.
* Das Backend wird als "tot" markiert und für die Dauer von `cooldown_seconds` (Standard: 10s) auf die "Ersatzbank" gesetzt. Der Load-Balancer leitet in dieser Zeit keine neuen Anfragen dorthin.
* Nach Ablauf der Cooldown-Phase bekommt das Backend eine neue Chance ("Half-Open" State) und die nächste reguläre Anfrage wird wieder versuchsweise dorthin geleitet.
* **Failover (`max_retries`):** Wenn ein Backend genau während einer Kundenanfrage ausfällt, bricht der Proxy nicht einfach ab. Er fängt den Fehler auf und schickt die Kundenanfrage automatisch an das nächste gesunde Backend in der Liste. Der Parameter `max_retries` (Standard: 2) steuert, wie oft das versucht wird. Für den Kunden ist der Server-Ausfall so völlig unsichtbar.

**2. Aktive Health-Checks (Background Polling)**
Diese Funktion wird aktiviert, indem Sie `active_health_check_interval` auf einen Wert größer 0 setzen (z.B. `15`).
* Der Proxy startet dann im Hintergrund für jedes Backend einen asynchronen Task, der (im Beispiel alle 15 Sekunden) proaktiv die Erreichbarkeit prüft, auch wenn gerade kein Kunden-Traffic anliegt.
* **REST-Backends:** Es wird automatisch ein HTTP-GET-Request auf den Pfad `/health` des Backend-Servers gesendet.
* **gRPC-Backends:** Der Proxy nutzt "gRPC Server Reflection", um das Schema des Servers zu laden. Er durchsucht dabei alle angebotenen Services nach einer Methode, die exakt den Namen `health` trägt (z.B. `/MyService/health`). Findet er diese Methode, wird sie zyklisch mit einem leeren Protobuf-Payload angepingt. Findet er keine solche Methode, wird der aktive Health-Check für diesen Knoten übersprungen.
* **Health-Score (Wichtig für die `HighestScore` Strategie):** Der Proxy wertet nicht nur den HTTP-Statuscode aus, sondern liest auch die Payload der Health-Check-Antwort, um den Servern einen "Score" zuzuweisen.
  * *Bei REST:* Das Backend muss ein JSON-Objekt zurückgeben: `{"score": 100}`.
  * *Bei gRPC:* Die Methode muss eine Protobuf-Message zurückgeben, deren allererstes Feld (Field Tag 1) ein Integer ist (z.B. `uint32 score = 1;`).
  * *Bedeutung & Wertebereich:* Ein Score von `0` markiert den Server sofort als tot (unhealthy). Bei einem Wert `> 0` gilt er als gesund. Es wird **für beide Protokolle dringend ein Wertebereich von 0 bis 100** (z.B. analog zu Prozent) empfohlen. (Hinweis: Der interne gRPC-Parser wertet aus Performancegründen das Protobuf-Feld aktuell nur aus dem ersten Byte aus, weshalb gRPC-Scores technisch ohnehin nicht größer als 127 sein dürfen).
  * Wenn Sie beim Load Balancing die Strategie `"HighestScore"` gewählt haben, leitet der Proxy neue Anfragen immer an den Server weiter, der beim letzten Check den höchsten Wert gemeldet hat (nützlich, um Server nach ihrer aktuellen CPU-Auslastung zu priorisieren).
* **Vorteil:** Tote Server werden erkannt, noch bevor ein Kunde überhaupt versucht darauf zuzugreifen. Ist ein toter Server beim nächsten proaktiven Ping wieder erreichbar, wird er sofort und ohne Risiko wieder in den Load-Balancer aufgenommen.



### Upstream Connection Parameters (`[Server.RouterParams]`)

Konfiguriert die ausgehende Verbindung des Proxys zu den Backend-Servern.

| Parameter | Datentyp | Beschreibung | Mögliche Werte / Beispiel |
| :--- | :--- | :--- | :--- |
| `protocol` | String | Protokoll für ausgehende Verbindungen. | `"http"`, `"https"` |
| `authentication` | String | Auth-Methode, die der Proxy gegenüber dem Backend nutzt. | `"None"`, `"ClientCert"`, `"JWT"` |
| `ssl_root_certificate` | String | Pfad zum CA-Zertifikat zur Überprüfung des Backend-Zertifikats. | `"/pfad/zur/ca.pem"` |
| `ssl_client_certificate` | String | Proxy Client-Zertifikat für mTLS zum Backend. | `"/pfad/zum/proxy-client.pem"` |
| `ssl_client_key` | String | Proxy Private Key für mTLS zum Backend. | `"/pfad/zum/proxy-client.key"` |
| `jwt` | String | Pfad zu einer JWT-Datei, die bei `authentication = "JWT"` ans Backend gesendet wird. | `"/pfad/zum/token.jwt"` |
