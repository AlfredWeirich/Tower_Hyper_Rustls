#!/bin/bash
set -e

# ==============================================================================
# mTLS Zertifikats-Generator mit Custom OIDs
# 
# Dieses Skript generiert ein lokales Root-CA (falls noch nicht vorhanden)
# und erstellt ein Client-Zertifikat, in welches benutzerdefinierte
# OID-Erweiterungen (Object Identifiers) geschrieben werden.
# Diese OIDs werden vom Reverse-Proxy für die Rollenzuweisung (RBAC) genutzt.
# ==============================================================================

# === 1. Konfiguration laden ===
# Wir lesen die Base-OID dynamisch aus der zentralen Config.toml aus, 
# damit Proxy und generierte Zertifikate immer die gleiche Basis verwenden.
CONFIG_FILE="/Users/fredi/Data/Projekte/Rust/260225_Tower_Hyper_Rustls_refactor_client_gprc/Config.toml"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Fehler: $CONFIG_FILE nicht gefunden!"
    exit 1
fi

# Extraktion der pki_base_oid mit grep und sed (z.B. "1.3.6.1.4.1.65111")
BASE_OID=$(grep "pki_base_oid" "$CONFIG_FILE" | sed -E 's/.*"([0-9.]+)"/\1/')

if [ -z "$BASE_OID" ]; then
    echo "❌ Fehler: pki_base_oid konnte in $CONFIG_FILE nicht gefunden werden!"
    exit 1
fi

# === 2. Parameter-Parsing ===
CN="client.weirich"
EMAIL="alfred.weirich@gmail.com"
SUFFIXES="1" # Standard: Suffix 1

while getopts "c:e:o:h" flag; do
    case "${flag}" in
        c) CN=${OPTARG};;
        e) EMAIL=${OPTARG};;
        o) SUFFIXES=${OPTARG};;
        h) 
           echo "Verwendung: $0 [-c <CommonName>] [-e <Email>] [-o <OID-Suffixe (kommagetrennt)>]"
           echo "Beispiel: $0 -c max.mustermann -e max@test.com -o 1,3"
           exit 0
           ;;
    esac
done

CA_KEY="ca.key.pem"
CA_CERT="ca.cert.pem"
CLIENT_KEY="client.key.pem"
CLIENT_CSR="client.csr.pem"
CLIENT_CERT="client.cert.pem"
CLIENT_EXT="client_ext.cnf"

echo "▶️ OID Basis: $BASE_OID"

# === 3. Zertifikatserstellung ===

# Schritt 3.1: Generiere die Root-CA (Certificate Authority), falls sie nicht existiert.
# Diese CA muss später im Proxy als "trust_anchor" hinterlegt werden.
if [ ! -f "$CA_KEY" ]; then
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 -out "$CA_CERT" \
    -subj "/C=GE/ST=NRW/L=AC/O=Weirich/OU=dev/CN=MyRootCa/emailAddress=$EMAIL"
fi

# Schritt 3.2: Generiere den privaten Schlüssel für den Client.
openssl genrsa -out "$CLIENT_KEY" 2048

# Schritt 3.3: Erstelle die Konfigurationsdatei für das Client-Zertifikat.
# OIDs werden dynamisch basierend auf dem Parameter -o in das Zertifikat geschrieben.
OID_EXTENSIONS=""

if [ -n "$SUFFIXES" ] && [ "$SUFFIXES" != "none" ]; then
    IFS=',' read -ra SUFFIX_ARRAY <<< "$SUFFIXES"
    for suffix in "${SUFFIX_ARRAY[@]}"; do
        # Der Text "Proxy-RBAC-Role" ist ein Dummy. Der Proxy wertet nur die nackte OID aus.
        OID_EXTENSIONS+="${BASE_OID}.${suffix} = ASN1:UTF8String:Proxy-RBAC-Role
"
    done
fi

cat > "$CLIENT_EXT" <<EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = GE
ST = NRW
L = AC
O = Weirich
OU = dev
CN = $CN

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
$OID_EXTENSIONS
EOF

# Schritt 3.4: Erstelle einen Certificate Signing Request (CSR) mit der Config.
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -config "$CLIENT_EXT"

# Schritt 3.5: Signiere das Client-Zertifikat mit unserer Root-CA.
openssl x509 -req -in "$CLIENT_CSR" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CERT" -days 365 -sha256 \
  -extfile "$CLIENT_EXT" -extensions v3_req

# Schritt 3.6: Exportiere alles komfortabel in eine PKCS12 (.p12) Datei,
# welche in Postman, cURL oder Browsern importiert werden kann.
openssl pkcs12 -export \
  -inkey "$CLIENT_KEY" \
  -in "$CLIENT_CERT" \
  -certfile "$CA_CERT" \
  -out client.p12 \
  -name "Client Certificate" \
  -passout pass:

echo "✅ Fertig. OID Check:"
# Überprüft, ob die OIDs erfolgreich in das fertige Zertifikat geschrieben wurden.
openssl x509 -in "$CLIENT_CERT" -text -noout 