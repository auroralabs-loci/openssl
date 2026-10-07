#!/bin/sh
# Generate test certificates for EAI name constraint tests.
# Run with the system openssl (not the one being built).

OPENSSL=${OPENSSL:-openssl}
DIR=$(dirname "$0")

# --- Test 1: leading-dot base constraint (.example.com) ---
# CA with nameConstraints = permitted;email:.example.com

$OPENSSL req -x509 -new -newkey rsa:2048 -nodes \
    -keyout "$DIR/nc-eai-dotbase-key.pem" \
    -subj "/CN=NC EAI Dot Base CA" \
    -days 36500 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "nameConstraints=critical,permitted;email:.example.com" \
    -out "$DIR/nc-eai-dotbase-root.pem" 2>/dev/null

# Leaf with SmtpUTF8Mailbox SAN: user@sub.example.com
$OPENSSL req -new -newkey rsa:2048 -nodes \
    -keyout "$DIR/nc-eai-dotbase-leaf-key.pem" \
    -subj "/CN=NC EAI Dot Base Leaf" \
    -addext "subjectAltName=otherName:1.3.6.1.5.5.7.8.9;UTF8:user@sub.example.com" \
    -out "$DIR/nc-eai-dotbase-leaf.csr" 2>/dev/null

$OPENSSL x509 -req -in "$DIR/nc-eai-dotbase-leaf.csr" \
    -CA "$DIR/nc-eai-dotbase-root.pem" \
    -CAkey "$DIR/nc-eai-dotbase-key.pem" \
    -CAcreateserial \
    -days 36500 \
    -copy_extensions copyall \
    -out "$DIR/nc-eai-dotbase-leaf.pem" 2>/dev/null

# --- Test 2: full email base constraint (testuser@example.com) ---
# CA with nameConstraints = permitted;email:testuser@example.com

$OPENSSL req -x509 -new -newkey rsa:2048 -nodes \
    -keyout "$DIR/nc-eai-atbase-key.pem" \
    -subj "/CN=NC EAI At Base CA" \
    -days 36500 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "nameConstraints=critical,permitted;email:testuser@example.com" \
    -out "$DIR/nc-eai-atbase-root.pem" 2>/dev/null

# Leaf with SmtpUTF8Mailbox SAN: testuser@example.com
$OPENSSL req -new -newkey rsa:2048 -nodes \
    -keyout "$DIR/nc-eai-atbase-leaf-key.pem" \
    -subj "/CN=NC EAI At Base Leaf" \
    -addext "subjectAltName=otherName:1.3.6.1.5.5.7.8.9;UTF8:testuser@example.com" \
    -out "$DIR/nc-eai-atbase-leaf.csr" 2>/dev/null

$OPENSSL x509 -req -in "$DIR/nc-eai-atbase-leaf.csr" \
    -CA "$DIR/nc-eai-atbase-root.pem" \
    -CAkey "$DIR/nc-eai-atbase-key.pem" \
    -CAcreateserial \
    -days 36500 \
    -copy_extensions copyall \
    -out "$DIR/nc-eai-atbase-leaf.pem" 2>/dev/null

# --- Test 3: negative test - wrong local part against full email constraint ---
# Leaf with SmtpUTF8Mailbox SAN: wronguser@example.com, signed by atbase CA
# Should FAIL because name constraint only permits testuser@example.com

$OPENSSL req -new -newkey rsa:2048 -nodes \
    -keyout "$DIR/nc-eai-atbase-wrong-key.pem" \
    -subj "/CN=NC EAI At Base Wrong Leaf" \
    -addext "subjectAltName=otherName:1.3.6.1.5.5.7.8.9;UTF8:wronguser@example.com" \
    -out "$DIR/nc-eai-atbase-wrong.csr" 2>/dev/null

$OPENSSL x509 -req -in "$DIR/nc-eai-atbase-wrong.csr" \
    -CA "$DIR/nc-eai-atbase-root.pem" \
    -CAkey "$DIR/nc-eai-atbase-key.pem" \
    -CAcreateserial \
    -days 36500 \
    -copy_extensions copyall \
    -out "$DIR/nc-eai-atbase-wrong-leaf.pem" 2>/dev/null

# Clean up intermediate files
rm -f "$DIR"/*.csr "$DIR"/*-key.pem "$DIR"/*.srl

echo "Generated test certificates in $DIR:"
ls -1 "$DIR"/nc-eai-*.pem
