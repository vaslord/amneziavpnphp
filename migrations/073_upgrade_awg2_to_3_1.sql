-- Upgrade the compatible AWG2 protocol recipe to AmneziaWG 3.1.
-- Existing servers change only when the administrator explicitly selects reinstall.

UPDATE protocols
SET output_template = '[Interface]
Address = {{client_ip}}/32
DNS = {{dns_servers}}
PrivateKey = {{private_key}}
Jc = {{Jc}}
Jmin = {{Jmin}}
Jmax = {{Jmax}}
S1 = {{S1}}
S2 = {{S2}}
S3 = {{S3}}
S4 = {{S4}}
H1 = {{H1}}
H2 = {{H2}}
H3 = {{H3}}
H4 = {{H4}}
I1 = {{I1}}
I2 = {{I2}}
I3 = {{I3}}
I4 = {{I4}}
I5 = {{I5}}
{{awg3_interface_params}}
[Peer]
PublicKey = {{server_public_key}}
PresharedKey = {{preshared_key}}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{server_host}}:{{server_port}}
PersistentKeepalive = 25',
    install_script = '#!/bin/bash
set -euo pipefail

CONTAINER_NAME="${SERVER_CONTAINER:-amnezia-awg2}"
IMAGE="amnezia-awg2:v3.1.20260828"
SOURCE_DIR="/opt/amnezia/awg2/src"
CONFIG_DIR="/opt/amnezia/awg2"
CONF_FILE="$CONFIG_DIR/awg0.conf"
PORT_RANGE_START=${PORT_RANGE_START:-30000}
PORT_RANGE_END=${PORT_RANGE_END:-65000}
VPN_PORT="${SERVER_PORT:-$((RANDOM % (PORT_RANGE_END - PORT_RANGE_START + 1) + PORT_RANGE_START))}"

if ! command -v git >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1
fi
mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONF_FILE" ] && docker ps -aq --format "{{.Names}}" | grep -Fxq "$CONTAINER_NAME"; then
  docker cp "$CONTAINER_NAME:/opt/amnezia/awg/awg0.conf" "$CONF_FILE" 2>/dev/null || true
  docker cp "$CONTAINER_NAME:/opt/amnezia/awg/wireguard_server_private_key.key" "$CONFIG_DIR/wireguard_server_private_key.key" 2>/dev/null || true
  docker cp "$CONTAINER_NAME:/opt/amnezia/awg/wireguard_server_public_key.key" "$CONFIG_DIR/wireguard_server_public_key.key" 2>/dev/null || true
  docker cp "$CONTAINER_NAME:/opt/amnezia/awg/wireguard_psk.key" "$CONFIG_DIR/wireguard_psk.key" 2>/dev/null || true
fi

if [ ! -d "$SOURCE_DIR/.git" ]; then
  rm -rf "$SOURCE_DIR"
  git clone --depth=1 --branch v3.1.20260828 https://github.com/amnezia-vpn/amneziawg-go.git "$SOURCE_DIR"
else
  git -C "$SOURCE_DIR" fetch --depth=1 origin tag v3.1.20260828
  git -C "$SOURCE_DIR" checkout --force v3.1.20260828
fi
docker build --no-cache -t "$IMAGE" "$SOURCE_DIR"

set_interface_value() {
  key="$1"
  value="$2"
  sed -i -E "/^[[:space:]]*${key}[[:space:]]*=/d" "$CONF_FILE"
  sed -i "0,/^[[]Peer[]]/{s|^[[]Peer[]]|${key} = ${value}\\n[Peer]|}" "$CONF_FILE"
  if ! grep -q "^[[:space:]]*${key}[[:space:]]*=" "$CONF_FILE"; then
    printf "%s = %s\\n" "$key" "$value" >> "$CONF_FILE"
  fi
}

if [ ! -f "$CONF_FILE" ]; then
  PRIVATE_KEY=$(docker run --rm "$IMAGE" awg genkey)
  PUBLIC_KEY=$(printf "%s" "$PRIVATE_KEY" | docker run -i --rm "$IMAGE" awg pubkey)
  PRESHARED_KEY=$(docker run --rm "$IMAGE" awg genpsk)
  HEADER_KEY=$(docker run --rm "$IMAGE" awg genkey)
  cat > "$CONF_FILE" <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.1.1/24
ListenPort = $VPN_PORT
Jc = 5
Jmin = 10
Jmax = 50
S1 = 51
S2 = 125
S3 = 13
S4 = 12
H1 = 1443912531-1981073285
H2 = 1984025557-2135018048
H3 = 2145217268-2146643749
H4 = 2146790761-2146860793
I1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>
HeaderProtectionKey = $HEADER_KEY
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF
  printf "%s\\n" "$PRIVATE_KEY" > "$CONFIG_DIR/wireguard_server_private_key.key"
  printf "%s\\n" "$PUBLIC_KEY" > "$CONFIG_DIR/wireguard_server_public_key.key"
  printf "%s\\n" "$PRESHARED_KEY" > "$CONFIG_DIR/wireguard_psk.key"
  printf "[]\\n" > "$CONFIG_DIR/clientsTable"
else
  VPN_PORT=$(sed -n -E "s/^[[:space:]]*ListenPort[[:space:]]*=[[:space:]]*//p" "$CONF_FILE" | head -1)
  [ -n "$VPN_PORT" ] || VPN_PORT="${SERVER_PORT:-51820}"
  HEADER_KEY=$(sed -n -E "s/^[[:space:]]*HeaderProtectionKey[[:space:]]*=[[:space:]]*//p" "$CONF_FILE" | head -1)
  [ -n "$HEADER_KEY" ] || HEADER_KEY=$(docker run --rm "$IMAGE" awg genkey)
  for item in "S1 51" "S2 125" "S3 13" "S4 12"; do
    set -- $item
    current=$(sed -n -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONF_FILE" | head -1)
    if ! [[ "$current" =~ ^[0-9]+$ ]] || [ "$current" -lt 12 ]; then set_interface_value "$1" "$2"; fi
  done
  set_interface_value HeaderProtectionKey "$HEADER_KEY"
  set_interface_value ContentPaddingAddition 10-100
  set_interface_value RekeyAfterTime 100-120
  set_interface_value RekeyTimeout 3-7
  set_interface_value RejectAfterTime 150-180
  set_interface_value KeepaliveTimeout 5-15
  set_interface_value MaxHandshakeAttempts 15-20
fi

PRIVATE_KEY=$(cat "$CONFIG_DIR/wireguard_server_private_key.key" 2>/dev/null || sed -n -E "s/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//p" "$CONF_FILE" | head -1)
PUBLIC_KEY=$(cat "$CONFIG_DIR/wireguard_server_public_key.key" 2>/dev/null || printf "%s" "$PRIVATE_KEY" | docker run -i --rm "$IMAGE" awg pubkey)
PRESHARED_KEY=$(cat "$CONFIG_DIR/wireguard_psk.key" 2>/dev/null || true)
printf "%s\\n" "$PRIVATE_KEY" > "$CONFIG_DIR/wireguard_server_private_key.key"
printf "%s\\n" "$PUBLIC_KEY" > "$CONFIG_DIR/wireguard_server_public_key.key"
[ -n "$PRESHARED_KEY" ] && printf "%s\\n" "$PRESHARED_KEY" > "$CONFIG_DIR/wireguard_psk.key"

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER_NAME" --restart always --cap-add=NET_ADMIN --device /dev/net/tun -p "${VPN_PORT}:${VPN_PORT}/udp" -v "$CONFIG_DIR:/opt/amnezia/awg" "$IMAGE" sh -ec "WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go awg-quick up /opt/amnezia/awg/awg0.conf; exec sleep infinity" >/dev/null
READY=0
for attempt in $(seq 1 15); do
  if docker exec "$CONTAINER_NAME" awg show awg0 >/dev/null 2>&1 && docker exec "$CONTAINER_NAME" sh -c "ss -uln 2>/dev/null | grep -Eq '':${VPN_PORT}([[:space:]]|$)''"; then READY=1; break; fi
  sleep 1
done
if [ "$READY" != 1 ]; then
  docker logs "$CONTAINER_NAME" >&2 || true
  echo "AWG3 interface or UDP listener did not become ready" >&2
  exit 1
fi

EXTERNAL_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
echo "AmneziaWG 3.1 installed successfully"
echo "Port: $VPN_PORT"
echo "Server Public Key: $PUBLIC_KEY"
echo "PresharedKey = $PRESHARED_KEY"
echo "Server Host: $EXTERNAL_IP"
for P in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 HeaderProtectionKey ContentPaddingAddition RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies; do
  VAL=$(sed -n -E "s/^[[:space:]]*$P[[:space:]]*=[[:space:]]*//p" "$CONF_FILE" | head -1)
  [ -n "$VAL" ] && echo "Variable: $P=$VAL"
done
echo "Variable: dns_servers=1.1.1.1, 1.0.0.1"'
WHERE slug = 'awg2';

UPDATE protocols
SET definition = JSON_MERGE_PATCH(COALESCE(definition, JSON_OBJECT()), JSON_OBJECT('metadata', JSON_OBJECT('awg_version', '3.1', 'awg_go_tag', 'v3.1.20260828')))
WHERE slug = 'awg2';

INSERT INTO protocol_variables (protocol_id, variable_name, variable_type, default_value, description, required)
SELECT p.id, v.variable_name, 'text', v.default_value, v.description, false
FROM protocols p
JOIN (
  SELECT 'HeaderProtectionKey' AS variable_name, '' AS default_value, 'Shared AWG 3.1 header protection key' AS description
  UNION ALL SELECT 'ContentPaddingAddition', '10-100', 'AWG 3.1 content padding range'
  UNION ALL SELECT 'RekeyAfterTime', '100-120', 'AWG 3.1 rekey interval range'
  UNION ALL SELECT 'RekeyTimeout', '3-7', 'AWG 3.1 rekey timeout range'
  UNION ALL SELECT 'RejectAfterTime', '150-180', 'AWG 3.1 reject-after interval range'
  UNION ALL SELECT 'KeepaliveTimeout', '5-15', 'AWG 3.1 keepalive timeout range'
  UNION ALL SELECT 'MaxHandshakeAttempts', '15-20', 'AWG 3.1 handshake attempt range'
  UNION ALL SELECT 'RandomTrailers', '', 'Optional AWG 3.1 random trailers'
  UNION ALL SELECT 'DisableCookies', '', 'Optional AWG 3.1 cookie suppression'
) v
WHERE p.slug = 'awg2'
  AND NOT EXISTS (SELECT 1 FROM protocol_variables pv WHERE pv.protocol_id = p.id AND pv.variable_name = v.variable_name);
