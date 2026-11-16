#!/usr/bin/env bash
# Writes a local flood deployment: hosts.yaml and one <public key>.yaml config per peer, in the
# shapes the deployer and `setup` write. Peer i gets the loopback address 127.0.0.<i+1> and, like
# every flood peer, port 4545. Keys are fresh ed25519 keys from openssl.
#   examples/flood/local.sh <peers> <directory> [message-size] [message-rate]
set -euo pipefail

peers=${1:?usage: local.sh <peers> <directory> [message-size] [message-rate]}
dir=${2:?usage: local.sh <peers> <directory> [message-size] [message-rate]}
message_size=${3:-1024}
message_rate=${4:-200}
mkdir -p "$dir"

hex_tail() { tail -c 32 | od -An -v -tx1 | tr -d ' \n'; }

private=()
public=()
for ((i = 0; i < peers; i++)); do
  pem=$(openssl genpkey -algorithm ed25519 2>/dev/null)
  private+=("$(printf '%s\n' "$pem" | openssl pkey -outform DER | hex_tail)")
  public+=("$(printf '%s\n' "$pem" | openssl pkey -pubout -outform DER | hex_tail)")
done

{
  printf 'monitoring:\n  public: 127.0.0.1\n  private: 127.0.0.1\nhosts:\n'
  for ((i = 0; i < peers; i++)); do
    printf -- '- name: %s\n  region: local\n  ip: 127.0.0.%d\n' "${public[i]}" $((i + 1))
  done
} >"$dir/hosts.yaml"

for ((i = 0; i < peers; i++)); do
  {
    printf 'private_key: %s\nport: 4545\nallowed_peers:\n' "${private[i]}"
    for key in "${public[@]}"; do printf -- '- %s\n' "$key"; done
    printf 'bootstrappers:\n- %s\n' "${public[0]}"
    printf 'worker_threads: 2\nmessage_size: %d\nmessage_rate: %d\n' "$message_size" "$message_rate"
    printf 'mailbox_size: 16384\ninstrument: false\n'
  } >"$dir/${public[i]}.yaml"
  echo "$dir/${public[i]}.yaml"
done
