# Option B — Self-Hosted Gotham Testnet (Cloud Always-Free)

A turnkey package to deploy 3 Gotham mixnet relays on Oracle Cloud
(Always Free) + Google Cloud (Always Free) for **0€/month**. You are
the sole operator of all 3 relays, so anonymity-set = 1 against
yourself, but the network is reachable from anywhere and lets the
Crypto app function end-to-end.

This complements **Option D** (embedded relay in every app — see
[`GOTHAM-EMBEDDED.md`](../docs/gotham/README.md)), which is the long-term
goal. Option B is what gets you a working network *today*.

---

## What you get

After completing this guide you will have:

- **2 Oracle Cloud Ampere ARM A1 VMs** (1 OCPU, 6 GB RAM each) in 2
  geographically distinct regions, each running `gotham-relay` as a
  systemd service on UDP/443.
- **1 Google Cloud e2-micro VM** (1/8 vCPU shared, 1 GB RAM) in a US
  region, same setup.
- A **signed `gotham-bootstrap.json`** that the Crypto app reads to
  learn about these 3 relays and route through them.

All three VMs are hardened (no-new-privs, read-only root FS, ufw deny
by default, systemd seccomp filter) — see
[`systemd/crypto-gotham-relay.service`](systemd/crypto-gotham-relay.service).

---

## Prerequisites

On your local machine:

- `terraform` ≥ 1.5
- `cargo` (for signing the directory locally)
- `ssh` and an Ed25519 SSH key at `~/.ssh/id_ed25519`
- An Oracle Cloud account with payment method validated (Always Free
  tier doesn't bill but Oracle requires the card on file)
- A Google Cloud account with billing enabled (same caveat)

---

## Step 1 — Generate a Directory Authority key (one time, local)

This is the key that signs your `gotham-bootstrap.json`. The Crypto
app pins this pubkey, so once you ship it you cannot rotate it
without re-shipping the app. Store the **secret half** somewhere safe
(YubiKey for production; for personal testnets `~/.gotham-authority.key`
with `chmod 0400` is fine).

```bash
cargo run --release -p crypto-gotham-relay --bin gotham-relay -- \
    keygen --key-file ~/.gotham-authority.key
chmod 0400 ~/.gotham-authority.key

# Print the pubkey hex — this is what the app will pin.
cargo run --release -p crypto-gotham-relay --bin gotham-relay -- \
    pubkey --key-file ~/.gotham-authority.key
# Example output: 4f1e8a...d2c9
```

Save the pubkey hex — you'll embed it in the app code in Step 5.

---

## Step 2 — Provision the 2 Oracle Cloud VMs (Terraform)

```bash
# Configure the OCI CLI once. Reads ~/.oci/config thereafter.
oci setup config

cd infra/oracle-cloud
terraform init
terraform apply -var "compartment_ocid=ocid1.tenancy.oc1..<your-tenancy-id>"

# Outputs the two public IPs and the SSH commands.
terraform output
```

Expected output:
```
relay_a_public_ip = "X.X.X.X"
relay_a_ssh       = "ssh ubuntu@X.X.X.X"
relay_b_public_ip = "Y.Y.Y.Y"
relay_b_ssh       = "ssh ubuntu@Y.Y.Y.Y"
```

---

## Step 3 — Provision the Google Cloud VM (Terraform)

```bash
gcloud auth application-default login

cd infra/google-cloud
export TF_VAR_project_id="your-gcp-project-id"
terraform init
terraform apply

terraform output
# relay_c_public_ip = "Z.Z.Z.Z"
```

---

## Step 4 — Install the relay daemon on each VM (~5 min each)

For each of the 3 VMs:

```bash
ssh ubuntu@<VM_IP>
sudo bash -c 'curl -fsSL https://raw.githubusercontent.com/0x9Angel/Crypto/main/infra/scripts/install-relay.sh | bash'
```

OR, if you've cloned the repo:

```bash
scp -r infra ubuntu@<VM_IP>:~/
ssh ubuntu@<VM_IP>
sudo bash infra/scripts/install-relay.sh
```

At the end, the script prints a JSON snippet you'll need:

```
{
  "node_id_hex": "abc123...",
  "addr": "X.X.X.X:443",
  "capabilities": "all"
}
```

**Save the `node_id_hex` of each relay.**

---

## Step 5 — Sign the directory locally

Now produce the signed `gotham-bootstrap.json` that the app will load:

```bash
bash infra/scripts/sign-directory.sh \
    --relay-a "<NODE_ID_A>:<IP_A>:443" \
    --relay-b "<NODE_ID_B>:<IP_B>:443" \
    --relay-c "<NODE_ID_C>:<IP_C>:443" \
    --authority-key ~/.gotham-authority.key \
    --output gotham-bootstrap.json
```

You now have `gotham-bootstrap.json`.

---

## Step 6 — Make the app trust your directory

Two things need to happen:

### 6a — Pin the authority pubkey in the app source

In the Crypto application (not published in this repository), find the constant
`DEFAULT_AUTHORITY_PUBKEY` (TODO: this constant doesn't exist yet in
Phase 0 of Option D — for now, the app uses `load_or_create_local_directory`
which generates a per-install authority. Until that's wired, you have
two paths:

- **Path A (today, manual)**: copy your `gotham-bootstrap.json` to
  `<data_dir>/gotham/directory.json` on each app instance, AND copy
  your authority pubkey (raw 32 bytes Ed25519) to
  `<data_dir>/gotham/authority.ed25519` — the app reads both at
  unlock and routes through them.

- **Path B (after the `gotham_paste_directory` Tauri command lands)**:
  paste the contents of `gotham-bootstrap.json` into the GothamPanel
  in Settings. The app verifies the signature against the pinned
  authority pubkey, swaps the directory in memory, and persists it
  to disk for future cold starts.

### 6b — Disable dev mode (after Option B is up)

Once the app sees your real 3-relay directory, you can turn off the
local 3-relay dev mode:

```sqlite
-- via the Crypto SQLite DB (you can run this through any sqlite3 CLI
-- with `PRAGMA key = '<password-derived-key>'` first — or wait for
-- the `set_gotham_devmode` Tauri command).
INSERT OR REPLACE INTO settings (key, value) VALUES ('gotham_devmode', '0');
```

---

## Step 7 — Verify the network works end-to-end

On any machine with the Crypto app installed and your directory pinned:

1. Unlock the app, wait for `gotham-init-progress` events to reach
   `pct: 100`.
2. Open Settings → Network. You should see:
   - Transport: `Gotham mixnet — ready`
   - Your Gotham address (your own pubkey hex)
   - Directory: 3 relays
3. Create an invitation, copy the URI, paste it into another instance
   of the app on a second machine (or in the same machine for a
   self-loop test).
4. Accept the invitation. The X3DH init message should land within
   ~200-500 ms (3 hops × ~50-150 ms each through the cloud relays).
5. Send a message. It should arrive on the other side.

If the message doesn't arrive after ~10 seconds:

- Check `journalctl -u crypto-gotham-relay.service` on each VM — look
  for QUIC handshake errors or replay-cache rejections.
- Check `~/.crypto/data.db`'s `pending_outbox` table — if the row is
  still there with `retry_count > 0`, the send is failing. The
  background poller retries every 30 s.
- Check that UDP/443 is actually open on all 3 VMs:
  `nmap -sU -p 443 <VM_IP>` from your local machine.

---

## Maintenance

### Re-signing the directory

The directory expires after 30 days. To re-sign (no key rotation):

```bash
bash infra/scripts/sign-directory.sh ... --output gotham-bootstrap.json
```

Then redistribute to all app instances.

### Updating a relay's binary

```bash
ssh ubuntu@<VM_IP>
cd /tmp/crypto-src && git pull
cargo build --release -p crypto-gotham-relay
sudo cp target/release/gotham-relay /opt/gotham/bin/gotham-relay
sudo setcap 'cap_net_bind_service=+ep' /opt/gotham/bin/gotham-relay
sudo systemctl restart crypto-gotham-relay
```

### Oracle Cloud reclaims your "free" VMs

Oracle has been known to terminate Always Free instances that look
"idle". The Gotham relay generates constant cover traffic (~10
packets/sec), so this shouldn't trigger their reclaim heuristic, but
monitor the VMs every couple of weeks. Set up a `cron` heartbeat that
SSHes in once a day — that should suffice.

---

## What this guide does NOT do

- **Anonymity vs. yourself**: you operate all 3 relays. Anyone who
  compromises your Oracle/GCP accounts can correlate the full path.
  This is fine for testing and dev, defensible for "I'm hosting my
  own messenger" use cases, **not defensible for "anonymous
  messenger for journalists"** claims.
- **NAT traversal / hidden services**: the relays use raw public
  IPs, not Tor v3 `.onion`. Anyone who reads `gotham-bootstrap.json`
  sees your VM IPs. The Option D plan in `GOTHAM-EMBEDDED.md` Chantier
  2 (Arti integration) fixes this by routing each relay behind a
  hidden service.
- **Cover traffic at the relay**: the current `crypto-gotham-relay`
  generates cover traffic at the client (outbound `GothamClient::send_sealed`)
  but not always-on between relay links. Option D Chantier 4 adds
  that. Until then, an observer with link-level visibility on all 3
  VPS can correlate traffic bursts.

For a production-quality anonymous mixnet, complete Option D Chantiers
2 + 3 + 4 (see `GOTHAM-EMBEDDED.md`). For a working testnet today,
Option B is enough.

---

© 2026 Angel. AGPL-3.0-or-later OR LicenseRef-Crypto-Commercial.
