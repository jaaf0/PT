# 13 — SSH (22)

> **Observation:** 22 open. **Objective:** assess version/crypto/auth posture and gain access
> only via authorized credentials/keys. **Risk:** enum SAFE; auth testing CONTROLLED (lockout/
> fail2ban); guessing = **RoE-gated**.

## WHY

SSH is the main Linux admin channel. It rarely has exploitable RCE on modern versions, so the
real risks are **weak/default/reused credentials, exposed private keys, and weak crypto config**.

| Step | Objective | Tool | Command | Look for |
|------|-----------|------|---------|----------|
| 1 | Version & banner | nmap/nc | `nc <ip> 22`; `nmap -p22 -sV <ip>` | OpenSSH version → known CVEs (mostly DoS/info; verify) |
| 2 | Crypto & auth methods | ssh-audit | `ssh-audit <ip>` | weak KEX/ciphers/MACs; `password`/`publickey`/`keyboard-interactive` |
| 3 | Auth methods (manual) | ssh | `ssh -o PreferredAuthentications=none -o BatchMode=yes <ip>` | server lists accepted methods |
| 4 | User enum (version-dependent) | nmap/script | `nmap -p22 --script ssh-auth-methods --script-args ssh.user=root <ip>` | valid users (older OpenSSH timing bugs) |
| 5 | Key-based access | ssh | `ssh -i <found_key> user@<ip>` | a harvested key logs in → access |
| 6 | Authorized cred test | nxc/ssh | `nxc ssh <ip> -u <u> -p <p>` (single known cred) | valid login |
| 7 | Config review (post-access) | cat | `sshd_config`: `PermitRootLogin`,`PasswordAuthentication`,`AllowUsers` | weak policy findings |

## Decision flow
```
password auth enabled + weak policy → spray risk → §20 (RoE-gated); report as hardening finding
harvested private key (from §09 loot) → try it → access → §21 lateral
weak ciphers/KEX (e.g. CBC, SHA1, diffie-hellman-group1) → config finding (low/medium)
OpenSSH version with real CVE → validate exact version; most are not RCE → don't overclaim
root login permitted → finding; combined with a cred = direct root
```

## Safety
- **Password guessing/spraying over SSH triggers fail2ban/lockouts** → `REQUIRES EXPLICIT RoE
  APPROVAL`; test known creds only by default.
- Using a **found** key is authorized credential use (CONTROLLED); document where the key came
  from (which host/finding) for the chain.

## Evidence
`enumeration/<id>-ssh.txt` (ssh-audit), login proof screenshot, sshd_config excerpt. Keys →
`loot/` encrypted.
