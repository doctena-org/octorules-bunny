## Access List (BN3xx)

### BN300 — Invalid access list type

**Severity:** ERROR

The `type` must be one of: `ip`, `cidr`, `asn`, `country`, `organization`, `ja4`.

**Triggers on:**

```yaml
bunny_waf_access_list_rules:
  - ref: "1"
    type: hostname
```

**Fix:**

```yaml
    type: ip
```

### BN301 — Empty access list content

**Severity:** ERROR

The `content` field must contain at least one entry. Each entry is on a separate line.

**Triggers on:**

```yaml
    content: ""
```

**Fix:**

```yaml
    content: |
      CN
      RU
```

### BN302 — Invalid CIDR/IP notation

**Severity:** WARNING

For `ip` and `cidr` type access lists, each entry must be a valid IP address or CIDR range.

**Triggers on:**

```yaml
    type: ip
    content: |
      not-an-ip
```

**Fix:**

```yaml
    content: |
      192.0.2.1
```

### BN303 — Invalid ASN format

**Severity:** WARNING

For `asn` type access lists, each entry must be numeric or AS-prefixed (e.g., `13335` or `AS13335`).

**Triggers on:**

```yaml
    type: asn
    content: |
      cloudflare
```

**Fix:**

```yaml
    content: |
      AS13335
```

### BN304 — Invalid country code

**Severity:** WARNING

For `country` type access lists, each entry must be exactly 2 uppercase letters (ISO 3166-1 alpha-2).

**Triggers on:**

```yaml
    content: |
      usa
```

**Fix:**

```yaml
    content: |
      US
```

### BN305 — Private/reserved IP range

**Severity:** WARNING

An IP or CIDR falls within a private/reserved range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1/128, fc00::/7). These are not routable on the public internet.

**Triggers on:**

```yaml
    type: ip
    content: |
      192.168.1.1
```

**Fix:**

```yaml
    content: |
      203.0.113.50
```

### BN306 — CIDR has host bits set

**Severity:** WARNING

A CIDR has host bits set (e.g., `10.0.0.1/24`). The API normalises to the network address, causing phantom diffs on the next plan.

**Triggers on:**

```yaml
    type: cidr
    content: |
      10.0.0.1/24
```

**Fix:**

```yaml
    content: |
      10.0.0.0/24
```

### BN307 — Overlapping CIDRs

**Severity:** WARNING

Two CIDRs in the same access list overlap. The broader range already covers the narrower one.

**Triggers on:**

```yaml
    type: cidr
    content: |
      10.0.0.0/8
      10.1.0.0/16
```

**Fix:** Remove the narrower range:

```yaml
    content: |
      10.0.0.0/8
```

### BN308 — Invalid JA4 fingerprint

**Severity:** WARNING

For `ja4` type access lists, each entry must be a valid JA4 TLS fingerprint — exactly 36 characters in the format `a_b_c`:

- Section A (10 chars): protocol (`t`/`q`/`d`) + TLS version + SNI + cipher count + extension count + ALPN
- Section B (12 chars): truncated SHA-256 of cipher suites (lowercase hex)
- Section C (12 chars): truncated SHA-256 of extensions (lowercase hex)

**Triggers on:**

```yaml
    type: ja4
    content: |
      not-a-fingerprint
```

**Fix:**

```yaml
    content: |
      t13d1516h2_8daaf6152771_e5627efa2ab1
```

### BN309 — Duplicate entry in access list

**Severity:** WARNING

The same entry appears more than once in an access list. Duplicates waste capacity and may indicate a copy-paste error. Applies to `ip` and `cidr` type access lists.

- **`ip` type:** IPv6 addresses are normalised to lowercase before comparison so that `2001:DB8::1` and `2001:db8::1` are detected as duplicates.
- **`cidr` type:** CIDRs are normalised to their network address before comparison, so `10.0.0.1/24` and `10.0.0.0/24` are detected as duplicates (both normalise to `10.0.0.0/24`).

**Triggers on:**

```yaml
    type: ip
    content: |
      1.2.3.4
      5.6.7.0/24
      1.2.3.4
```

```yaml
    type: cidr
    content: |
      10.0.0.1/24
      10.0.0.0/24
```

```yaml
    type: ip
    content: |
      2001:DB8::1
      2001:db8::1
```

**Fix:** Remove the duplicate entry:

```yaml
    type: ip
    content: |
      1.2.3.4
      5.6.7.0/24
```

### BN310 — Duplicate organization entry in access list

**Severity:** WARNING

The same organization entry appears more than once in an `organization` type access list. Comparison is case-insensitive.

**Triggers on:**

```yaml
    type: organization
    content: |
      ACME Corp
      acme corp
```

**Fix:** Remove the duplicate entry.

---
