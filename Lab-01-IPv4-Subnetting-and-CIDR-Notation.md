# 🌐 Lab 1: IPv4 Subnetting and CIDR Notation

**Date:** 2026-02-12

---

### 🎯 Objective
Demonstrate the ability to convert IPv4 addresses to binary, derive subnet masks from CIDR notation, identify network and host portions, and calculate the full usable IP range and broadcast address for a given subnet.

---

### 🧰 Reference: 8-Bit Octet Chart

| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |
|-----|----|----|-----|---|---|---|---|

---

## Example 1 — 172.16.50.0/22

### 🔢 Binary Breakdown

```
Address:      10101100.00010000.001100|10.00000000
Subnet Mask:  11111111.11111111.111111|00.00000000
              |-------- Network -------|---- Host ----|
```

| Field | Value |
|-------|-------|
| CIDR | /22 |
| Subnet Mask | 255.255.252.0 |
| Broadcast Address | 172.16.51.255 |
| Total IPs | 1024 |
| Usable Hosts | 1022 |

### 📊 Full Range

```
Network:   10101100.00010000.00110000.00000000  →  172.16.48.0
Broadcast: 10101100.00010000.00110011.11111111  →  172.16.51.255
```

---

## Example 2 — 10.45.0.0/18

### 🔢 Binary Breakdown

```
Address:      00001010.00101101.00|000000.00000000
Subnet Mask:  11111111.11111111.11|000000.00000000
              |------- Network ----|------ Host ----|
```

| Field | Value |
|-------|-------|
| CIDR | /18 |
| Subnet Mask | 255.255.192.0 |
| Network Address | 10.45.0.0 |
| Broadcast Address | 10.45.63.255 |
| Total IPs | 16384 |
| Usable Hosts | 16382 |

### 📊 Full Range

```
Network:   10.45.0.0
Broadcast: 10.45.63.255
```

---

### ✅ Conclusion
Both examples demonstrate the full subnetting workflow:
- Converting dotted-decimal to binary
- Applying the CIDR prefix to identify the network/host boundary
- Deriving the subnet mask
- Calculating network address, broadcast address, and usable host range
