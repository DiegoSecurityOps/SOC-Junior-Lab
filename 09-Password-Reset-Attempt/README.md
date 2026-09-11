# Case 09 — Password Reset Attempt

## Overview

This investigation focuses on a Windows account password reset attempt detected through **Windows Security Event ID 4724**.

The objective was to identify:

- who performed the password reset,
- which account was affected,
- when the activity occurred,
- what host was involved,
- what events occurred around the reset,
- and whether the activity was legitimate or suspicious.

---

## Lab Environment

- SIEM: Splunk Enterprise
- Data Source: Windows Security Events
- Index: `windows_soc`
- Host: `SOC-WS01`
- Test Account: `SOC_CASE09`
- Analyst Account: `lab_analyst`

> All identifiers have been sanitized for public documentation.

---

## Detection Objective

Detect and investigate **Event ID 4724**, which indicates that an attempt was made to reset an account password.

Password reset activity may be legitimate administrative behavior, but in a production environment it can also be associated with:

- unauthorized account manipulation,
- privilege abuse,
- account takeover,
- persistence,
- or misuse of administrative credentials.

For this reason, the event should be reviewed in context.

---

## Initial Search

```spl
index=windows_soc EventCode=4724 earliest=-24h latest=now
