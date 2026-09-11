# Case 08 — Local Account Deletion

## Overview

This investigation focuses on the deletion of a local Windows account detected through **Windows Security Event ID 4726**.

The objective was to identify:

- who performed the deletion,
- which account was affected,
- when the action occurred,
- what host was involved,
- what activity occurred before the deletion,
- and whether the event was benign or suspicious.

---

## Lab Environment

- SIEM: Splunk Enterprise
- Data Source: Windows Security Events
- Index: `windows_soc`
- Host: `SOC-WS01`
- Test Account: `SOC_CASE08`
- Analyst Account: `lab_analyst`

> All identifiers have been sanitized for public documentation.

---

## Detection Objective

Detect and investigate **Event ID 4726**, which indicates that a user account was deleted.

A local account deletion can be legitimate administrative activity, but in a real environment it may also be associated with:

- account cleanup,
- temporary account usage,
- unauthorized administrative activity,
- removal of persistence,
- or attempts to hide previous activity.

For this reason, the event must be analyzed in context.

---

## Initial Search

```spl
index=windows_soc EventCode=4726 earliest=-24h latest=now
