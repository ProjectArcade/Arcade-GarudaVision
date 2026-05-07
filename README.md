# Arcade Lykon – Garuda Vision Proposal

## Introduction

Garuda Vision is a proposed native intelligence layer for Lykon that goes beyond encrypted connections to determine whether a URL can actually be trusted. By analyzing domain structures, brand signals, and page content in real time — both before and after a page loads — Garuda Vision addresses a critical limitation in modern browser security.

Today’s browsers answer the question:

> “Is this connection secure?”

Garuda Vision is designed to answer the more important question:

> “Is this destination safe?”

The modern web faces a growing trust problem. Current browsers are primarily built to verify whether a connection is encrypted, not whether the destination itself is legitimate. These are fundamentally different concerns, and the gap between them is where millions of users are deceived every year.

Garuda Vision aims to bridge this gap by introducing native browser intelligence capable of evaluating trust signals before a user fully interacts with a webpage.

---

## The Problem

When a browser displays a padlock icon, it confirms only one thing:

* The connection between the user and the server is encrypted.

It does **not** verify:

* Who operates the website
* Whether the destination is legitimate
* Whether the page is attempting to impersonate a trusted brand

Attackers have exploited this weakness for years. A phishing page hosted at:

`googleauthlogin.vercel.app`

can display the same padlock icon as:

`google.com`

because the encryption is genuine — even if the intent behind the page is malicious.

### Limitations of Current Browser Security

Most browser security systems rely heavily on blocklists: databases containing known malicious domains. The core issue with this model is timing.

A typical phishing site:

1. Goes live
2. Harvests credentials
3. Disappears within hours

In many cases, the attack succeeds before the domain is ever added to a blocklist. The defense activates only after the damage has already occurred.

---

## Scope of Detection

The phishing examples throughout this proposal frequently reference free hosting platforms such as:

* `vercel.app`
* `netlify.app`

This is not because Garuda Vision is limited to detecting threats on those platforms. They are highlighted because they currently represent one of the fastest-growing and least-defended attack vectors on the web.

Garuda Vision evaluates trust signals across the entire internet, regardless of domain extension or hosting provider.

Examples within scope include:

* Homoglyph attacks on `.com` domains
* Credential-harvesting pages on `.in` domains
* Brand impersonation pages on `.co` domains

All of these threats are analyzed using the same detection layers proposed within Garuda Vision.

The platform examples are intended to illustrate the problem — not define the limits of detection.

---

## Learn More

[Garuda Vision Full Documentation](https://docs.google.com/document/d/1pEkEXVbTcQIA3jZqvhHxFgENFgyUlIzwtaiI4n_St1g/edit?usp=sharing&utm_source=chatgpt.com)
