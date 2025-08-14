<br />
<br />

Hi, I'm Tobias. I currently try my luck with Rust, Flutter and fuzzing. See what I'm working
on below, it's nothing crazy but it's fun.

<br />

## Introducing my new Generic Network Protocol Fuzzer in Rust
<span class="metadata">2025-08-14 • Rust, Open-Source, Fuzzing</span>

This blog post introduces my new generic approach to easily create a fast and easy-to use protocol fuzzer for custom targets. The fuzzer aims to be used mainly in the embedded world, where most of the time it is not easy to create a running harness on a Linux-based system because of hardware dependencies, the source code is not available, or it requires hardware attacks to dump the firmware.

<ul class="links">
  <li><a href="generic-protocol-fuzzer.html">Blog post</a></li>
  <li><a href="https://github.com/otsmr/profuzz">Github</a></li>
</ul>

<br />

## twonly - The European Alternative
<span class="metadata">2025-05-01 • Android & iOS App, Signal-Protocol, Open-Source</span>

twonly is a European [open-source](https://github.com/twonlyapp/twonly-app) alternative to Snapchat, written in Flutter. It uses the Signal protocol to encrypt all messages end-to-end and offers a clean UI without distractions or ads. Try it out for yourself by downloading the app from your app store or directly via GitHub.

<ul class="links">
  <li><a href="https://twonly.eu">Website</a></li>
  <li><a href="https://github.com/twonlyapp/twonly-app/releases">Github Releases</a></li>
  <li><a href="https://testflight.apple.com/join/U9B3v2rk">App Store</a></li>
  <li><a href="https://twonly.eu#join">Google Play Store</a></li>
</ul>

<br />

## Finding Security Vulnerabilities in Open-Source Repos
<span class="metadata">2025-03-25 • Pentesting, Open-Source, Afl.rs</span>

This winter semester I took part in the TU Darmstadt [Hacker
Contest](https://www.usd.de/tag/hacker-contest/), where we had an exercise in which we had to find
security vulnerabilities in open source repositories. In this blog post I will share my findings. It's nothing crazy,
but it was still fun to find them.

<ul class="links">
  <li><a href="hackercontest.html">Blog post</a></li>
</ul>
<br />

## Blackbox-Fuzzing of IoT Devices Using the Router TL-WR902AC as Example
<span class="metadata">2024-03-13 • AFL++, TP-LINK</span>

In my term paper about the "Internet of Vulnerable Things" I wanted to find a memory-related
vulnerability in a binary running on the TL-WR902AC but was not successful. This time I use fuzzing
to find such a vulnerability.

<ul class="links">
  <li><a href="blackbox-fuzzing.html">Blog post</a></li>
  <li><a href="https://github.com/otsmr/blackbox-fuzzing">GitHub</a></li>
</ul>
<br />

## AnotherTLS and VulnTLS
<span class="metadata">2023-12-21 • TLS, Cryptography, Rust, CTF</span>

To learn Rust and cryptography at the same time I implemented the TLSv1.3 from scratch. The implementation includes all
cryptographic operations like elliptic curves or AES. During the implementation, I looked at various attacks in detail.
Some of them have become CTF challenges (see VulnTLS for more), such as Dual_EC, an NSA backdoor.

<ul class="links">
  <li><a href="anothertls.html">Blog post</a></li>
  <li><a href="https://github.com/otsmr/anothertls">AnotherTLS</a></li>
  <li><a href="https://github.com/otsmr/vulntls">VulnTLS</a></li>
</ul>
<br />

## WebRocket
<span class="metadata">2023-01-26 • Rust, WebSocket</span>

WebRocket is a WebSocket server implementation programmed from scratch in Rust (including SHA-1
and Base64). This is my project with which I learned Rust.

<ul class="links">
  <li><a href="https://crates.io/crates/webrocket">Crates.io</a></li>
  <li><a href="https://github.com/otsmr/webrocket">GitHub</a></li>
</ul>

<br />

## CVE-2022-48194 - Internet of Vulnerable Things
<span class="metadata">2022-12-30 • IoT, TP-Link</span>

In one of my term papers I had to write about the topic "Internet of Vulnerable Things". So I bought
a cheap router and took a closer look. As expected, the security was not really good and I was able
to find a security vulnerability with a CVE score of 8.8 in no time.

<ul class="links">
  <li><a href="https://raw.githubusercontent.com/otsmr/internet-of-vulnerable-things/main/Internet_of_Vulnerable_Things.pdf">Term Paper</a> </li>
  <li><a href="https://github.com/otsmr/internet-of-vulnerable-things">Exploit</a></li>
</ul>

<br />

## ODMIN a Identity Management Solution
<span class="metadata">2021-10-30 • TypeScript, OAuth, Single-Sign On, NodeJS</span>

I created this project to provide a privacy compliant and feature rich "sign in with" solution for
my own websites. In the meantime my focus has changed to web application security. It is therefore
explicitly allowed to hack my own instance under odmin.de - and if the hack impresses me there is
also a small bug bounty :)

<ul class="links">
  <li><a href="https://odmin.de">Demo</a></li>
  <li><a href="https://github.com/otsmr/odmin">GitHub</a></li>
</ul>
