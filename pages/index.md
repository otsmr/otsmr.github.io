<br />
<br />

Hi, I am someone who likes to do security related things or learn something
new. I'm currently trying my luck with rust and fuzzing. See what I'm working
on below, it's nothing crazy but it's fun.

<br />


## Finding Security Vulnerabilities in Open-Source Repos
Keywords: Pentesting, Open-Source, Afl.rs

This winter semester I took part in the TU Darmstadt [Hacker
Contest](https://www.usd.de/tag/hacker-contest/), where we had an exercise in which we had to find
security vulnerabilities in open source repositories. In this blog post I will share my findings. It's nothing crazy,
but it was still fun to find them.

<ul class="links">
  <li><a href="hackercontest.html">Blog post</a></li>
</ul>
<br />

## Blackbox-Fuzzing of IoT Devices Using the Router TL-WR902AC as Example
Keywords: AFL++, TP-LINK

In my term paper about the "Internet of Vulnerable Things" I wanted to find a memory-related
vulnerability in a binary running on the TL-WR902AC but was not successful. This time I use fuzzing
to find such a vulnerability.

<ul class="links">
  <li><a href="blackbox-fuzzing.html">Blog post</a></li>
  <li><a href="https://github.com/otsmr/blackbox-fuzzing">GitHub</a></li>
</ul>
<br />

## AnotherTLS and VulnTLS
Keywords: TLS, Cryptography, Rust, CTF

To learn Rust and cryptography at the same time I implemented the Transport Security Layer Protocol
Version 3 (TLSv1.3) from scratch. The implementation includes all cryptographic operations like
elliptic curves or AES. During the implementation, I looked at various attacks in detail. Some of
them have become CTF challenges (see VulnTLS for more), such as Dual_EC, an NSA backdoor.

<ul class="links">
  <li><a href="anothertls.html">Blog post</a></li>
  <li><a href="https://github.com/otsmr/anothertls">AnotherTLS</a></li>
  <li><a href="https://github.com/otsmr/vulntls">VulnTLS</a></li>
</ul>
<br />

## WebRocket
Keywords: Rust, WebSocket

WebRocket is a WebSocket server implementation programmed from scratch in Rust (including SHA-1
and Base64). This is my project with which I learned Rust.

<ul class="links">
  <li><a href="https://crates.io/crates/webrocket">Crates.io</a></li>
  <li><a href="https://github.com/otsmr/webrocket">GitHub</a></li>
</ul>

<br />

## CVE-2022-48194 - Internet of Vulnerable Things
Keywords: IoT, TP-Link

In one of my term papers I had to write about the topic "Internet of Vulnerable Things". So I bought
a cheap router and took a closer look. As expected, the security was not really good and I was able
to find a security vulnerability with a CVE score of 8.8 in no time.

<ul class="links">
  <li><a href="https://raw.githubusercontent.com/otsmr/internet-of-vulnerable-things/main/Internet_of_Vulnerable_Things.pdf">Term Paper</a> </li>
  <li><a href="https://github.com/otsmr/internet-of-vulnerable-things">Exploit</a></li>
</ul>

<br />

## ODMIN a Identity Management Solution

Keywords: TypeScript, OAuth, Single-Sign On, NodeJS

I created this project to provide a privacy compliant and feature rich "sign in with" solution for
my own websites. In the meantime my focus has changed to web application security. It is therefore
explicitly allowed to hack my own instance under odmin.de - and if the hack impresses me there is
also a small bug bounty :)

<ul class="links">
  <li><a href="https://odmin.de">Demo</a></li>
  <li><a href="https://github.com/otsmr/odmin">GitHub</a></li>
</ul>
