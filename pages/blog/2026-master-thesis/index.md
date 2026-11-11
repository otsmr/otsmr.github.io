---
title: "Know Your Contacts: Usable Authentication for Secure Messaging"
date: 2026-09-30
description: My master's thesis redesigns the authentication ceremony of end-to-end encrypted messengers and evaluates it in twonly through usability studies, in-app statistics and a survey comparing it to Signal.
keywords: Master's Thesis, Usable Security, twonly
---
# Know Your Contacts: Usable Authentication for Secure Messaging

This is my master's thesis, which I wrote at the [Secure Mobile Networking Lab (SEEMOO)](https://www.seemoo.tu-darmstadt.de/) at TU Darmstadt.

End-to-end encrypted messengers such as Signal commonly rely on servers to distribute users' public keys. A server that also controls message delivery may substitute these keys to perform a machine-in-the-middle attack. Users must therefore authenticate their contacts' public keys through an authentication ceremony to detect such attacks, but prior research identified persistent usability problems in Signal's ceremony. This thesis proposes and evaluates a redesigned ceremony that uses clearer terminology, verification badges, one-way QR code scanning, and an automated Web of Trust approach that propagates verification states. Two pluralistic usability walkthroughs with six participants and three iterations of simplified user testing with 15 participants informed and refined the implementation in the open-source messenger [twonly](https://twonly.eu). In the final iteration, all five participants completed the ceremony, and usability issues reported in previous research did not reappear. Its public release enabled the collection of in-app usage statistics from 32 participants, which measured how often contacts were verified and how widely the automation was adopted. A comparative online survey with 23 users of both messengers assessed which elements could be transferred to Signal: 65.2% preferred twonly's verification process, whereas 17.4% preferred Signal's. However, even after the improved ceremony was published, the in-app statistics showed that manual verification barely increased, which suggests that better usability alone does not motivate users to verify their contacts.

The new authentication ceremony and the Web of Trust approach from this thesis are now part of twonly. You can read more about them in the twonly blog post [Finding Friends Without Phone Numbers](https://twonly.eu/en/blog/2026-mutual-friends.html).

<p class="cta"><a class="button" href="https://twonly.eu/en/faq/security/verify-identity.html">Try it out yourself and verify your contacts in twonly now</a></p>

**The download link for the full thesis will be added soon.**
