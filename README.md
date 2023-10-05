# Awesome EDR Bypass　![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)

🛡️ Awesome EDR Bypass Resources For Ethical Hacking ⚔️

EDR bypass technology is not just for attackers.
Many malware now have EDR bypass capabilities, knowledge that pentesters and incident responders should also be aware of.
This repository is not intended to be used to escalate attacks. Use it for ethical hacking.

## PoC
- [trickster0/TartarusGate: TartarusGate, Bypassing EDRs](https://github.com/trickster0/TartarusGate)
- [am0nsec/HellsGate: Original C Implementation of the Hell's Gate VX Technique](https://github.com/am0nsec/HellsGate)
    - The paper PDF has a nice summary of EDR Bypass techniques.
- [Maldev-Academy/HellHall: Performing Indirect Clean Syscalls](https://github.com/Maldev-Academy/HellHall)
    - A technique called HellsGate, which specifies a system call number through a value in memory, combined with a technique to call a system call by specifying an address in NTDLL where the syscall instruction is implemented, without calling the syscall instruction.
- [TheD1rkMtr/UnhookingPatch: Bypass EDR Hooks by patching NT API stub, and resolving SSNs and syscall instructions at runtime](https://github.com/TheD1rkMtr/UnhookingPatch)
- [RedTeamOperations/Journey-to-McAfee](https://github.com/RedTeamOperations/Journey-to-McAfee)
- [op7ic/EDR-Testing-Script: Test the accuracy of Endpoint Detection and Response (EDR) software with simple script which executes various ATT&CK/LOLBAS/Invoke-CradleCrafter/Invoke-DOSfuscation payloads](https://github.com/op7ic/EDR-Testing-Script)

## Tool
- [tanc7/EXOCET-AV-Evasion: EXOCET - AV-evading, undetectable, payload delivery tool](https://github.com/tanc7/EXOCET-AV-Evasion)
- [naksyn/Pyramid: a tool to help operate in EDRs' blind spots](https://github.com/naksyn/Pyramid)
- [Yaxser/Backstab: A tool to kill antimalware protected processes](https://github.com/Yaxser/Backstab/)
- [klezVirus/inceptor: Template-Driven AV/EDR Evasion Framework](https://github.com/klezVirus/inceptor)
- [georgesotiriadis/Chimera: Automated DLL Sideloading Tool With EDR Evasion Capabilities](https://github.com/georgesotiriadis/Chimera)

## Workshop
More of a malware development workshop for pentesters than a workshop to Bypass EDR.

- [chvancooten/maldev-for-dummies: A workshop about Malware Development](https://github.com/chvancooten/maldev-for-dummies)
- [BC-SECURITY/Beginners-Guide-to-Obfuscation](https://github.com/BC-SECURITY/Beginners-Guide-to-Obfuscation)
- [chr0n1k/AH2021Workshop: Malware development for red teaming workshop](https://github.com/chr0n1k/AH2021Workshop)
- [WesleyWong420/RedTeamOps-Havoc-101: Materials for the workshop "Red Team Ops: Havoc 101"](https://github.com/WesleyWong420/RedTeamOps-Havoc-101)

## Presentation
- [Lifting the veil, a look at MDE under the hood - FIRST CONFERENCE
2022](https://www.first.org/resources/papers/conf2022/MDEInternals-FIRST.pdf)
- [Dirty Vanity: A New Approach to Code Injection &#38; EDR Bypass - Black Hat Europe 2022](https://www.blackhat.com/eu-22/briefings/schedule/#dirty-vanity-a-new-approach-to-code-injection--edr-bypass-28417)
- [talks/Diego Capriotti - DEFCON30 Adversary Village - Python vs Modern Defenses.pdf](https://github.com/naksyn/talks/blob/main/DEFCON30/Diego%20Capriotti%20-%20DEFCON30%20Adversary%20Village%20-%20%20Python%20vs%20Modern%20Defenses.pdf)
- [Develop Your Own Rat](https://docs.google.com/presentation/d/1UZmFo_TvSS2TvPJKlDjIW1kTVjYGGaYO86Buh2UgbaI/mobilepresent?slide=id.g11cdb36f978_1_129)
- [EDR Evasion Primer for Red Teamers - Karsten Nohl & Jorge Gimenez - Hack in the Box 2022 Singapore](https://conference.hitb.org/hitbsecconf2022sin/materials/D1T1%20-%20EDR%20Evasion%20Primer%20for%20Red%20Teamers%20-%20Karsten%20Nohl%20&%20Jorge%20Gimenez.pdf)

## Blog
- [Living-Off-the-Blindspot - Operating into EDRs’ blindspot | Naksyn’s blog](https://www.naksyn.com/edr%20evasion/2022/09/01/operating-into-EDRs-blindspot.html)
  - Type of person who works hard in Python; uses [PEP 578 – Python Runtime Audit Hooks](https://peps.python.org/pep-0578/).
- [Bypass CrowdStrike Falcon EDR protection against process dump like lsass.exe | by bilal al-qurneh | Medium](https://medium.com/@balqurneh/bypass-crowdstrike-falcon-edr-protection-against-process-dump-like-lsass-exe-3c163e1b8a3e)
  - The story is that a forensic tool can be used to dump memory without detection. This is an example of how a tool for legitimate purposes that is not an attack tool can be used in an attack without being detected. 
- [State-of-the-art EDRs are not perfect, fail to detect common attacks - The Record from Recorded Future News](https://therecord.media/state-of-the-art-edrs-are-not-perfect-fail-to-detect-common-attacks/)
  - Commentary on [An Empirical Assessment of Endpoint Security Systems Against Advanced Persistent Threats Attack Vectors](https://arxiv.org/abs/2108.10422)
- [A tale of EDR bypass methods | S3cur3Th1sSh1t](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)
- [In-Memory Execution in macOS: the Old and the New | Meta Red Team X](https://rtx.meta.security/post-exploitation/2022/12/19/In-Memory-Execution-in-macOS.html)
  - macOS!!!!
- [Blindside: A New Technique for EDR Evasion with Hardware Breakpoints - Cymulate](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints)
- [Attacking an EDR - Part 1](https://riccardoancarani.github.io/2023-08-03-attacking-an-edr-part-1/)
- [Attacking an EDR - Part 2](https://riccardoancarani.github.io/2023-09-14-attacking-an-edr-part-2/)

## Book
- [Evading EDR | No Starch Press](https://nostarch.com/evading-edr)

## Other awesome series
- [MrEmpy/Awesome-AV-EDR-XDR-Bypass: Awesome AV/EDR/XDR Bypass Tips](https://github.com/MrEmpy/Awesome-AV-EDR-XDR-Bypass)
