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
- [zer0condition/mhydeath: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.](https://github.com/zer0condition/mhydeath)
  - Demo to force quit Crowdstrike Falcon and Microsoft　Defender
- [Mr-Un1k0d3r/RedTeamCCode: Red Team C code repo](https://github.com/Mr-Un1k0d3r/RedTeamCCode/)
- [BYOSI: Bypass EDR by bringing your own script interpreter](https://github.com/oldkingcone/BYOSI)
- [Polydrop: Expanded BYOSI attack, leverages 12 additional languages.](https://github.com/MalwareSupportGroup/PolyDrop)
- [senzee1984/EDRPrison: Leverage a legitimate WFP callout driver to prevent EDR agents from sending telemetry](https://github.com/senzee1984/EDRPrison)
- [S3cur3Th1sSh1t/Ruy-Lopez: Proof-of-Concept(PoC) for a new approach to completely prevent DLLs from being loaded into a newly spawned process](https://github.com/S3cur3Th1sSh1t/Ruy-Lopez)
    - This [post](https://s3cur3th1ssh1t.github.io/Cat_Mouse_or_Chess/) will cover the background and description of the technique.

## Tool
- [tanc7/EXOCET-AV-Evasion: EXOCET - AV-evading, undetectable, payload delivery tool](https://github.com/tanc7/EXOCET-AV-Evasion)
- [naksyn/Pyramid: a tool to help operate in EDRs' blind spots](https://github.com/naksyn/Pyramid)
- [Yaxser/Backstab: A tool to kill antimalware protected processes](https://github.com/Yaxser/Backstab/)
- [klezVirus/inceptor: Template-Driven AV/EDR Evasion Framework](https://github.com/klezVirus/inceptor)
- [georgesotiriadis/Chimera: Automated DLL Sideloading Tool With EDR Evasion Capabilities](https://github.com/georgesotiriadis/Chimera)
- [netero1010/EDRSilencer: A tool uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server.](https://github.com/netero1010/EDRSilencer)
- [wavestone-cdt/EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast)
- [myzxcg/RealBlindingEDR: Remove AV/EDR Kernel ObRegisterCallbacks、CmRegisterCallback、MiniFilter Callback、PsSetCreateProcessNotifyRoutine Callback、PsSetCreateThreadNotifyRoutine Callback、PsSetLoadImageNotifyRoutine Callback...](https://github.com/myzxcg/RealBlindingEDR)
- [jthuraisamy/SysWhispers2: Direct system call generator to bypass userland API hooks](https://github.com/jthuraisamy/SysWhispers2)
- [klezVirus/SysWhispers3: Generate header/ASM files implants can use to make direct system calls](https://github.com/klezVirus/SysWhispers3)
- [d1rkmtrr/dark-kill: A user-mode code and its rootkit that will Kill EDR Processes permanently by leveraging the power of Process Creation Blocking Kernel Callback Routine registering and ZwTerminateProcess.](https://github.com/d1rkmtrr/dark-kill)

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
- [EDR Reloaded: Erase Data Remotely - Black Hat Asia 2024 | Briefings Schedule](https://i.blackhat.com/Asia-24/Presentations/Asia-24_Bar-EDREraseDataRemotelyReloaded.pdf)
- [EvilEDR: Repurposing EDR as an Offensive Tool - USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/alachkar)
    - Demonstrates how EDR systems can be employed for offensive use, executing arbitrary commands, exfiltrating data, and impairing defenses. Artifact repository is hosted on the Zenodo platform and is publicly accessible through the following permanent URL:https://doi.org/10.5281/zenodo.15116409
- [Hiding Payloads in Plain .text, bypass EDRs which use Shannon entropy for detection - x33fcon 2024](https://www.youtube.com/watch?v=8YIfjM_zCjs)
    - [code repository for this Presentation](https://github.com/NVISOsecurity/codasm)
    - some blogs relative to this topic:
      - https://redsiege.com/blog/2023/04/evading-crowdstrike-falcon-using-entropy/
      - https://redops.at/en/blog/meterpreter-vs-modern-edrs-in-2023
      - https://practicalsecurityanalytics.com/file-entropy/

## Blog
- [Living-Off-the-Blindspot - Operating into EDRs’ blindspot | Naksyn’s blog](https://www.naksyn.com/edr%20evasion/2022/09/01/operating-into-EDRs-blindspot.html)
  - Type of person who works hard in Python; uses [PEP 578 – Python Runtime Audit Hooks](https://peps.python.org/pep-0578/).
- [Bypass CrowdStrike Falcon EDR protection against process dump like lsass.exe | by bilal al-qurneh | Medium](https://medium.com/@balqurneh/bypass-crowdstrike-falcon-edr-protection-against-process-dump-like-lsass-exe-3c163e1b8a3e)
  - The story is that a forensic tool can be used to dump memory without detection. This is an example of how a tool for legitimate purposes that is not an attack tool can be used in an attack without being detected.
- [Bypassing CrowdStrike Falcon and MDE](https://ericesquivel.github.io/posts/bypass)
- [State-of-the-art EDRs are not perfect, fail to detect common attacks - The Record from Recorded Future News](https://therecord.media/state-of-the-art-edrs-are-not-perfect-fail-to-detect-common-attacks/)
  - Commentary on [An Empirical Assessment of Endpoint Security Systems Against Advanced Persistent Threats Attack Vectors](https://arxiv.org/abs/2108.10422)
- [A tale of EDR bypass methods | S3cur3Th1sSh1t](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)
- [Blindside: A New Technique for EDR Evasion with Hardware Breakpoints - Cymulate](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints)
- [Attacking an EDR - Part 1](https://riccardoancarani.github.io/2023-08-03-attacking-an-edr-part-1/)
- [Attacking an EDR - Part 2](https://riccardoancarani.github.io/2023-09-14-attacking-an-edr-part-2/)
- [The Dark Side of EDR: Repurpose EDR as an Offensive Tool | SafeBreach](https://www.safebreach.com/blog/dark-side-of-edr-offensive-tool/)
  - Probably the same content as [The Dark Side of EDR: Repurpose EDR as an Offensive Tool - Black Hat Asia 2024](https://www.blackhat.com/asia-24/briefings/schedule/index.html#the-dark-side-of-edr-repurpose-edr-as-an-offensive-tool-37846)
  - Focusing on Palo Alto Networks' Cortex XDR, the report presents a case study of how EDR turned into a stealthy and unique persistent malware.
- [Silent Threat: Red Team Tool EDRSilencer Disrupting Endpoint Security Solutions | Trend Micro (US)](https://www.trendmicro.com/en_us/research/24/j/edrsilencer-disrupting-endpoint-security-solutions.html)
  - Leveraging the Windows Filtering Platform (WFP)
- [Bring Your Own Installer: Bypassing EDR Through Agent Version Change Interruption](https://www.aon.com/en/insights/cyber-labs/bring-your-own-installer-bypassing-sentinelone)
  - Running the EDR installer locally stops the EDR process.
- [Meterpreter vs Modern EDR(s) - RedOps](https://redops.at/en/blog/meterpreter-vs-modern-edrs-in-2023)
- [Blinding EDR On Windows | synzack](https://synzack.github.io/Blinding-EDR-On-Windows/)
  - Detailed explanation of Windows kernel callbacks, how EDRs work, and techniques to remove EDR visibility
- [Silencing the EDR Silencers | Huntress](https://www.huntress.com/blog/silencing-the-edr-silencers)
  - Defense perspective on protecting EDRs from blinding attacks using firewall and WFP rules

### BYOVD
- [EDR Bypass Testing Reveals Extortion Actor's Toolkit](https://unit42.paloaltonetworks.com/edr-bypass-extortion-attempt-thwarted/)
- [Forget vulnerable drivers - Admin is all you need — Elastic Security Labs](https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need)
- [Bring Your Own Backdoor: How Vulnerable Drivers Let Hackers In - VMware Security Blog - VMware](https://blogs.vmware.com/security/2023/04/bring-your-own-backdoor-how-vulnerable-drivers-let-hackers-in.html)
- [It’ll be back: Attackers still abusing Terminator tool and variants – Sophos News](https://news.sophos.com/en-us/2024/03/04/itll-be-back-attackers-still-abusing-terminator-tool-and-variants/)
- [Bypassing EDR through Retrosigned Drivers and System Time Manipulation](https://www.aon.com/en/insights/cyber-labs/bypassing-edr-through-retrosigned-drivers-and-system-time-manipulation)
  - Retrosigned Drivers extends previous techniques by altering the system clock on the target system to load malicious kernel drivers that were signed by historically compromised expired cross-signing certificates. 

### Sandbox / Container
- [Live off the Land? How About Bringing Your Own Island? An Overview of UNC1945 | Mandiant | Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/live-off-the-land-an-overview-of-unc1945?hl=en)
- [Bring Your Own Container: When Containers Turn the Key to EDR Bypass - Speaker Deck](https://speakerdeck.com/tkmru/byoc-avtokyo2024)
- [Hack The Sandbox: Unveiling the Truth Behind Disappearing Artifacts | JSAC 2025](https://jsac.jpcert.or.jp/archive/2025/pdf/JSAC2025_2_9_kamekawa_sasada_niwa_en.pdf)

### macOS
- [EDR Internals for macOS and Linux | Outflank Security Blog](https://www.outflank.nl/blog/2024/06/03/edr-internals-macos-linux/)
- [In-Memory Execution in macOS: the Old and the New | Meta Red Team X](https://rtx.meta.security/post-exploitation/2022/12/19/In-Memory-Execution-in-macOS.html)

## Book
- [Evading EDR | No Starch Press](https://nostarch.com/evading-edr)

## Other awesome series
- [MrEmpy/Awesome-AV-EDR-XDR-Bypass: Awesome AV/EDR/XDR Bypass Tips](https://github.com/MrEmpy/Awesome-AV-EDR-XDR-Bypass)
