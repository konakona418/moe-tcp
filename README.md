# moe-tcp

This is a naive implementation of RFC 791 & RFC 793 TCP/IP protocol stack for my assignment of **Computer Network U14M11007**. BTW there's a ICMP echo server implementation embedded. You can ping it if you want.

The original assignment was 'to demostrate how TCP/IP (or similar reliable protocols) work with **Java** or _other languages_'. However I somehow misinterpreted it. The lecturer's intention was something like an animation program with some colorful stuff moving around, but I thought that the best way to demonstrate how it works is to write a REAL ONE.

I made the first few versions for submission by myself, with AI-assisted inline completion but no coding agent involved. At first I thought the assignment is due today (26/04/20), so I wrote everything in a hurry, and it was pretty messed up. However the lecturer told me that if I keep working on this project, it's okay to postpone the DDL for me because that's far beyond the original expectation - and it's also okay to use coding agents.

So, I used GPT-5.3-Codex to clean up my code, find some hazards or spec violations and implemented Reno style congestion control for me. Of course I went over the code, and it seems to be working just fine.

I still didn't handle SACKS which are necessary for out-of-order packs. And still, a lot of corner cases need to be handled properly. But the current version is sufficient for an echo server.

李梓萌 2024303504
