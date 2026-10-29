# Documented censorship behaviours (lab evidence base)

Purpose: every rule in `dotvpn-lab/profiles/*.json` traces to a row here. Nothing in the lab is encoded without a source.

Read on 2026-10-28 from the full issue bodies and comments via the GitHub API, plus the GFW Report USENIX Security '23 page. Papers behind PDFs were not read in full; where a row relies on a paper summary posted in the issue, it says so.

Confidence tags:

- `observed`: measured by the reporter with method and data published.
- `reported`: first-hand claim without published method, or a single vantage.
- `derived`: summary of a peer-reviewed paper written by a third party (the issue poster), not re-checked by us.
- `assumed`: our guess, used only to make a profile runnable. Reports must label these.

Lab fidelity: `yes` (reproducible as written), `partial` (mechanism reproducible, trigger or threshold not), `no`.

## Caveats that apply to every row

- Censors differ by country, ISP, mobile versus fixed, region and week. Row #RU-WL-1 shows the same operator and city behaving differently between base stations. A lab profile is a dated model of one reported behaviour, never "Iran" or "Russia".
- Most Iran data is from datacenter-to-datacenter routes (#676). Residential and mobile lines are not covered.
- Thresholds marked `assumed` are parameters to sweep, not truths.

## Iran

| ID | Mechanism | Detail | Source (date) | Confidence | Lab | Profile rule |
| --- | --- | --- | --- | --- | --- | --- |
| IR-1 | Protocol cut after a few packets | On measured Iran-to-abroad datacenter routes since early Oct 2026, TCP, UDP, GRE, IPIP, SCTP and ESP are cut after a few packets. Only ICMP passes reliably. Random loss 0.2-2 %. | [net4people/bbs#676](https://github.com/net4people/bbs/issues/676) (2026-10-18) | observed (one reporter, several server pairs) | yes | `iran-partition`: allow only ICMP; drop other protocols after N packets (`assumed` N=5) |
| IR-2 | ICMP packet-rate cap | Abroad-to-Iran direction delivers at most about 50-55k ICMP pps, shared by every ICMP type. Queue builds past about 45k pps (p99 one-way delay +300 ms). | #676 | observed | partial (rule and shape yes, absolute pps depends on host) | `throttle pps=50000` on ICMP, parameterised |
| IR-3 | Volume-triggered reroute | Total ICMP held above about 30 MB/s for a few seconds; 5-30 s later route changes (RTT 40 to 76 ms) for minutes; bulk collapses to about 2 MB/s with 50-90 % loss, light traffic fine. Runs at or below about 27 MB/s never triggered. Scope (per IP, AS, global) unknown. | #676 | observed (two events) | partial | `volume-trigger`: bytes/s above threshold for T seconds, then `degrade` (loss + rate cap) for D seconds. Thresholds `assumed` from this one report |
| IR-4 | One-way ICMP block | Some Iran IPs: echo requests Iran to abroad dropped 100 %, abroad to Iran works; comes and goes daily. Non-echo ICMP types pass. | #676 | observed | yes | `direction`-aware ICMP echo drop |
| IR-5 | ICMP size limit | Payloads above about 640 B dropped at first; full 1500 B pass again since at least 2026-10-12. Some hosts have `mtu lock 680` routes. | #676 | observed | yes | `max_payload` rule, off by default in `iran-2026-10`, on in a variant |
| IR-6 | CDN SNI filtering | Iran to Cloudflare over `wss`: every variant without ECH failed right after the TLS handshake (SNI filtering). With ECH it worked (44-48 MB/s). | #676 | observed | yes | `sni_block` on the CDN host; ECH variant passes (ClientHello with ECH extension is not parsed for SNI) |
| IR-7 | ClientHello fragmentation dropped | About 2026-07-27 the TLS-hello fragmentation trick stopped working, even with clean SNIs. Reporter: all fragmented tlshello packets are dropped. | [#640](https://github.com/net4people/bbs/issues/640) (2026-07-31, 3 comments) | reported (single reporter; one reply says REALITY still works, rotating IPs) | yes | `dpi.mode=strict`: reassemble ClientHello; `drop_fragmented_hello` action. `naive` mode keeps the old behaviour for comparison |
| IR-8 | Proxy traffic on domestic servers exposed | Panel fingerprints on domestic servers get servers suspended by the provider. | [#675](https://github.com/net4people/bbs/issues/675) (2026-10-14) | reported | no | none (operational risk, not a packet rule) |
| IR-9 | DPI shared with Chinese product line | Iran is listed in the Geedge analysis scope. Use as architecture reference only. | [#653](https://github.com/net4people/bbs/issues/653) | derived | no | none |

Not found in the reading: a measured Iran protocol allowlist (TLS/DNS/HTTP pass) with thresholds, and Iranian DNS poisoning data. Earlier lab ideas for these are therefore `assumed` and are marked so in the profile (`IR-A1`, `IR-A2` below).

| ID | Mechanism | Confidence | Lab | Profile rule |
| --- | --- | --- | --- | --- |
| IR-A1 | Default-deny UDP/TCP except 53/80/443 at the border | assumed (generic whitelist model) | yes | `iran-2026-10` variant `allowlist` |
| IR-A2 | DNS answer injection for blocked names | assumed (modelled on RU-DNS-1) | yes | `inject_dns` rule, variant only |

## Russia

| ID | Mechanism | Detail | Source (date) | Confidence | Lab | Profile rule |
| --- | --- | --- | --- | --- | --- | --- |
| RU-QUIC-1 | QUIC Initial SNI filtering | TSPU decrypts QUIC v1 Initial packets (keys derive from the public connection ID) and drops those whose SNI is on the blocklist. Since no later than July 2023. Only traffic leaving Russia is affected. All UDP ports, not only 443. QUIC v1 only, not v2. Blocklist closely matches the TCP/TLS SNI blocklist. | [#654](https://github.com/net4people/bbs/issues/654) (2026-08-25), FOCI 2026 paper by Heitmann et al. | derived (paper summary posted by wkrp) | yes | `quic_sni_block`, `version=v1`, any UDP port, direction egress |
| RU-QUIC-2 | Residual censorship | After a blocked Initial, all packets of the same 4-tuple are dropped for 420 s; another blocked Initial restarts the timer. | #654 | derived | yes | `residual_block ttl=420s key=4tuple`, restart on re-trigger |
| RU-QUIC-3 | Historic period B | Until some time between May 2022 and July 2023: first UDP packet to 443 at least 1001 B with QUIC v1 version dropped regardless of SNI, 420 s residual; non-QUIC first packet clears the flow (residual clearance). Kept as variant `russia-quic-2022`. | #654 | derived | yes | variant profile |
| RU-TCP-1 | TCP 16-20 KB cutoff | For non-whitelisted sites behind some CDNs, after about 16-20 KB the connection freezes (no RST). Not applied 24/7. Small whitelist of sites exempt. Checker: [hyperion-cs tcp-16-20](https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/). | [#662](https://github.com/net4people/bbs/issues/662) comment by gohoski (2026-09-02) | reported (home and mobile ISPs, one reporter, no published method; the page itself was a browser tool and I did not read its methodology) | yes | `bytes_cutoff after=16384..20480 action=blackhole` on flagged prefixes. Cutoff is a parameter, sweep it. Exempt SNI list is `assumed` empty |
| RU-TLS-1 | Chrome-default fingerprint blocking | TSPU reportedly blocks standard Chrome TLS fingerprints for many non-Russian IPs, aimed at REALITY. | #662 (same comment) | reported | partial (needs JA3/JA4 in the classifier; exact fingerprints unknown) | `ja3_block` with a user-supplied list, empty by default. Lets Phase 5 fingerprint results feed back in |
| RU-IP-1 | Mass IP bans of popular hosting | 2026-08-04 and 2026-09-21: many REALITY and AmneziaWG server IPs banned, mostly in popular VPS providers. Reported counts: AmneziaHosting 131/20k, FirstByte 3k/29k, Fornex 596/24k, Play2Go DE 2k/37k, VEESP 5k/30k. | [#671](https://github.com/net4people/bbs/issues/671) (2026-09-30) | reported (counts from one reporter, lists attached) | yes | `prefix_block` on a lab-assigned prefix; fraction is a profile parameter |
| RU-IP-2 | Trigger-based temporary block | A "trigger" packet sequence blocks new TCP/UDP connections to the destination for the requesting IP for 10 minutes (reporter links ntc.party/t/4625). One VPS had TCP blocked from all Russia after 130 GB in 8 days, UDP and ICMP still working, unblocked on its own about 2 weeks later. | #671 comment by its0ka (2026-10-02, 2026-10-15) | reported (single reporter, trigger itself not described in the issue) | partial | `residual_block ttl=600s key=src+dst` armed by a configurable trigger; `tcp_only_block` action. Trigger content `assumed` |
| RU-PFX-1 | Prefix collateral on Cloudflare | Initial post claimed Cloudflare reachability follows the IP prefix. The poster later retracted the attribution (the resolver, not the domain, decided the prefix) and the control (namecheap) fails the same way. | #662 and its replies (2026-09-02) | retracted by author | no | none. Recorded so nobody re-derives it. Prefix blocking stays covered by RU-IP-1 |
| RU-DNS-1 | UDP DNS hijack | `nslookup whoami.akamai.net 8.8.8.8` returns a MSK-IX address on many ISPs; `.ua`, whatsapp.com, youtube.com etc. return NXDOMAIN on UDP to 8.8.8.8; TCP DNS to 8.8.8.8 is fine. AAAA also NXDOMAIN. | [#657](https://github.com/net4people/bbs/issues/657) (2026-08-26) | observed (one reporter, command lines given) | yes | `dns_intercept proto=udp port=53 names=[list] action=nxdomain|redirect`; TCP and DoH untouched |
| RU-DNS-2 | DNS interception is on-path, close to the user | A TTL-2 A query reaches the real resolver and gets the real answer; random UDP/53 junk with TTL 2 does not bypass interception. Interception starts at TTL 5 from one router. A TTL-64 duplicate gets a fake NXDOMAIN with TTL 60 versus real answer TTL 109. | #657 comment by agent188 (2026-08-27) | observed | partial (injector lives in the border namespace with an adjustable hop distance) | `dns_intercept hop=5` |
| RU-DNS-3 | Resolver SNI block flapping | `dns.google` SNI was blocked for a few days, then unblocked. | #657 | reported | yes | `sni_block` list entry with expiry |
| RU-TUN-1 | Possible TUN-mode detection | On one Beeline mobile line, TUN mode led to heavy degradation within 5-15 min, then total loss except `max.ru`, for all devices behind the hotspot; system-proxy mode fine; fixed by disconnecting and rebooting the router. Replies suggest DNS settings, connection-count or Telegram sniffing as likelier causes. | [#663](https://github.com/net4people/bbs/issues/663) (2026-09-02, 4 comments) | reported, unresolved, likely not a detector | partial | `conn_rate` rule: many new flows per minute from one source, then degrade. Used only as a stress profile, `assumed` threshold, never claimed as TUN detection |
| RU-WL-1 | Mobile whitelist, uneven | Operator allows only a pre-approved list; behaviour differs by operator, base station, even IPv4 versus IPv6 after reattach. Public CIDR lists are unreliable in both directions; one commenter's 700+ floating IPs across five regions had none in a permitted /24; only an on-SIM, same-day test is trusted. Some users see total blackout including whitelisted sites. | [#650](https://github.com/net4people/bbs/issues/650) (2026-08-19 and comments to 2026-10-12) | reported (several vantages, mostly MTS) | partial | `russia-2026-10` variant `whitelist`: default deny plus an allowlist of prefixes and SNIs. Prefixes and SNI list are the lab's own. No claim about real lists |

## Reference (China, for entropy and probing rules)

| ID | Mechanism | Detail | Source | Confidence | Lab | Profile rule |
| --- | --- | --- | --- | --- | --- | --- |
| CN-ENT-1 | Fully-encrypted-traffic heuristic | Block unless the first client payload satisfies an exemption. Ex1: popcount/len at most 3.4 or at least 4.6 (bits per byte). Ex2: first 6+ bytes in 0x20-0x7e. Ex3: more than 50 % of bytes in 0x20-0x7e. Ex4: more than 20 contiguous bytes in 0x20-0x7e. Ex5: matches the TLS or HTTP protocol fingerprint. Applied to certain destination subnets, with probabilistic blocking. | [GFW Report, USENIX Security 2023, Algorithm 1](https://gfw.report/publications/usenixsecurity23/en/) | observed (peer reviewed, read directly) | yes | `entropy_class` rule, `profiles/china-reference.json` |
| CN-ENT-2 | Commercial DPI entropy scoring | `entropy_score` in Qosmos qdpi_detector takes a buffer and returns 0-10000 from the proportion of zero bits and bit runs; configuration names `entropy_threshold`, `printable_char_seq_threshold`, `char_occur_threshold`. Author says details do not exactly match the China classifier above. | [#677](https://github.com/net4people/bbs/issues/677) (2026-10-21), leak in [#519](https://github.com/net4people/bbs/issues/519) | observed (reverse engineering by wkrp; exact function not re-implemented here) | no | none. CN-ENT-1 is the only entropy rule the lab encodes |
| CN-LEAK-1 | Architecture of a real DPI | Geedge TSG source analysed: protocols it parses, rule format, fingerprints such as custom RNGs and parsing quirks. | #653 (USENIX Security 2026) | derived (PDF not read in full) | no | informs rule format only |

## Circumvention side evidence

| ID | Finding | Source | Confidence | Use in the lab |
| --- | --- | --- | --- | --- |
| CIRC-1 | Patterniha `SNI-Spoofing` (README: "Bypass DPI with IP/TCP-Header manipulation") and `MITM-DomainFronting` (README: spoofs the origin identity locally to receive plain data, then sends upstream with a fake SNI via domain fronting; the author lists YouTube, Instagram, WhatsApp, Facebook, Reddit and some Fastly sites as reachable on 2026-05-31, and says it is not for full internet access). | [github.com/patterniha](https://github.com/patterniha) READMEs only; the source code was not read | reported | Evidence that a DPI which checks only the SNI of the first packets can be fooled. The lab therefore keeps `dpi.mode=naive` versus `strict`. It does not by itself justify building the desync carriers excluded in `REPORT.md` |
| CIRC-2 | ECH defeats the Iranian CDN SNI block in one measurement (see IR-6). | #676 | observed | `ech` variant of IR-6 |
| CIRC-3 | REALITY still works in Iran with IP rotation (one reporter). | #640 comment 2026-08-03 | reported | context only |

## Corrections to the earlier chat evaluation

- #662 and "IP-prefix collateral": retracted by its author. The Russian prefix finding rests on #671 only.
- #663 is not established TUN detection. The thread points to DNS or connection-count causes.
- #650 "mobile whitelist": real but uneven and unmodelable to exact lists. The lab models the mechanism (default deny plus an allowlist) only.
- Iran "allowlist of TLS/DNS/HTTP" and "DNS poisoning" had no source in the issues read. They are `assumed` and variant-only.
- The "about 50k pps cap" is an ICMP-only measurement on specific datacenter routes. It does not describe ordinary TCP traffic.
- Russian QUIC filtering is egress-only, v1-only, all UDP ports, with 420 s residual blocking, which is stricter than "port 443".

## Source index

- net4people/bbs: #519, #640, #650, #653, #654, #657, #662, #663, #671, #675, #676, #677.
- Wu et al., "How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic", USENIX Security 2023, Algorithm 1 (page read).
- Heitmann et al., FOCI 2026, paper on Russian QUIC SNI censorship (summary only; data at `UPB-SysSec/RussiaQuicResults`).
- Ablove et al., USENIX Security 2026, Geedge leak analysis (summary only).
- Reviewed but not used for rules: OONI and IODA were not queried in this pass. Add rows from them when a profile needs scope or dates.
