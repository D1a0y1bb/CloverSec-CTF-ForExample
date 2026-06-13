# Public Source Smoke Validation

Date: 2026-06-13

Validated with:

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py ctftime-events --year 2025 --limit 5 --output ctftime_events.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover --query "LA CTF 2024 web challenge writeup" --year 2024 --source github --source ctftime --source duckduckgo --source seeds --limit 10 --output discover.json --cases-jsonl cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py fetch-url https://github.com/uclaacm/lactf-archive --output github_archive_fetch.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py fetch-url https://ctftime.org/writeup/40461 --output writeup_fetch.json
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py download-url https://raw.githubusercontent.com/uclaacm/lactf-archive/main/README.md --filename lactf-archive-README.md --output-dir downloads --output direct_download.json
```

Observed results:

| Scenario | Result |
| --- | --- |
| CTFTime 2025 events | 5 events returned; first result: `IrisCTF 2025` |
| Public search mix | 33 results returned for LA CTF query; providers included CTFTime, DuckDuckGo and seeds; GitHub code search skipped without token |
| GitHub archive fetch | HTTP 200; title: `GitHub - uclaacm/lactf-archive...`; SHA256 prefix `d3e7f9455234` |
| Specific writeup fetch | HTTP 200; title: `CTFtime.org / EnigmaXplore 3.0 / Announce Your Name / Writeup`; SHA256 prefix `d0093f0b62ca` |
| Direct URL download | HTTP 200; `lactf-archive-README.md`; 209 bytes; SHA256 prefix `5027ed7f2775` |

Notes:

- A filtered CTFTime query for `LA CTF` in 2025 returned zero events. The unfiltered yearly event path works and should be used before narrowing.
- No GitHub, Brave or Bing API key was used. Key-backed source quality still needs user-provided keys.
