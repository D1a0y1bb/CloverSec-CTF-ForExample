# Research Intake Reference

## Result Layers

Search results must keep `source_url`, `title`, `snippet`, `provider`, `confidence`, `evidence`, `layer`, `score`, and `quality_issues`.

Layer meanings:

- `confirmed_challenge`: a specific challenge has event, year, and challenge-name evidence.
- `writeup_candidate`: writeup, WP, source notes, or article evidence exists, but attachment/source package is not confirmed.
- `attachment_candidate`: direct archive, GitHub Release asset, raw file, or likely attachment/source package.
- `platform_lead`: CTFTime, NSSCTF, CTFHub, BUUOJ, or similar platform homepage; also set `lead_only=true`.
- `noise`: unrelated event, tutorial, search page, login page, captcha page, or broad article.

Filtering:

- Match event names strongly. `IrisCTF` must not accept `NepCTF` or `Compfest CTF`.
- Support spaced event names such as `LA CTF` and compact variants such as `LACTF`.
- Require a specific challenge term before promoting to `confirmed_challenge`.
- Keep platform homepages as `platform_lead`.
- Mark search engines, login pages, and captcha pages as `noise`.

## Default Sources

Default free sources:

- GitHub repository search.
- GitHub code search through `GITHUB_TOKEN`, `GH_TOKEN`, or local `gh auth token`.
- CTFTime events/writeups.
- DuckDuckGo HTML.
- Public archive seeds.
- CTF platform seeds as `platform_lead`.
- CSDN, Cnblogs, and Yuque site search through DuckDuckGo.

Do not require paid search API keys.

## Agent Web Search

If the current Agent has web search, use it first for Google/Baidu/all-web coverage. Import visible results through:

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py import-agent-search \
  --input agent_web_results.json \
  --query "IrisCTF 2025 web writeup" \
  --provider agent-web-search \
  --output search_results.agent.json
```

## Browser-Assisted Search

Use `cloversec-ctf-browser-search` for Google/Baidu/CSDN/Cnblogs/Yuque pages that may need a real browser. It only reads visible titles, URLs, snippets, ranks, and blocked status. It must not read Cookie, token, localStorage, sessionStorage, passwords, or captcha data.

## Commands

```bash
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py discover \
  --query "LA CTF 2024 web challenge writeup" \
  --year 2024 \
  --limit 20 \
  --output search_results.json \
  --cases-jsonl ctf_cases.jsonl

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_search.py ctftime-events \
  --year 2025 \
  --output ctftime_events_2025.json

python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py migrate-xlsx <旧表.xlsx> ctf_cases.jsonl
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py research-report ctf_cases.jsonl research_report.md
python3 plugins/cloversec-ctf-forexample/scripts/cloversec_ctf_collect.py validate-collection ctf_cases.jsonl
```

## Stop Conditions

Stop and ask the user when a source requires payment, login, captcha, unclear permission, large-scale scraping, or cannot be judged authentic.
