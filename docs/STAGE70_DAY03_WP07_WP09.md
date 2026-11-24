# Cyber Security 2.0 — Stage70 Day03 WP07–WP09

**LAB-ONLY, NEVER PRODUCTION.** Base: Day02 commit `82c9cb9a35ccf8650ca85368155163d9d9b5dc5b`. This is opt-in bounded Spider/Passive and separately guarded Ajax Spider integration. Not registered in normal scan-job workers. No ZAP Active Scan.

Only `http://day03-target:8080/` is permitted, inside a dedicated verified Docker network with `Internal=true` and exactly two containers. ZAP API is bound to host `127.0.0.1:18080`. Supply independently verified digest-pinned `CYBERSEC_DAY03_ZAP_IMAGE` and `CYBERSEC_DAY03_TARGET_IMAGE` in `repository@sha256:64hex` form. Supply a fresh 24+ character `CYBERSEC_DAY03_ZAP_API_KEY`. Do not publish secrets: Docker administrators can inspect container configuration.

Commands from application root, after installing its venv:
```bash
docker compose -f deployment/day03/compose.lab.yml config -q
docker compose -f deployment/day03/compose.lab.yml up -d
bash Stage70_DAY03_ZAP.command --review
bash Stage70_DAY03_ZAP.command --check
bash Stage70_DAY03_ZAP.command --run --authorize-local-lab
# Only with isolated headless Firefox available:
bash Stage70_DAY03_ZAP.command --run --authorize-local-lab --ajax
docker compose -f deployment/day03/compose.lab.yml down --volumes
```

**Bounds:** Spider depth 2, children 8, threads 1, 35s; passive queue 20s, alerts 100; Ajax states 8, one Firefox Headless, Strict scope, 35s, no random inputs. No redirects or ambient proxies in the ZAP API client. The key is sent in `X-ZAP-API-Key` header only. Docker runtime inspection verifies network isolation, container resource restrictions, port binding, image digests, and network members before scanning.

The mock E2E is `MOCK_ZAP_ONLY`, NOT a real ZAP scan. Docker/browser absent => `SKIP/NOT_EXECUTED`, not PASS. Source code tests, CI and local mock are distinct from real lab evidence. No permission to scan any external/third-party target. Stage70 production is BLOCKED/NO-GO; 0/10 gates, 0/92 scenarios; Stage71 NOT_OPENED.

Official references: https://www.zaproxy.org/docs/api/ ; https://www.zaproxy.org/docs/docker/about/ ; https://www.zaproxy.org/docs/desktop/addons/spider/options/ ; https://www.zaproxy.org/docs/desktop/addons/ajax-spider/ .
