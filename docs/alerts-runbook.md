# Relay Alerts and Runbook (v1)

This is the initial operator runbook for relay observability.

## Endpoints

- `/-/healthz`: process health (`200 ok` when process is running).
- `/-/readyz`: readiness (`200 ready` when SSH + Tier 1 listeners are up).
- `/metrics`: plaintext counters.

Default bind is local-only:

```bash
SISUMAIL_OBS_LISTEN=127.0.0.1:9090
```

## Suggested Alerts

- Readiness down:
  - Condition: `/-/readyz` is non-200 for 2 minutes.
  - Action: check relay service and bound ports.
- Tier1 no-session spikes:
  - Metric: `sisumail_tier1_reject_no_session_total`.
  - Condition: increase > 200 in 5 minutes.
  - Action: verify user node availability and session churn.
- Tier1 source-cap spikes:
  - Metric: `sisumail_tier1_reject_source_cap_total`.
  - Condition: increase > 100 in 5 minutes.
  - Action: inspect source IP concentration; apply network filtering as needed.
- Tier1 channel open instability:
  - Metrics: `sisumail_tier1_channel_open_timeout_total`, `sisumail_tier1_channel_open_error_total`.
  - Condition: either increases steadily for 10 minutes.
  - Action: inspect SSH gateway saturation and host resource pressure.
- Chat abuse pressure:
  - Metric: `sisumail_chat_send_limited_total`.
  - Condition: increase > 300 in 5 minutes.
  - Action: lower chat send limits or block abusive sources.

Tune thresholds for your traffic profile; these are safe starting points for early alpha.

## First Response Steps

1. `systemctl status sisumail-relay --no-pager`
2. `journalctl -u sisumail-relay -n 200 --no-pager`
3. `curl -fsS http://127.0.0.1:9090/-/readyz`
4. `curl -fsS http://127.0.0.1:9090/metrics | sed -n '1,80p'`
5. `ss -lntp | rg '(:2222|:2525|:9090)'`

## Emergency Mitigation Levers

- Tighten Tier1 source caps:
  - `SISUMAIL_TIER1_MAX_CONNS_PER_SOURCE`
- Tighten Tier1 byte/duration budgets:
  - `SISUMAIL_TIER1_MAX_BYTES_PER_CONN`
  - `SISUMAIL_TIER1_MAX_CONN_DURATION_MS`
- Tighten chat throughput:
  - `-chat-send-per-min`
  - `-chat-send-per-user-per-min`

After edits:

```bash
systemctl restart sisumail-relay
```
