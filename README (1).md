# Release Gate

A deterministic policy endpoint for CI/CD container release decisions.

## Endpoint

`POST /release-gate`

Takes a JSON payload describing a GitHub Actions run + Docker image, and returns:

```json
{"decision": "promote | block", "violations": ["CODE", "..."]}
```

## Run locally

```bash
npm install
npm start
```

Server listens on port 3000 (or `$PORT`).

## Run tests

```bash
npm test
```

Runs 20 checks covering all 11 violation codes individually, safe/valid
payloads, and a combined multi-failure payload.

## Deploy

Deploy anywhere that runs Node.js and exposes a public HTTPS URL (Render,
Railway, Fly.io, a VPS, etc.). Make sure the app binds to `process.env.PORT`
(it already does) and stays running — the grader hits this endpoint live.

## GitHub Actions evidence

`.github/workflows/release-gate.yml` runs on every push to `main`, named
`TDS GA7 Release Gate`, and includes a step named
`TDS identity: 25ds1000076@ds.study.iitm.ac.in`.
