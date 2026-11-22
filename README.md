# APKInspector

APKInspector is an explainable static security analyzer for Android APK files.
It turns permissions, manifest configuration, signing identity, DEX indicators,
native libraries, and trusted-package differences into a prioritized report
without installing or executing the application.

[![CI](https://github.com/RaoHaris535/Apk-Inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/RaoHaris535/Apk-Inspector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-69f0b0.svg)](LICENSE)

> APKInspector provides security indicators for education and defensive
> review. It is not a replacement for antivirus software or a complete mobile
> application security assessment.

## Architecture

- `apps/web`: Next.js dashboard deployed to Vercel.
- `services/api`: FastAPI analysis service deployed as a Docker container.
- `docs`: architecture, scoring, deployment, and demonstration guidance.

The browser sends APK files directly to the analysis API. Each upload is
validated, processed in an isolated temporary directory, and deleted after the
report is produced.

## What it detects

- Application identity, SDK range, permissions, declared components, libraries,
  signature schemes, and certificate fingerprints.
- Debuggable builds, backups, cleartext networking, legacy targets, exported
  components, high-impact permissions, and risky permission combinations.
- Dynamic code loading, runtime process execution, accessibility-service
  indicators, endpoints, credential-like strings, and bundled native libraries.
- Certificate, permission, component, endpoint, native-library, and risk-score
  differences from a trusted reference APK.

Every scored finding includes observed evidence, an impact explanation, a
recommended action, and its exact contribution to the final 0–100 score.

## Local development

### Docker

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:3000`. The API health endpoint is available at
`http://localhost:8000/api/v1/health`.

### Without Docker

Frontend:

```bash
npm install
npm run dev
```

Backend:

```bash
cd services/api
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.main:app --reload
```

## Project status

The core analyzer, comparison workflow, reports, tests, Docker environment, and
deployment configuration are implemented. See the [demonstration guide](docs/DEMO_GUIDE.md),
[deployment guide](docs/DEPLOYMENT.md), and [architecture](docs/ARCHITECTURE.md).

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Container health check |
| `POST` | `/api/v1/analyze` | Analyze one APK |
| `POST` | `/api/v1/compare` | Compare an APK with a trusted reference |

Interactive OpenAPI documentation is available at `/api/docs` while the API is
running.

## Quality checks

```bash
npm run lint
npm run test
npm run build
docker build --target test -t apkinspector-api-test services/api
docker run --rm apkinspector-api-test
```

The backend test suite enforces at least 85% statement coverage. GitHub Actions
runs frontend linting, tests, and production compilation plus backend linting
and tests on pushes and pull requests.

## Deployment

Deploy the Docker API to Render and the Next.js application to Vercel. Follow
[the deployment guide](docs/DEPLOYMENT.md) for the required root directory,
environment variables, CORS update, and production verification.

## License

APKInspector is available under the MIT License.
