# APKInspector

APKInspector is an explainable static security analyzer for Android APK files.
It turns permissions, manifest configuration, signing identity, DEX indicators,
native libraries, and trusted-package differences into a prioritized report
without installing or executing the application.

[![CI](https://github.com/RaoHaris535/Apk-Inspector/actions/workflows/ci.yml/badge.svg)](https://github.com/RaoHaris535/Apk-Inspector/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-69f0b0.svg)](LICENSE)
[![Web interface](https://img.shields.io/badge/live-Vercel-69f0b0.svg)](https://apk-inspector-snowy.vercel.app)
[![API health](https://img.shields.io/badge/API-Render-69f0b0.svg)](https://apk-inspector-api.onrender.com/api/v1/health)

> APKInspector provides security indicators for education and defensive
> review. It is not a replacement for antivirus software or a complete mobile
> application security assessment.

## Try it

- **Live interface:** [apk-inspector-snowy.vercel.app](https://apk-inspector-snowy.vercel.app)
- **API health:** [apk-inspector-api.onrender.com/api/v1/health](https://apk-inspector-api.onrender.com/api/v1/health)
- **OpenAPI documentation:** [apk-inspector-api.onrender.com/api/docs](https://apk-inspector-api.onrender.com/api/docs)

No APK is required for a first look. Select **View safe demonstration report**
on the live interface to explore a complete, non-sensitive example. To test a
real upload, use an APK that you own or are authorized to inspect and keep it
below 100 MB.

## Classroom-safe demonstration APK

The repository includes a deliberately insecure but behaviorally harmless APK
fixture under [`samples/safe-insecure-demo`](samples/safe-insecure-demo). It
declares realistic static red flags but contains no sensitive or malicious
behavior. The generated APK is intentionally unsigned, so it should be uploaded
to APKInspector and **not installed on a device**.

To download a prebuilt copy:

1. Open [GitHub Actions](https://github.com/RaoHaris535/Apk-Inspector/actions/workflows/demo-apk.yml).
2. Open the latest successful **Build classroom demo APK** run.
3. Download the `apkinspector-safe-insecure-demo` artifact.
4. Extract the ZIP and upload the `.apk` file to the live interface.

The sample source, safety explanation, local build command, and expected output
are documented in its [README](samples/safe-insecure-demo/README.md).

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

The backend test suite uses `coverage run -m pytest` followed by
`coverage report` and enforces at least 85% statement coverage. GitHub Actions
runs frontend linting, tests, and production compilation plus backend linting
and tests on pushes and pull requests.

### Manual smoke test

1. Open the [live interface](https://apk-inspector-snowy.vercel.app) and confirm
   the analyzer status changes to **Analyzer online**.
2. Open the safe demonstration report, export its JSON, and test print-to-PDF.
3. Upload an APK you control and confirm a report is generated.
4. Enable trusted comparison and select two authorized APK variants.
5. Check the [API health endpoint](https://apk-inspector-api.onrender.com/api/v1/health)
   if Render is waking from an idle period.

## Deployment

Deploy the Docker API to Render and the Next.js application to Vercel. Follow
[the deployment guide](docs/DEPLOYMENT.md) for the required root directory,
environment variables, CORS update, and production verification.

## License

APKInspector is available under the MIT License.
