# APKInspector

APKInspector is a web-based static security analyzer for Android APK files. It
explains risky permissions, insecure manifest configuration, signing details,
code indicators, native libraries, and differences from a trusted reference
without installing or executing the application.

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

The project is under active development. See [the roadmap](docs/ROADMAP.md)
for the planned milestones.

## License

APKInspector is available under the MIT License.
