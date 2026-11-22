# Deployment guide

APKInspector uses two services. Deploy the Docker analysis API to Render first,
then deploy the Next.js interface to Vercel with the API URL.

## Render API

1. Open the Render dashboard and select **New** then **Blueprint**.
2. Connect `RaoHaris535/Apk-Inspector`.
3. Render detects `render.yaml` and proposes `apk-inspector-api` on the free plan.
4. Set `APKINSPECTOR_ALLOWED_ORIGINS` temporarily to
   `http://localhost:3000`. After Vercel is deployed, replace it with the exact
   Vercel production origin, such as `https://apk-inspector.vercel.app`.
5. Apply the Blueprint and wait for `/api/v1/health` to report `healthy`.
6. Copy the resulting `https://...onrender.com` service URL without a trailing
   slash.

Free Render services sleep after inactivity. The first analysis after a sleep
can take longer while the container starts. Uploaded APKs remain temporary and
are deleted at the end of each request.

## Vercel web application

1. In Vercel, select **Add New Project** and import `Apk-Inspector`.
2. Set **Root Directory** to `apps/web`.
3. Keep the detected framework as Next.js.
4. Add `NEXT_PUBLIC_API_URL` with the Render service URL.
5. Deploy the project.
6. Copy the production Vercel origin and update
   `APKINSPECTOR_ALLOWED_ORIGINS` in Render. Do not include a trailing slash.
7. Trigger a Render redeploy and verify that an APK can be uploaded from the
   Vercel site.

## Production verification

```bash
curl --fail https://YOUR-RENDER-SERVICE.onrender.com/api/v1/health
```

In the browser:

- Open the Vercel production URL.
- Open the safe demonstration report.
- Upload a team-owned APK smaller than 100 MB.
- Confirm the analysis report appears and browser developer tools show no CORS
  error.
- Export JSON and test the print-to-PDF layout.

## Environment variables

| Service | Variable | Required value |
| --- | --- | --- |
| Vercel | `NEXT_PUBLIC_API_URL` | Full Render origin |
| Render | `APKINSPECTOR_ALLOWED_ORIGINS` | Full Vercel origin |
| Render | `APKINSPECTOR_MAX_UPLOAD_MB` | `100` by default |
| Render | `APKINSPECTOR_ANALYSIS_TIMEOUT_SECONDS` | `180` by default |

Do not place credentials in `NEXT_PUBLIC_*` variables because those values are
included in browser JavaScript.
