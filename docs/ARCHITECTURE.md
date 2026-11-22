# Architecture

## Design goals

APKInspector separates the public interface from CPU-intensive static analysis.
This keeps the dashboard fast while allowing the analyzer to run in a bounded
Docker container with the Android and Python tooling it needs.

## Request flow

1. The browser validates the selected file name, extension, and size.
2. The browser uploads the APK directly to the FastAPI service.
3. The service verifies the ZIP structure and applies archive safety limits.
4. Static analyzers inspect the manifest, certificate, DEX files, resources,
   and native libraries without executing application code.
5. A deterministic rule engine produces findings and an explainable score.
6. The temporary workspace and uploaded file are deleted.

## Trust boundaries

Uploaded APKs are hostile input. The API never imports code from an archive,
invokes an Android runtime, or writes archive members using untrusted paths.
Analysis has explicit limits for file size, archive entries, decompressed size,
and processing time.

## Deployment

The Next.js application is designed for Vercel. The FastAPI service is designed
for Render using its Dockerfile. Production origins and API URLs are supplied
through environment variables.
