# APKInspector Safe Insecure Demo

This sample is a deliberately insecure but behaviorally harmless Android APK
for demonstrating APKInspector. It is **not malware** and contains no code that
reads messages, records audio, accesses the camera, collects location, starts at
boot, downloads code, executes commands, or communicates over the network.

The sample intentionally declares risky settings and permissions so the static
analyzer has realistic evidence to report:

- debugging, backups, and cleartext traffic enabled;
- an outdated target SDK;
- SMS, overlay, camera, microphone, location, contacts, and installation
  permissions;
- inert exported service and receiver components;
- placeholder URLs and fake credentials under the reserved `demo.invalid`
  domain;
- static strings resembling dynamic loading and process execution indicators;
- a harmless placeholder entry under the native-library directory.

The generated APK is intentionally unsigned. Do not install it. Upload it to
APKInspector directly from the browser and delete it after the demonstration.

## Build

Download the official Apktool JAR, then run:

```bash
APKTOOL_JAR=/absolute/path/to/apktool.jar sh samples/safe-insecure-demo/build.sh
```

The APK is written to:

```text
samples/safe-insecure-demo/dist/apkinspector-safe-insecure-demo.apk
```

Build output is ignored by Git.
