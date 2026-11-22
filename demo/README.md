# Safe demonstration material

APKInspector does not include malware or third-party APK binaries. The web
application includes a clearly labeled synthetic report that demonstrates the
reporting workflow using intentionally insecure configuration values.

For a live class demonstration, use APKs built and owned by the project team:

1. A minimal release APK with current SDK targets and no sensitive permissions.
2. An intentionally insecure training APK with debug mode, backup, cleartext
   traffic, a controlled exported component, and placeholder-only test secrets.
3. A second team-built variant signed with a different demonstration key for
   comparison and possible-repackaging detection.

Never upload real credentials, private applications, malware, or APKs the team
does not have permission to inspect. The string `demo.invalid` is reserved for
documentation and does not contact a real service.
