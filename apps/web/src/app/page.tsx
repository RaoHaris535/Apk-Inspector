import {
  Binary,
  FileKey2,
  Fingerprint,
  GitFork,
  Radar,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";

import { UploadPanel } from "@/components/upload-panel";

const inspectionAreas = [
  {
    icon: FileKey2,
    title: "Manifest security",
    text: "Review permissions, exported components, backup settings, debug mode, cleartext traffic, and SDK targets.",
  },
  {
    icon: Fingerprint,
    title: "Signing identity",
    text: "Inspect signing certificates and compare fingerprints with a trusted copy to uncover possible repackaging.",
  },
  {
    icon: Binary,
    title: "Code indicators",
    text: "Surface dynamic loading, suspicious endpoints, embedded secrets, persistence hooks, overlays, and native code.",
  },
];

const reportRows = [
  { severity: "High", finding: "Debug mode enabled", area: "Manifest", tone: "danger" },
  { severity: "Medium", finding: "Cleartext traffic permitted", area: "Network", tone: "warning" },
  { severity: "Info", finding: "Certificate fingerprint recorded", area: "Signing", tone: "info" },
];

export default function Home() {
  return (
    <main>
      <nav className="site-nav" aria-label="Primary navigation">
        <a className="brand" href="#top" aria-label="APKInspector home">
          <span className="brand-mark"><ScanSearch aria-hidden="true" /></span>
          <span>APKInspector</span>
        </a>
        <div className="nav-links">
          <a href="#capabilities">Capabilities</a>
          <a href="#report">Report</a>
          <a href="#privacy">Privacy</a>
        </div>
        <a className="nav-action" href="https://github.com/RaoHaris535/Apk-Inspector">
          <GitFork aria-hidden="true" />
          GitHub
        </a>
      </nav>

      <section className="hero" id="top">
        <div className="hero-copy">
          <p className="eyebrow"><span /> Static Android security analysis</p>
          <h1>See what is inside an APK <em>before</em> it reaches your phone.</h1>
          <p className="lede">
            APKInspector translates Android manifests, signatures, and code
            indicators into a clear, explainable security report. No installation.
            No execution. Just evidence.
          </p>
          <div className="hero-points" aria-label="Analysis guarantees">
            <span><ShieldCheck aria-hidden="true" /> Static analysis only</span>
            <span><Radar aria-hidden="true" /> Transparent scoring</span>
          </div>
        </div>
        <UploadPanel />
      </section>

      <section className="signal-bar" aria-label="Inspection coverage">
        <span>Manifest</span><i />
        <span>Permissions</span><i />
        <span>Certificates</span><i />
        <span>DEX code</span><i />
        <span>Native libraries</span>
      </section>

      <section className="section capabilities" id="capabilities">
        <div className="section-heading">
          <p className="section-kicker">Complete inspection</p>
          <h2>One upload. Multiple layers of evidence.</h2>
          <p>Every result connects a technical signal to its security impact and a practical remediation.</p>
        </div>
        <div className="capability-grid">
          {inspectionAreas.map(({ icon: Icon, title, text }, index) => (
            <article className="capability-card" key={title}>
              <div className="card-index">0{index + 1}</div>
              <Icon aria-hidden="true" />
              <h3>{title}</h3>
              <p>{text}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="section report-section" id="report">
        <div className="report-copy">
          <p className="section-kicker">Evidence, not alarms</p>
          <h2>A score you can actually understand.</h2>
          <p>
            Findings are grouped by severity and include the observed evidence,
            affected component, risk explanation, and recommended action. The final
            score is a transparent sum of those findings—not a black box.
          </p>
          <ul className="check-list">
            <li><span>01</span>Prioritized security findings</li>
            <li><span>02</span>Certificate and package identity</li>
            <li><span>03</span>Downloadable analysis report</li>
          </ul>
        </div>
        <div className="report-preview" aria-label="Illustrative security report preview">
          <div className="preview-head">
            <div>
              <span className="preview-label">Illustrative report</span>
              <strong>com.example.demo</strong>
            </div>
            <div className="score-orbit">
              <span>62</span><small>Risk score</small>
            </div>
          </div>
          <div className="preview-summary">
            <span><b>3</b> findings</span>
            <span><b>34</b> permissions</span>
            <span><b>8</b> components</span>
          </div>
          <div className="finding-list">
            {reportRows.map((row) => (
              <div className="finding-row" key={row.finding}>
                <span className={`severity ${row.tone}`}>{row.severity}</span>
                <strong>{row.finding}</strong>
                <span>{row.area}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="privacy-strip" id="privacy">
        <div className="privacy-icon"><ShieldCheck aria-hidden="true" /></div>
        <div>
          <p className="section-kicker">Built for hostile input</p>
          <h2>Your APK is analyzed, then removed.</h2>
        </div>
        <p>
          Uploaded files are handled in a temporary workspace, never executed,
          and deleted when analysis completes. Archive size and path protections
          keep the service bounded.
        </p>
      </section>

      <footer>
        <div className="brand footer-brand">
          <span className="brand-mark"><ScanSearch aria-hidden="true" /></span>
          <span>APKInspector</span>
        </div>
        <p>Defensive Android analysis for education and security review.</p>
        <p>Open source · MIT License</p>
      </footer>
    </main>
  );
}
