"use client";

import { ChangeEvent, DragEvent, useRef, useState } from "react";
import { Beaker, FileArchive, GitCompareArrows, LoaderCircle, LockKeyhole, Upload, X } from "lucide-react";
import { useRouter } from "next/navigation";

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;
type UploadState = "idle" | "ready" | "uploading" | "error";

function formatBytes(bytes: number) {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${Math.ceil(bytes / 1024)} KB`;
}

export function UploadPanel() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement>(null);
  const referenceInputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [referenceFile, setReferenceFile] = useState<File | null>(null);
  const [compareMode, setCompareMode] = useState(false);
  const [state, setState] = useState<UploadState>("idle");
  const [message, setMessage] = useState("");
  const [isDragging, setIsDragging] = useState(false);

  const validateFile = (candidate?: File) => {
    if (!candidate) return;
    if (!candidate.name.toLowerCase().endsWith(".apk")) {
      setState("error");
      setMessage("Choose a valid Android APK file.");
      return false;
    }
    if (candidate.size > MAX_UPLOAD_BYTES) {
      setState("error");
      setMessage("The selected APK is larger than 100 MB.");
      return false;
    }
    return true;
  };

  const acceptFile = (candidate?: File) => {
    if (!candidate || !validateFile(candidate)) return;
    setFile(candidate);
    setState("ready");
    setMessage("");
  };
  const acceptReference = (candidate?: File) => {
    if (!candidate || !validateFile(candidate)) return;
    setReferenceFile(candidate);
    setState(file ? "ready" : "idle");
    setMessage("");
  };

  const onInput = (event: ChangeEvent<HTMLInputElement>) => acceptFile(event.target.files?.[0]);
  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    acceptFile(event.dataTransfer.files?.[0]);
  };
  const clear = () => {
    setFile(null);
    setState("idle");
    setMessage("");
    if (inputRef.current) inputRef.current.value = "";
  };

  const analyze = async () => {
    if (!file) return;
    setState("uploading");
    setMessage("Uploading securely and inspecting the package…");
    const form = new FormData();
    form.append("file", file);
    if (compareMode && referenceFile) form.append("reference_file", referenceFile);

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
      const endpoint = compareMode ? "/api/v1/compare" : "/api/v1/analyze";
      const response = await fetch(`${apiUrl}${endpoint}`, { method: "POST", body: form });
      if (!response.ok) {
        const error = await response.json().catch(() => null);
        throw new Error(error?.detail?.message ?? "Analysis service did not accept the APK.");
      }
      const result = await response.json();
      const report = compareMode ? result.submitted : result;
      sessionStorage.setItem("apkinspector:last-report", JSON.stringify(report));
      if (compareMode) sessionStorage.setItem("apkinspector:last-comparison", JSON.stringify(result));
      else sessionStorage.removeItem("apkinspector:last-comparison");
      router.push("/report");
    } catch (error) {
      setState("error");
      setMessage(error instanceof Error ? error.message : "Analysis could not be started.");
    }
  };

  const openDemo = async () => {
    const response = await fetch("/demo/insecure-report.json");
    const report = await response.json();
    sessionStorage.setItem("apkinspector:last-report", JSON.stringify(report));
    sessionStorage.removeItem("apkinspector:last-comparison");
    router.push("/report");
  };

  return (
    <section className="upload-shell" aria-labelledby="upload-title">
      <div className="upload-head">
        <div><span className="panel-label">Start an inspection</span><h2 id="upload-title">Upload your APK</h2></div>
        <span className="service-status"><i /> Analyzer ready</span>
      </div>
      <div className={`drop-zone ${isDragging ? "dragging" : ""} ${file ? "has-file" : ""}`} onDragEnter={() => setIsDragging(true)} onDragLeave={() => setIsDragging(false)} onDragOver={(event) => event.preventDefault()} onDrop={onDrop}>
        <input ref={inputRef} type="file" accept=".apk,application/vnd.android.package-archive" onChange={onInput} />
        {file ? (
          <div className="selected-file">
            <div className="file-icon"><FileArchive aria-hidden="true" /></div>
            <div><strong>{file.name}</strong><span>{formatBytes(file.size)} · Ready to inspect</span></div>
            <button type="button" className="icon-button" onClick={clear} aria-label="Remove selected APK"><X aria-hidden="true" /></button>
          </div>
        ) : (
          <button type="button" className="drop-button" onClick={() => inputRef.current?.click()}>
            <span className="upload-icon"><Upload aria-hidden="true" /></span>
            <strong>Drop an APK here</strong><span>or select a file from your device</span>
          </button>
        )}
      </div>
      <button
        className={`comparison-toggle ${compareMode ? "active" : ""}`}
        type="button"
        onClick={() => {
          setCompareMode((current) => !current);
          setReferenceFile(null);
        }}
      >
        <GitCompareArrows aria-hidden="true" />
        <span><strong>Compare with trusted APK</strong><small>Check signatures and package differences</small></span>
      </button>
      {compareMode && (
        <div className="reference-picker">
          <input ref={referenceInputRef} type="file" accept=".apk,application/vnd.android.package-archive" onChange={(event) => acceptReference(event.target.files?.[0])} />
          <button type="button" onClick={() => referenceInputRef.current?.click()}>
            <FileArchive aria-hidden="true" />
            <span>{referenceFile ? referenceFile.name : "Select trusted reference APK"}</span>
          </button>
          {referenceFile && <button type="button" className="icon-button" aria-label="Remove reference APK" onClick={() => setReferenceFile(null)}><X aria-hidden="true" /></button>}
        </div>
      )}
      {message && <p className={`upload-message ${state}`}>{message}</p>}
      <button className="analyze-button" type="button" disabled={!file || (compareMode && !referenceFile) || state === "uploading"} onClick={analyze}>
        {state === "uploading" ? <LoaderCircle className="spin" aria-hidden="true" /> : <LockKeyhole aria-hidden="true" />}
        {state === "uploading" ? "Analyzing package" : compareMode ? "Compare APKs securely" : "Analyze APK securely"}
      </button>
      <p className="upload-note">Maximum 100 MB · Static inspection · File deleted after analysis</p>
      <button className="demo-button" type="button" onClick={openDemo}><Beaker aria-hidden="true" /> View safe demonstration report</button>
    </section>
  );
}
