import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "APKInspector",
  description: "Explainable static security analysis for Android APK files.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
