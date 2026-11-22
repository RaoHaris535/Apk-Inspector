import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import Home from "./page";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(() => new Promise(() => undefined)));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

test("introduces the APK security analyzer and upload action", () => {
  render(<Home />);

  expect(screen.getByRole("heading", { level: 1 }).textContent).toContain(
    "See what is inside an APK",
  );
  expect(screen.getByRole("button", { name: "Analyze APK securely" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "A careful path through untrusted input." })).toBeTruthy();
  expect(screen.getByRole("link", { name: "Workflow" }).getAttribute("href")).toBe("#workflow");
});
