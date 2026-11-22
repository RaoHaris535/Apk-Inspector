import { render, screen } from "@testing-library/react";
import { expect, test, vi } from "vitest";

import Home from "./page";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

test("introduces the APK security analyzer and upload action", () => {
  render(<Home />);

  expect(screen.getByRole("heading", { level: 1 }).textContent).toContain(
    "See what is inside an APK",
  );
  expect(screen.getByRole("button", { name: "Analyze APK securely" })).toBeTruthy();
});
