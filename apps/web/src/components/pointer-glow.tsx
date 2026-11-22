"use client";

import { useEffect, useRef } from "react";

const INTERACTIVE_SELECTOR = "a, button, input, [role='button']";

export function PointerGlow() {
  const glowRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const glow = glowRef.current;
    if (typeof window.matchMedia !== "function") return;

    const motionQuery = window.matchMedia(
      "(pointer: fine) and (prefers-reduced-motion: no-preference)",
    );

    if (!glow || !motionQuery.matches) return;

    let frame = 0;
    let x = 0;
    let y = 0;

    const paint = () => {
      glow.style.setProperty("--pointer-x", `${x}px`);
      glow.style.setProperty("--pointer-y", `${y}px`);
      glow.dataset.visible = "true";
      frame = 0;
    };

    const onPointerMove = (event: PointerEvent) => {
      x = event.clientX;
      y = event.clientY;
      glow.dataset.interactive = String(
        event.target instanceof Element &&
          Boolean(event.target.closest(INTERACTIVE_SELECTOR)),
      );
      if (!frame) frame = window.requestAnimationFrame(paint);
    };

    const onPointerDown = () => {
      glow.dataset.pressed = "true";
    };
    const onPointerUp = () => {
      glow.dataset.pressed = "false";
    };
    const onPointerLeave = () => {
      glow.dataset.visible = "false";
    };

    window.addEventListener("pointermove", onPointerMove, { passive: true });
    window.addEventListener("pointerdown", onPointerDown, { passive: true });
    window.addEventListener("pointerup", onPointerUp, { passive: true });
    document.documentElement.addEventListener("mouseleave", onPointerLeave);

    return () => {
      if (frame) window.cancelAnimationFrame(frame);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointerup", onPointerUp);
      document.documentElement.removeEventListener("mouseleave", onPointerLeave);
    };
  }, []);

  return <div ref={glowRef} className="pointer-glow" aria-hidden="true" />;
}
