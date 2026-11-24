"use client";

import { useEffect, useRef, useState } from "react";
import { ORCHESTRATOR_WS_URL } from "./api";

export interface RunEvent {
  event_type: "node_progress" | "gate_result" | "run_status" | "audit" | "error" | string;
  run_id: string;
  timestamp?: string;
  seq?: number;
  payload: Record<string, any>;
}

/** Live pipeline events for one run; reconnects with backoff while the page is open. */
export function useRunWebSocket(runId: string, onEvent?: (e: RunEvent) => void) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const handler = useRef(onEvent);
  handler.current = onEvent;

  useEffect(() => {
    if (!runId) return;
    let socket: WebSocket | null = null;
    let closed = false;
    let retry = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const connect = () => {
      socket = new WebSocket(`${ORCHESTRATOR_WS_URL}/runs/${encodeURIComponent(runId)}/ws`);
      socket.onopen = () => {
        retry = 0;
        setConnected(true);
      };
      socket.onmessage = (msg) => {
        try {
          const event = JSON.parse(msg.data) as RunEvent;
          if (event.seq !== undefined) {
            setEvents((prev) => (prev.some((p) => p.seq === event.seq) ? prev : [...prev, event]));
          }
          handler.current?.(event);
        } catch {
          /* ignore malformed frames */
        }
      };
      socket.onclose = () => {
        setConnected(false);
        if (!closed) {
          retry += 1;
          timer = setTimeout(connect, Math.min(10000, 500 * 2 ** retry));
        }
      };
      socket.onerror = () => socket?.close();
    };

    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      socket?.close();
    };
  }, [runId]);

  return { connected, events };
}
