'use client';

import { useEffect, useRef, useState, useCallback } from 'react';

interface WSMessage {
  type: string;
  data: unknown;
}

export function useWebSocket(url?: string) {
  const [lastMessage, setLastMessage] = useState<WSMessage | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    if (!url) return;

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        setTimeout(connect, 5000);
      };
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          setLastMessage(msg);
        } catch {
          // ignore non-JSON messages
        }
      };
      ws.onerror = () => setConnected(false);
    } catch {
      setConnected(false);
    }
  }, [url]);

  useEffect(() => {
    connect();
    return () => {
      wsRef.current?.close();
    };
  }, [connect]);

  return { lastMessage, connected };
}
