import type { TaskEvent } from '@vulnlab/shared-types';
import { useEffect, useRef, useState } from 'react';

import { useSessionStore } from '../../../stores/session';
import { taskEventSchema } from '../schemas/task-event';

export type StreamState = 'closed' | 'connecting' | 'open' | 'retrying';

function parseSseFrame(frame: string): TaskEvent | null {
  const data = frame
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).trimStart())
    .join('\n');
  if (!data) return null;
  try {
    const parsed = taskEventSchema.safeParse(JSON.parse(data));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export function useTaskEventStream(taskId: string) {
  const apiKey = useSessionStore((state) => state.apiKey);
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [state, setState] = useState<StreamState>('closed');
  const lastEventId = useRef(0);

  useEffect(() => {
    if (!apiKey) return;

    const controller = new AbortController();
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;

    const connect = async () => {
      setState(lastEventId.current === 0 ? 'connecting' : 'retrying');
      try {
        const response = await fetch(`/api/v1/tasks/${encodeURIComponent(taskId)}/events/stream`, {
          headers: {
            Accept: 'text/event-stream',
            'X-API-Key': apiKey,
            ...(lastEventId.current > 0 ? { 'Last-Event-ID': String(lastEventId.current) } : {}),
          },
          signal: controller.signal,
        });
        if (!response.ok || !response.body) throw new Error(`SSE ${response.status}`);
        setState('open');
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        while (!stopped) {
          const chunk = await reader.read();
          if (chunk.done) break;
          buffer += decoder.decode(chunk.value, { stream: true }).replaceAll('\r\n', '\n');
          let boundary = buffer.indexOf('\n\n');
          while (boundary >= 0) {
            const event = parseSseFrame(buffer.slice(0, boundary));
            buffer = buffer.slice(boundary + 2);
            if (event && event.id > lastEventId.current) {
              lastEventId.current = event.id;
              setEvents((current) => [...current, event].slice(-1000));
            }
            boundary = buffer.indexOf('\n\n');
          }
        }
        if (!stopped) throw new Error('SSE stream closed');
      } catch (error) {
        if (stopped || (error instanceof DOMException && error.name === 'AbortError')) return;
        setState('retrying');
        retryTimer = setTimeout(() => void connect(), 2000);
      }
    };

    void connect();
    return () => {
      stopped = true;
      controller.abort();
      if (retryTimer) clearTimeout(retryTimer);
      setState('closed');
    };
  }, [apiKey, taskId]);

  return { events, state: apiKey ? state : 'closed' };
}
