/**
 * The message channel between the pane and the Studio Pro host.
 *
 * Studio Pro's web view exposes `window.chrome.webview`. Messages are `{ message, data }` in
 * both directions, and the host queues its own messages until the page posts
 * `MessageListenerRegistered` (see `IWebView.PostMessage` in the Extensions API).
 *
 * Outside Studio Pro — the page opened in a normal browser for development — there is no
 * channel, and the UI falls back to analysing a snapshot file the user picks.
 */

export type HostMessage =
  | { message: 'Snapshot'; data: { json: string } }
  | { message: 'SnapshotFailed'; data: { error: string } }
  | { message: 'ExportDone'; data: { path?: string; error?: string } }
  | { message: 'OpenUnitResult'; data: { ok: boolean; error?: string; name?: string; location?: string } };

type Handler = (msg: HostMessage) => void;

interface WebViewChannel {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
}

const channel: WebViewChannel | undefined = (
  window as unknown as { chrome?: { webview?: WebViewChannel } }
).chrome?.webview;

export const inStudioPro = channel !== undefined;

const handlers = new Set<Handler>();

export function onHostMessage(handler: Handler): void {
  handlers.add(handler);
}

export function send(message: string, data?: Record<string, unknown>): void {
  channel?.postMessage(data === undefined ? { message } : { message, data });
}

export function connect(): void {
  if (!channel) return;
  channel.addEventListener('message', (event) => {
    const msg = event.data as HostMessage;
    if (!msg || typeof msg.message !== 'string') return;
    for (const handler of handlers) handler(msg);
  });
  send('MessageListenerRegistered');
}
