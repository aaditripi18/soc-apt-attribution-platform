import { Bot, Loader2, RotateCcw, Send, Sparkles, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { askAssistant, paths, useApi, type AssistantStatus, type ChatMessage } from "../lib/api";
import { cx } from "./ui";

const SUGGESTIONS = [
  "Summarise this investigation",
  "Walk me through the attack chain",
  "Which threat groups does this match, and why?",
  "Which indicators should I hunt for first?",
  "What should we do to contain and prevent this?",
];

const storageKey = (id: string) => `assistant:${id}`;

function restore(id: string): ChatMessage[] {
  try {
    const stored: unknown = JSON.parse(window.sessionStorage.getItem(storageKey(id)) ?? "[]");
    return Array.isArray(stored) ? (stored as ChatMessage[]) : [];
  } catch {
    return [];
  }
}

/**
 * The analyst assistant for one investigation. The conversation is kept in this
 * browser tab and sent with each question, so follow-up questions have context;
 * the server stores nothing.
 */
export function AssistantPanel({ investigationId, source }: { investigationId: string; source: string }) {
  const status = useApi<AssistantStatus>(paths.assistant());
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>(() => restore(investigationId));
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => {
    try {
      window.sessionStorage.setItem(storageKey(investigationId), JSON.stringify(messages));
    } catch {
      // the conversation simply does not survive a reload
    }
    end.current?.scrollIntoView({ block: "end" });
  }, [messages, investigationId, busy]);

  const enabled = status.state === "ready" && status.data.enabled;

  const ask = async (question: string) => {
    const text = question.trim();
    if (!text || busy || !enabled) return;
    // a failed question stays in the box; the history sent is always user/assistant pairs
    const history = messages[messages.length - 1]?.role === "user" ? messages.slice(0, -1) : messages;
    const next: ChatMessage[] = [...history, { role: "user", content: text }];
    setMessages(next);
    setDraft("");
    setFailure(null);
    setBusy(true);
    try {
      const answer = await askAssistant(investigationId, next);
      setMessages([...next, { role: "assistant", content: answer.reply }]);
    } catch (error) {
      setFailure(error instanceof Error ? error.message : String(error));
      setMessages(history);
      setDraft(text);
    }
    setBusy(false);
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Open the AI analyst assistant"
        className={cx(
          "no-print fixed bottom-6 right-6 z-40 flex h-11 items-center gap-2 rounded-full border border-primary/50 bg-primary-container px-4 text-label-md text-on-primary shadow-lg transition-opacity hover:bg-primary",
          open && "pointer-events-none opacity-0",
        )}
      >
        <Sparkles size={16} />
        Ask the AI analyst
      </button>

      {open && (
        <aside
          aria-label="AI analyst assistant"
          className="no-print fixed bottom-0 right-0 top-14 z-40 flex w-full max-w-[30rem] flex-col border-l border-outline-variant bg-surface-lowest shadow-2xl"
        >
          <header className="flex items-center gap-3 border-b border-outline-variant/70 px-4 py-3">
            <span className="flex h-8 w-8 items-center justify-center rounded-md border border-primary/40 bg-primary/10 text-primary">
              <Bot size={17} />
            </span>
            <div className="min-w-0 flex-1">
              <div className="text-headline-sm text-on-surface">AI analyst</div>
              <div className="truncate text-body-sm text-on-surface-variant">{source}</div>
            </div>
            {messages.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  setMessages([]);
                  setFailure(null);
                }}
                title="Start a new conversation"
                aria-label="Start a new conversation"
                className="rounded-sm p-1.5 text-on-surface-variant hover:bg-surface-high hover:text-on-surface"
              >
                <RotateCcw size={15} />
              </button>
            )}
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label="Close the assistant"
              className="rounded-sm p-1.5 text-on-surface-variant hover:bg-surface-high hover:text-on-surface"
            >
              <X size={16} />
            </button>
          </header>

          <div className="flex-1 space-y-4 overflow-y-auto px-4 py-4" data-assistant-messages>
            {status.state === "ready" && !status.data.enabled && (
              <div className="rounded-md border border-outline-variant/70 bg-surface-low p-4 text-body-md text-on-surface-variant">
                <div className="text-headline-sm text-on-surface">The AI analyst is not enabled</div>
                <p className="mt-1.5">
                  It answers questions about this investigation using a language model, and needs an API key for the
                  model provider to be configured where the platform runs. Everything else on this page works without
                  it.
                </p>
              </div>
            )}
            {enabled && messages.length === 0 && (
              <div className="space-y-3">
                <p className="text-body-md text-on-surface-variant">
                  Ask anything about this investigation: what was detected, the attack chain, indicators, which groups
                  it matches, and what to do. I answer from this investigation's results and remember our conversation.
                </p>
                <div className="flex flex-col items-start gap-2">
                  {SUGGESTIONS.map((suggestion) => (
                    <button
                      key={suggestion}
                      type="button"
                      onClick={() => void ask(suggestion)}
                      className="rounded-full border border-outline-variant bg-surface-low px-3 py-1.5 text-left text-body-md text-on-surface hover:border-primary/60"
                    >
                      {suggestion}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {messages.map((message, index) => (
              <div key={index} className={cx("flex", message.role === "user" ? "justify-end" : "justify-start")} data-role={message.role}>
                <div
                  className={cx(
                    "max-w-[92%] rounded-md px-3 py-2 text-body-md",
                    message.role === "user"
                      ? "bg-primary/15 text-on-surface"
                      : "border border-outline-variant/70 bg-surface-low text-on-surface",
                  )}
                >
                  {message.role === "user" ? (
                    <p className="whitespace-pre-wrap">{message.content}</p>
                  ) : (
                    <div className="assistant-prose space-y-2 [&_code]:font-mono [&_code]:text-code-md [&_li]:ml-4 [&_ol]:list-decimal [&_strong]:text-on-surface [&_ul]:list-disc">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {busy && (
              <div className="flex items-center gap-2 text-body-md text-on-surface-variant">
                <Loader2 size={15} className="animate-spin" />
                Reading the investigation…
              </div>
            )}
            {failure && (
              <p role="alert" className="rounded-sm border border-error/40 bg-error/10 px-3 py-2 text-body-md text-error">
                The assistant could not answer: {failure}
              </p>
            )}
            <div ref={end} />
          </div>

          {enabled && (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void ask(draft);
              }}
              className="border-t border-outline-variant/70 p-3"
            >
              <div className="flex items-end gap-2">
                <textarea
                  value={draft}
                  onChange={(event) => setDraft(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && !event.shiftKey) {
                      event.preventDefault();
                      void ask(draft);
                    }
                  }}
                  rows={2}
                  maxLength={4000}
                  placeholder="Ask about this investigation…"
                  aria-label="Your question"
                  className="min-h-[2.75rem] flex-1 resize-none rounded-sm border border-outline-variant bg-surface-low px-3 py-2 text-body-md text-on-surface placeholder:text-outline focus:border-primary focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={busy || draft.trim() === ""}
                  aria-label="Send"
                  className="flex h-10 w-10 items-center justify-center rounded-sm bg-primary-container text-on-primary hover:bg-primary disabled:opacity-40"
                >
                  <Send size={16} />
                </button>
              </div>
              <p className="mt-2 text-body-sm text-outline">
                Answers are generated from this investigation's results and can be wrong — check them against the
                evidence. Your question and a summary of the results are sent to the model provider.
              </p>
            </form>
          )}
        </aside>
      )}
    </>
  );
}
