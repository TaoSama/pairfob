import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { operationBusy } from "../../operations/capabilities-store";
import {
  composeDraft,
  composeIME,
  finishComposeComposition,
  setComposeDraft,
  setComposeFocused,
  setComposeIME,
} from "../compose-store";
import { liveSession } from "../../computers/catalog-store";
import { openPaneId } from "../session-store";
import { useCompose, useSession } from "../hooks";
import { useDashboard } from "../../dashboard/hooks";
import { currentViewIncarnation } from "../drafts/compose-drafts";
import { agentFromDashboardSnapshot } from "../agents";
import { fitOperationPrompt, OPERATION_INPUT_LIMITS } from "../../../lib/operations";
import { t } from "../../../lib/i18n";
import { canSend, leaveAgentChat, sizeChatCompose, submitAgentPrompt } from "./agent-chat-controller";
import { publishAgentChatUI } from "./agent-chat-ui";
import { insertImageMarker, nextImageOrdinal, removeImageMarker } from "./agent-compose-images";
import { Button } from "../../../shared/ui/primitives";

function composeOwnerMoved(
  session: ReturnType<typeof liveSession>,
  paneId: string,
  incarnation: number,
): boolean {
  return liveSession() !== session || openPaneId() !== paneId || currentViewIncarnation() !== incarnation;
}

/** One attached image: its `[Image #N]` marker and a local preview URL. */
type AttachedImage = { key: number; marker: string; name: string; url: string };

/** The controller owns draft value/selection; React owns labels and availability. */
export function AgentCompose() {
  const input = useRef<HTMLTextAreaElement>(null);
  const picker = useRef<HTMLInputElement>(null);
  const [limited, setLimited] = useState(false);
  const [images, setImages] = useState<AttachedImage[]>([]);
  const imageKey = useRef(0);
  const allowed = canSend();
  const busy = operationBusy();
  const draft = useCompose().composeDraft;
  const selected = agentFromDashboardSnapshot(useDashboard(), useSession().paneId);

  // The draft empties on submit (and on a view switch that resets compose). Once
  // the markers are gone there is nothing for the thumbnails to reference, so
  // release the preview URLs and clear the strip.
  useEffect(() => {
    if (draft.trim() !== "") return;
    setImages((current) => {
      for (const image of current) URL.revokeObjectURL(image.url);
      return current.length ? [] : current;
    });
  }, [draft]);

  // Last line of defense against leaked object URLs when the field unmounts.
  useEffect(() => () => {
    for (const image of images) URL.revokeObjectURL(image.url);
  }, [images]);

  function attachFiles(files: FileList | null): void {
    const field = input.current;
    if (!field || !files || files.length === 0) return;
    const added: AttachedImage[] = [];
    for (const file of Array.from(files)) {
      if (!file.type.startsWith("image/")) continue;
      const session = liveSession();
      const paneId = openPaneId();
      const incarnation = currentViewIncarnation();
      const caret = field.selectionStart ?? field.value.length;
      const ordinal = nextImageOrdinal(field.value);
      const spliced = insertImageMarker(field.value, caret, ordinal);
      const fitted = fitOperationPrompt(spliced.text);
      const marked = fitted.text.includes(spliced.marker);
      setComposeDraft(fitted.text);
      if (composeOwnerMoved(session, paneId, incarnation) || !field.isConnected) return;
      field.value = fitted.text;
      // Trailing space may be trimmed by the fit; clamp the caret to the field.
      const caretAt = Math.min(spliced.caret, field.value.length);
      field.setSelectionRange(caretAt, caretAt);
      setLimited(fitted.truncated);
      sizeChatCompose(field);
      // A marker dropped by the 32 KiB fit gets no thumbnail — nothing references it.
      if (marked) added.push({ key: imageKey.current++, marker: spliced.marker, name: file.name, url: URL.createObjectURL(file) });
    }
    if (added.length) setImages((current) => [...current, ...added]);
    publishAgentChatUI();
    field.focus({ preventScroll: true });
  }

  function removeImage(target: AttachedImage): void {
    const field = input.current;
    setImages((current) => current.filter((image) => image.key !== target.key));
    URL.revokeObjectURL(target.url);
    if (!field) return;
    const session = liveSession();
    const paneId = openPaneId();
    const incarnation = currentViewIncarnation();
    const next = removeImageMarker(field.value, target.marker);
    const fitted = fitOperationPrompt(next);
    setComposeDraft(fitted.text);
    if (composeOwnerMoved(session, paneId, incarnation) || !field.isConnected) return;
    field.value = fitted.text;
    setLimited(fitted.truncated);
    sizeChatCompose(field);
    publishAgentChatUI();
    field.focus({ preventScroll: true });
  }

  useLayoutEffect(() => {
    const field = input.current!;
    const bindings = new AbortController();
    const signal = bindings.signal;
    const initial = fitOperationPrompt(composeDraft());
    setComposeDraft(initial.text);
    field.value = initial.text;
    setLimited(initial.truncated);
    const syncDraft = () => {
      const session = liveSession();
      const paneId = openPaneId();
      const incarnation = currentViewIncarnation();
      const fitted = fitOperationPrompt(field.value);
      setComposeDraft(fitted.text);
      if (composeOwnerMoved(session, paneId, incarnation) || !field.isConnected) return;
      field.value = fitted.text;
      setLimited(fitted.truncated);
      sizeChatCompose(field);
      publishAgentChatUI();
    };
    field.addEventListener("input", () => {
      if (composeIME()) sizeChatCompose(field);
      else syncDraft();
    }, { signal });
    field.addEventListener("compositionstart", () => { setComposeIME(true); }, { signal });
    field.addEventListener("compositionend", () => {
      const session = liveSession();
      const paneId = openPaneId();
      const incarnation = currentViewIncarnation();
      const fitted = fitOperationPrompt(field.value);
      finishComposeComposition(fitted.text);
      if (composeOwnerMoved(session, paneId, incarnation) || !field.isConnected) return;
      field.value = fitted.text;
      setLimited(fitted.truncated);
      sizeChatCompose(field);
      publishAgentChatUI();
    }, { signal });
    field.addEventListener("focus", () => { setComposeFocused(true); }, { signal });
    field.addEventListener("blur", () => { setComposeFocused(false); }, { signal });
    field.addEventListener("keydown", event => {
      if (event.isComposing || composeIME() || event.key !== "Enter" || event.shiftKey) return;
      event.preventDefault();
      void submitAgentPrompt();
    }, { signal });
    const frame = requestAnimationFrame(() => { if (field.isConnected) sizeChatCompose(field); });
    return () => { bindings.abort(); cancelAnimationFrame(frame); };
  }, []);
  return <div className="dock agent-dock">
    {selected?.status === "blocked" && <div className="agent-confirm">
      <p className="agent-confirm-copy">{t("chat.waitingConfirm")}</p>
      <Button className="btn btn-small" onClick={() => leaveAgentChat()}>{t("chat.goConfirm")}</Button>
    </div>}
    {images.length > 0 && <ul className="agent-image-strip" aria-label={t("chat.imageStrip")}>
      {images.map((image) => <li key={image.key} className="agent-image-thumb">
        <img src={image.url} alt={t("chat.imageAlt", { marker: image.marker })} />
        <Button className="agent-image-remove" aria-label={t("chat.removeImage", { name: image.name })}
          onClick={() => removeImage(image)}>×</Button>
      </li>)}
    </ul>}
    <form className="dock-form" onSubmit={event => { event.preventDefault(); void submitAgentPrompt(); }}>
      <Button className="agent-add-image" aria-label={t("chat.addImage")} disabled={!allowed || busy}
        onClick={() => picker.current?.click()}>＋</Button>
      <input ref={picker} type="file" accept="image/*" multiple hidden aria-hidden="true"
        onChange={event => { attachFiles(event.currentTarget.files); event.currentTarget.value = ""; }} />
      <textarea ref={input} rows={1} enterKeyHint="send" maxLength={OPERATION_INPUT_LIMITS.prompt}
        placeholder={t(allowed ? "chat.placeholder" : "chat.cantSend")} disabled={!allowed || busy} />
      <Button className="send-btn" disabled={!allowed || busy || !draft.trim()}
        onClick={() => void submitAgentPrompt()}>{t("compose.send")}</Button>
    </form>
    <p className="agent-compose-hint" aria-live="polite" hidden={!limited}>{limited ? t("chat.limit") : ""}</p>
  </div>;
}
