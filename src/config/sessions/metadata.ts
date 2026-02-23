import type { MsgContext } from "../../auto-reply/templating.js";
import type { GroupKeyResolution, SessionEntry, SessionOrigin } from "./types.js";
import { normalizeChatType } from "../../channels/chat-type.js";
import { resolveConversationLabel } from "../../channels/conversation-label.js";
import { getChannelDock } from "../../channels/dock.js";
import { normalizeChannelId } from "../../channels/plugins/index.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import {
  getEncryptionService,
  getOrInitEncryption,
  createEncryptionConfigFromEnv,
} from "../../security/encryption.js";
import { normalizeMessageChannel } from "../../utils/message-channel.js";
import { buildGroupDisplayName, resolveGroupSessionKey } from "./group.js";

const log = createSubsystemLogger("sessions/metadata");

/**
 * Fields in SessionEntry that contain sensitive data and should be encrypted
 */
const SENSITIVE_SESSION_FIELDS: Array<keyof SessionEntry> = [
  "origin",
  "deliveryContext",
  "lastTo",
  "lastAccountId",
  "lastThreadId",
];

/**
 * Initialize encryption service if not already initialized
 */
function ensureEncryptionService() {
  let service = getEncryptionService();
  if (!service) {
    const config = createEncryptionConfigFromEnv();
    service = getOrInitEncryption(config);
    if (config.enabled) {
      log.info("encryption initialized for session metadata");
    }
  }
  return service;
}

const mergeOrigin = (
  existing: SessionOrigin | undefined,
  next: SessionOrigin | undefined,
): SessionOrigin | undefined => {
  if (!existing && !next) {
    return undefined;
  }
  const merged: SessionOrigin = existing ? { ...existing } : {};
  if (next?.label) {
    merged.label = next.label;
  }
  if (next?.provider) {
    merged.provider = next.provider;
  }
  if (next?.surface) {
    merged.surface = next.surface;
  }
  if (next?.chatType) {
    merged.chatType = next.chatType;
  }
  if (next?.from) {
    merged.from = next.from;
  }
  if (next?.to) {
    merged.to = next.to;
  }
  if (next?.accountId) {
    merged.accountId = next.accountId;
  }
  if (next?.threadId != null && next.threadId !== "") {
    merged.threadId = next.threadId;
  }
  return Object.keys(merged).length > 0 ? merged : undefined;
};

export function deriveSessionOrigin(ctx: MsgContext): SessionOrigin | undefined {
  const label = resolveConversationLabel(ctx)?.trim();
  const providerRaw =
    (typeof ctx.OriginatingChannel === "string" && ctx.OriginatingChannel) ||
    ctx.Surface ||
    ctx.Provider;
  const provider = normalizeMessageChannel(providerRaw);
  const surface = ctx.Surface?.trim().toLowerCase();
  const chatType = normalizeChatType(ctx.ChatType) ?? undefined;
  const from = ctx.From?.trim();
  const to =
    (typeof ctx.OriginatingTo === "string" ? ctx.OriginatingTo : ctx.To)?.trim() ?? undefined;
  const accountId = ctx.AccountId?.trim();
  const threadId = ctx.MessageThreadId ?? undefined;

  const origin: SessionOrigin = {};
  if (label) {
    origin.label = label;
  }
  if (provider) {
    origin.provider = provider;
  }
  if (surface) {
    origin.surface = surface;
  }
  if (chatType) {
    origin.chatType = chatType;
  }
  if (from) {
    origin.from = from;
  }
  if (to) {
    origin.to = to;
  }
  if (accountId) {
    origin.accountId = accountId;
  }
  if (threadId != null && threadId !== "") {
    origin.threadId = threadId;
  }

  return Object.keys(origin).length > 0 ? origin : undefined;
}

export function snapshotSessionOrigin(entry?: SessionEntry): SessionOrigin | undefined {
  if (!entry?.origin) {
    return undefined;
  }
  return { ...entry.origin };
}

export function deriveGroupSessionPatch(params: {
  ctx: MsgContext;
  sessionKey: string;
  existing?: SessionEntry;
  groupResolution?: GroupKeyResolution | null;
}): Partial<SessionEntry> | null {
  const resolution = params.groupResolution ?? resolveGroupSessionKey(params.ctx);
  if (!resolution?.channel) {
    return null;
  }

  const channel = resolution.channel;
  const subject = params.ctx.GroupSubject?.trim();
  const space = params.ctx.GroupSpace?.trim();
  const explicitChannel = params.ctx.GroupChannel?.trim();
  const normalizedChannel = normalizeChannelId(channel);
  const isChannelProvider = Boolean(
    normalizedChannel &&
    getChannelDock(normalizedChannel)?.capabilities.chatTypes.includes("channel"),
  );
  const nextGroupChannel =
    explicitChannel ??
    ((resolution.chatType === "channel" || isChannelProvider) && subject && subject.startsWith("#")
      ? subject
      : undefined);
  const nextSubject = nextGroupChannel ? undefined : subject;

  const patch: Partial<SessionEntry> = {
    chatType: resolution.chatType ?? "group",
    channel,
    groupId: resolution.id,
  };
  if (nextSubject) {
    patch.subject = nextSubject;
  }
  if (nextGroupChannel) {
    patch.groupChannel = nextGroupChannel;
  }
  if (space) {
    patch.space = space;
  }

  const displayName = buildGroupDisplayName({
    provider: channel,
    subject: nextSubject ?? params.existing?.subject,
    groupChannel: nextGroupChannel ?? params.existing?.groupChannel,
    space: space ?? params.existing?.space,
    id: resolution.id,
    key: params.sessionKey,
  });
  if (displayName) {
    patch.displayName = displayName;
  }

  return patch;
}

export function deriveSessionMetaPatch(params: {
  ctx: MsgContext;
  sessionKey: string;
  existing?: SessionEntry;
  groupResolution?: GroupKeyResolution | null;
}): Partial<SessionEntry> | null {
  const groupPatch = deriveGroupSessionPatch(params);
  const origin = deriveSessionOrigin(params.ctx);
  if (!groupPatch && !origin) {
    return null;
  }

  const patch: Partial<SessionEntry> = groupPatch ? { ...groupPatch } : {};
  const mergedOrigin = mergeOrigin(params.existing?.origin, origin);
  if (mergedOrigin) {
    patch.origin = mergedOrigin;
  }

  return Object.keys(patch).length > 0 ? patch : null;
}

/**
 * Encrypt sensitive fields in a SessionEntry.
 * This is a no-op if encryption is not enabled.
 */
export async function encryptSessionEntry(entry: SessionEntry): Promise<SessionEntry> {
  const service = ensureEncryptionService();
  if (!service.isEnabled()) {
    return entry;
  }

  try {
    return await service.encryptFields(entry, SENSITIVE_SESSION_FIELDS);
  } catch (err) {
    log.warn("failed to encrypt session entry fields", { err, sessionId: entry.sessionId });
    // Return unencrypted entry on failure (fail open for compatibility)
    return entry;
  }
}

/**
 * Decrypt sensitive fields in a SessionEntry.
 * Handles both encrypted and plaintext entries (backward compatible).
 */
export async function decryptSessionEntry(entry: SessionEntry): Promise<SessionEntry> {
  const service = ensureEncryptionService();
  if (!service.isEnabled()) {
    // Even if encryption is disabled, try to decrypt in case it was enabled before
    try {
      return await service.decryptFields(entry, SENSITIVE_SESSION_FIELDS);
    } catch {
      // Return as-is if decryption fails
      return entry;
    }
  }

  try {
    return await service.decryptFields(entry, SENSITIVE_SESSION_FIELDS);
  } catch (err) {
    log.warn("failed to decrypt session entry fields", { err, sessionId: entry.sessionId });
    // Return entry as-is on decryption failure (may be plaintext)
    return entry;
  }
}

/**
 * Encrypt session origin data.
 */
export async function encryptSessionOrigin(
  origin: SessionOrigin,
): Promise<SessionOrigin | { encrypted: true; data: unknown }> {
  const service = ensureEncryptionService();
  if (!service.isEnabled()) {
    return origin;
  }

  try {
    return (await service.encryptObject(origin)) as
      | SessionOrigin
      | { encrypted: true; data: unknown };
  } catch (err) {
    log.warn("failed to encrypt session origin", { err });
    return origin;
  }
}

/**
 * Decrypt session origin data.
 */
export async function decryptSessionOrigin(
  origin: SessionOrigin | { encrypted?: boolean; data?: unknown },
): Promise<SessionOrigin | undefined> {
  const service = ensureEncryptionService();

  try {
    const decrypted = await service.decryptObject<SessionOrigin>(origin);
    return decrypted;
  } catch (err) {
    log.warn("failed to decrypt session origin", { err });
    // Return as-is if it's a plain SessionOrigin
    if (origin && typeof origin === "object" && !(origin as { encrypted?: boolean }).encrypted) {
      return origin as SessionOrigin;
    }
    return undefined;
  }
}
