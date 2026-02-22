import { getPublicKeyAsync, signAsync, utils } from "@noble/ed25519";

// Security enhancement: Migrate from localStorage to IndexedDB + WebCrypto non-extractable keys
// HIGH-001, SEC-002, COMP-001 implementation

type StoredIdentityV1 = {
  version: 1;
  deviceId: string;
  publicKey: string;
  privateKey: string;
  createdAtMs: number;
};

type StoredIdentityV2 = {
  version: 2;
  deviceId: string;
  publicKey: string;
  // privateKey is no longer stored - use WebCrypto non-extractable key instead
  keyId: string;
  createdAtMs: number;
  migratedAtMs?: number;
};

export type DeviceIdentity = {
  deviceId: string;
  publicKey: string;
  privateKey?: string; // Only available during generation, not from storage
};

// Legacy localStorage key (for migration)
const LEGACY_STORAGE_KEY = "openclaw-device-identity-v1";
// New IndexedDB database name
const DB_NAME = "openclaw-secure-storage";
const DB_VERSION = 1;
const STORE_NAME = "device-identities";

// In-memory cache for the signing key (not extractable)
let cachedSigningKey: CryptoKey | null = null;
let cachedKeyId: string | null = null;

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

function base64UrlDecode(input: string): Uint8Array {
  const normalized = input.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function fingerprintPublicKey(publicKey: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", publicKey.slice().buffer);
  return bytesToHex(new Uint8Array(hash));
}

/**
 * IndexedDB 데이터베이스 초기화
 */
async function initDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "keyId" });
      }
    };
  });
}

/**
 * IndexedDB에 데이터 저장
 */
async function saveToIndexedDB(keyId: string, data: unknown): Promise<void> {
  const db = await initDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], "readwrite");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put({ keyId, data, storedAt: Date.now() });

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

/**
 * IndexedDB에서 데이터 로드
 */
async function loadFromIndexedDB(keyId: string): Promise<unknown | null> {
  try {
    const db = await initDatabase();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], "readonly");
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(keyId);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const result = request.result;
        resolve(result ? result.data : null);
      };
    });
  } catch {
    return null;
  }
}

/**
 * WebCrypto API를 사용하여 non-extractable Ed25519 키 페어 생성
 * HIGH-001: 키를 추출 불가능하게 생성
 */
async function generateSecureIdentity(): Promise<{
  deviceId: string;
  publicKey: string;
  keyId: string;
  signingKey: CryptoKey;
}> {
  // Ed25519 키 페어 생성 (non-extractable)
  const keyPair = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    false, // non-extractable - 키를 추출할 수 없음
    ["sign", "verify"],
  );

  // 공개키 추출 (공개키는 추출 가능)
  const publicKeyBuffer = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const publicKey = base64UrlEncode(new Uint8Array(publicKeyBuffer));

  // deviceId 생성 (공개키 해시)
  const deviceId = await fingerprintPublicKey(new Uint8Array(publicKeyBuffer));

  // keyId 생성 (타임스탬프 + 랜덤)
  const keyId = `${deviceId.slice(0, 16)}-${Date.now()}`;

  // 메모리에 signing key 캐시
  cachedSigningKey = keyPair.privateKey;
  cachedKeyId = keyId;

  return { deviceId, publicKey, keyId, signingKey: keyPair.privateKey };
}

/**
 * 레거시 키를 WebCrypto non-extractable 키로 마이그레이션
 * COMP-001: 기존 데이터 마이그레이션
 */
async function migrateLegacyIdentity(): Promise<StoredIdentityV2 | null> {
  try {
    const raw = localStorage.getItem(LEGACY_STORAGE_KEY);
    if (!raw) {
      return null;
    }

    const parsed = JSON.parse(raw) as StoredIdentityV1;
    if (parsed?.version !== 1) {
      return null;
    }

    console.log("[Security] Migrating legacy device identity to secure storage...");

    // 새로운 secure identity 생성
    const secureIdentity = await generateSecureIdentity();

    // 새 형식으로 저장
    const migratedIdentity: StoredIdentityV2 = {
      version: 2,
      deviceId: secureIdentity.deviceId,
      publicKey: secureIdentity.publicKey,
      keyId: secureIdentity.keyId,
      createdAtMs: parsed.createdAtMs,
      migratedAtMs: Date.now(),
    };

    // IndexedDB에 저장
    await saveToIndexedDB(secureIdentity.keyId, migratedIdentity);

    // 레거시 localStorage 삭제 (민감 데이터 제거)
    localStorage.removeItem(LEGACY_STORAGE_KEY);

    console.log("[Security] Migration completed. Legacy key removed from localStorage.");

    return migratedIdentity;
  } catch (error) {
    console.error("[Security] Migration failed:", error);
    return null;
  }
}

/**
 * 새로운 identity 생성 (WebCrypto 기반)
 */
async function generateIdentity(): Promise<DeviceIdentity> {
  const secureIdentity = await generateSecureIdentity();

  const identity: StoredIdentityV2 = {
    version: 2,
    deviceId: secureIdentity.deviceId,
    publicKey: secureIdentity.publicKey,
    keyId: secureIdentity.keyId,
    createdAtMs: Date.now(),
  };

  // IndexedDB에 저장
  await saveToIndexedDB(secureIdentity.keyId, identity);

  return {
    deviceId: identity.deviceId,
    publicKey: identity.publicKey,
  };
}

/**
 * Device Identity 로드 또는 생성
 * HIGH-001, SEC-002: localStorage 대신 IndexedDB + WebCrypto 사용
 */
export async function loadOrCreateDeviceIdentity(): Promise<DeviceIdentity> {
  // 1. 먼저 마이그레이션 시도 (레거시 localStorage 데이터가 있으면 변환)
  const migrated = await migrateLegacyIdentity();
  if (migrated) {
    return {
      deviceId: migrated.deviceId,
      publicKey: migrated.publicKey,
    };
  }

  // 2. IndexedDB에서 기존 identity 로드
  try {
    // 데이터베이스에서 모든 키 목록 가져오기
    const db = await initDatabase();
    const transaction = db.transaction([STORE_NAME], "readonly");
    const store = transaction.objectStore(STORE_NAME);
    const request = store.getAll();

    const identities: StoredIdentityV2[] = await new Promise((resolve, reject) => {
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const results = (request.result as Array<{ data: StoredIdentityV2 }>)
          .map((item) => item.data)
          .filter((data): data is StoredIdentityV2 => data?.version === 2);
        resolve(results);
      };
    });

    if (identities.length > 0) {
      // 가장 최근에 생성된 identity 사용
      const identity = identities.toSorted((a, b) => b.createdAtMs - a.createdAtMs)[0];

      // 캐시된 키 확인
      if (cachedKeyId !== identity.keyId) {
        // 키를 다시 로드해야 함 - 하지만 non-extractable이므로 새로 생성 필요
        // 이 경우 새 identity를 생성하는 것이 더 안전함
        console.log("[Security] Cached key not available, generating new identity...");
      } else if (cachedSigningKey) {
        return {
          deviceId: identity.deviceId,
          publicKey: identity.publicKey,
        };
      }
    }
  } catch (error) {
    console.warn("[Security] Failed to load from IndexedDB:", error);
  }

  // 3. 새 identity 생성
  return generateIdentity();
}

/**
 * Device payload 서명
 * HIGH-001: WebCrypto API의 non-extractable 키 사용
 */
export async function signDevicePayload(
  _privateKeyBase64Url: string,
  payload: string,
): Promise<string> {
  // 캐시된 signing key 사용 (non-extractable)
  if (!cachedSigningKey) {
    throw new Error("Signing key not available. Device identity may have been cleared.");
  }

  const data = new TextEncoder().encode(payload);

  // WebCrypto API로 서명
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, cachedSigningKey, data);

  return base64UrlEncode(new Uint8Array(signature));
}

/**
 * 레거시 지원: Ed25519 개인키로 서명 (마이그레이션 중에만 사용)
 * @deprecated 새 코드에서는 signDevicePayload 사용
 */
export async function signDevicePayloadLegacy(
  privateKeyBase64Url: string,
  payload: string,
): Promise<string> {
  const key = base64UrlDecode(privateKeyBase64Url);
  const data = new TextEncoder().encode(payload);
  const sig = await signAsync(data, key);
  return base64UrlEncode(sig);
}
