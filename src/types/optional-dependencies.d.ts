// Type stubs for optional dependencies

declare module "ioredis" {
  export class Redis {
    constructor(url: string);
    get(key: string): Promise<string | null>;
    set(key: string, value: string, options?: { ex?: number }): Promise<string | null>;
    del(key: string): Promise<number>;
    multi(): RedisMulti;
    eval(script: string, keys: string[], args: string[]): Promise<unknown>;
  }

  export interface RedisMulti {
    get(key: string): RedisMulti;
    set(key: string, value: string, options?: { ex?: number }): RedisMulti;
    exec(): Promise<unknown[]>;
  }
}

declare module "@aws-sdk/client-kms" {
  export class KMSClient {
    constructor(config: { region: string });
    send(command: unknown): Promise<unknown>;
  }

  export class GenerateDataKeyCommand {
    constructor(params: { KeyId: string; KeySpec: string });
  }

  export class DecryptCommand {
    constructor(params: { CiphertextBlob: Buffer });
  }
}

declare module "@azure/keyvault-keys" {
  export class KeyClient {
    constructor(vaultUrl: string, credential: unknown);
    getKey(name: string): Promise<unknown>;
    createRsaKey(name: string, options?: { keySize?: number }): Promise<unknown>;
  }

  export class CryptographyClient {
    constructor(key: unknown, credential: unknown);
    wrapKey(algorithm: string, key: Buffer): Promise<{ result: Uint8Array }>;
    unwrapKey(algorithm: string, wrappedKey: Buffer): Promise<{ result: Uint8Array }>;
  }
}

declare module "@azure/identity" {
  export class DefaultAzureCredential {
    // Implementation details not needed for type checking
  }
}

declare module "argon2" {
  export function hash(password: string): Promise<string>;
  export function verify(hash: string, password: string): Promise<boolean>;
}
