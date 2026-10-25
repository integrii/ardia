import { requireOptionalNativeModule } from "expo-modules-core";
import type { Listing, Transport } from "./scope.ts";

export type FolderInfo = {
  path: string;
  defaultPath: string;
  iCloudAvailable: boolean;
  inICloud: boolean;
  exists: boolean;
  writable: boolean;
  hasSyncData: boolean;
};

export type PhraseResult =
  | { ok: true }
  | { error: "wordCount"; count: number }
  | { error: "unknownWord"; word: string }
  | { error: "checksum" }
  | { error: "noData" }
  | { error: "mismatch" }
  | { error: "keychain" };

export type PasswordSyncValue = { version: 2; sealed: string; fingerprint: string };
export type PasswordSyncRecord = { key: string; value: PasswordSyncValue; created: number | null };
export type PasswordSyncChange = { key: string; desired: PasswordSyncValue | null; base: PasswordSyncValue | null };
export type PasswordSyncProfile = { scope: string; engineProfile: string };

type SyncNative = {
  folderInfo(path: string | null): Promise<FolderInfo>;
  chooseFolder(current: string | null): Promise<string | null>;
  newDeviceId(): string;
  deviceName(): string;
  createPhrase(account: string): Promise<boolean>;
  enterPhrase(account: string, text: string, folder: string): Promise<PhraseResult>;
  unlock(account: string): Promise<boolean>;
  forget(account: string): Promise<void>;
  chainStatus(folder: string): Promise<"ok" | "missing" | "unavailable">;
  createChain(folder: string): Promise<void>;
  write(folder: string, scope: string, payload: string): Promise<string>;
  read(folder: string, scope: string, known: string[]): Promise<Listing>;
  remove(folder: string, scope: string, ids: string[]): Promise<void>;
  deleteChain(folder: string): Promise<void>;
  sealLocal(text: string): Promise<string>;
  openLocal(sealed: string): Promise<string>;
  addListener(event: "onPasswordSyncInvalidated", listener: () => void): { remove(): void };
  recoveryWords(): Promise<string[]>;
  qrCode(): Promise<string | null>;
  recoveryKitPreview(width: number): Promise<string | null>;
  saveRecoveryKit(format: "pdf" | "text"): Promise<string | null>;
  copyRecoveryKit(): Promise<void>;
  shareRecoveryKit(): Promise<void>;
  copyRecoveryPhrase(): Promise<void>;
  revealFolder(path: string): Promise<void>;
  authorizePasswordSync(folder: string, profiles: PasswordSyncProfile[]): Promise<boolean>;
  revokePasswordSyncAuthorization(): void;
  passwordSyncAuthorized(folder: string, scope: string, engineProfile: string): Promise<boolean>;
  readPasswordRecords(folder: string, scope: string, engineProfile: string): Promise<PasswordSyncRecord[] | null>;
  applyPasswordRecords(folder: string, scope: string, engineProfile: string, changes: PasswordSyncChange[]): Promise<boolean>;
};

export const SyncNative = requireOptionalNativeModule<SyncNative>("ArdiaSync");

export const folderTransport = (native: SyncNative, folder: string): Transport => ({
  write: (scope, payload) => native.write(folder, scope, payload),
  read: (scope, known) => native.read(folder, scope, known),
  remove: (scope, ids) => native.remove(folder, scope, ids),
});
