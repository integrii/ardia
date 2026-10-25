import { showMenu, Symbol } from "@ardia/shell";
import { SyncNative, type FolderInfo } from "@ardia/sync";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Image, StyleSheet, Text, TextInput, View } from "react-native";
import { useTheme } from "../../../lib/theme";
import { enterRecoveryPhrase, stopSync } from "../../../sync/engine";
import { Button, Checkbox, Sheet, useFormColors } from "../controls";
import { closeSettingsSheet, showSettingsSheet } from "../sheet";

const WORDS = 24;

function Title({ children }: { children: string }) {
  const theme = useTheme();
  return <Text style={{ fontSize: 15, fontWeight: "600", color: theme.textPrimary }}>{children}</Text>;
}

function Body({ children, style }: { children: ReactNode; style?: object }) {
  const theme = useTheme();
  return <Text style={[{ fontSize: 12.5, lineHeight: 17, marginTop: 6, color: theme.textSecondary }, style]}>{children}</Text>;
}

function Buttons({ children, left }: { children: ReactNode; left?: ReactNode }) {
  return (
    <View style={{ flexDirection: "row", alignItems: "center", gap: 8, marginTop: 18 }}>
      {left}
      <View style={{ flex: 1 }} />
      {children}
    </View>
  );
}

export function showRecoveryKit() {
  showSettingsSheet(<RecoveryKitSheet />);
}

function useRecoveryAccess(clear: () => void, defaultError = "Couldn’t open the recovery kit. Please try again.") {
  const current = useRef({ alive: true, generation: 0, unlocked: false, busy: false });
  const clearRef = useRef(clear);
  clearRef.current = clear;
  const [unlocked, setUnlocked] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const invalidate = () => {
    current.current.generation++;
    current.current.unlocked = false;
    current.current.busy = false;
    if (!current.current.alive) return;
    clearRef.current();
    setUnlocked(false);
    setBusy(false);
    setError(null);
  };
  useEffect(() => {
    current.current.alive = true;
    const listener = SyncNative?.addListener("onRecoveryInvalidated", invalidate);
    return () => {
      current.current.alive = false;
      current.current.generation++;
      current.current.unlocked = false;
      listener?.remove();
      SyncNative?.revokeRecoveryAuthorization();
    };
  }, []);
  const run = async <T,>(action: (valid: () => boolean) => Promise<T | null | undefined>, accept?: (value: T) => void, authorize = false, failureMessage?: string | (() => string | undefined)) => {
    if (current.current.busy || (!authorize && !current.current.unlocked)) return;
    const generation = current.current.generation;
    const valid = () => current.current.alive && current.current.generation === generation;
    const failure = () => typeof failureMessage === "function" ? failureMessage() : failureMessage;
    current.current.busy = true;
    setBusy(true);
    setError(null);
    try {
      if (authorize) {
        const allowed = await SyncNative?.authorizeRecovery();
        if (!valid() || !allowed) return;
        current.current.unlocked = true;
        setUnlocked(true);
      }
      const result = await action(valid);
      if (!valid()) return;
      const message = failure();
      if (result == null) {
        invalidate();
        if (message) setError(message);
      }
      else if (result === false && message) setError(message);
      else accept?.(result);
    } catch {
      if (valid()) setError(failure() ?? defaultError);
    } finally {
      if (valid()) {
        current.current.busy = false;
        setBusy(false);
      }
    }
  };
  const close = () => {
    invalidate();
    SyncNative?.revokeRecoveryAuthorization();
    closeSettingsSheet();
  };
  return { unlocked, busy, error, run, close };
}

function RecoveryKitSheet() {
  const theme = useTheme();
  const colors = useFormColors();
  const [preview, setPreview] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const access = useRecoveryAccess(() => { setPreview(null); setSaved(null); });
  const unlock = () => access.run(async () => SyncNative?.recoveryKitPreview(168), setPreview, true);
  const save = (format: "pdf" | "text") => access.run(async () => {
    const path = await SyncNative?.saveRecoveryKit(format);
    return { path };
  }, ({ path }) => { if (path) setSaved(path); });
  const more = async () => {
    let failureMessage: string | undefined;
    await access.run(async (valid) => {
      const choice = await showMenu([
        { id: "copy", title: "Copy", symbol: "doc.on.doc" },
        { id: "share", title: "Share…", symbol: "square.and.arrow.up" },
        { separator: true },
        { id: "text", title: "Save as Text…", symbol: "doc.plaintext" },
      ]);
      if (!valid()) return null;
      if (choice === "copy") {
        failureMessage = "Recovery kit wasn’t copied. Please try again.";
        const copied = await SyncNative?.copyRecoveryKit();
        return copied === true ? {} : copied;
      }
      if (choice === "share") return await SyncNative?.shareRecoveryKit() ? {} : null;
      if (choice === "text") return { path: await SyncNative?.saveRecoveryKit("text") };
      return {};
    }, (result) => { if (typeof result === "object" && "path" in result && result.path) setSaved(result.path); }, false, () => failureMessage);
  };
  return (
    <Sheet width={460} onClose={access.close}>
      <View style={{ flexDirection: "row", gap: 18 }}>
        <View style={{ flex: 1 }}>
          <Title>Save Your Recovery Kit</Title>
          <Body>Your Recovery Kit contains all you need to recover your data should you lose access to this device.</Body>
          <View
            style={{
              flexDirection: "row",
              gap: 8,
              marginTop: 14,
              padding: 10,
              borderRadius: 8,
              backgroundColor: theme.dark ? "rgba(255,159,10,0.12)" : "rgba(255,149,0,0.1)",
            }}
          >
            <Symbol name="exclamationmark.triangle.fill" size={12} color="#FF9500" style={{ width: 16, height: 16 }} />
            <Text style={{ flex: 1, fontSize: 12, lineHeight: 16, color: theme.textPrimary }}>
              This file contains your unencrypted recovery phrase. Anyone with it can read your synced data. Keep it somewhere private, away from this Mac.
            </Text>
          </View>
          {saved ? <Body style={{ marginTop: 10 }}>Saved to {saved.replace(/^\/Users\/[^/]+/, "~")}.</Body> : null}
          {!access.unlocked ? <Body>Unlock with Touch ID or your Mac password to view or export it.</Body> : null}
          {access.error ? <Body>{access.error}</Body> : null}
        </View>
        <View
          accessibilityLabel="Recovery kit preview"
          style={{ width: 168, height: 217, borderRadius: 4, overflow: "hidden", borderWidth: 1, borderColor: colors.groupBorder, backgroundColor: "#FFFFFF" }}
        >
          {preview ? <Image source={{ uri: preview }} style={{ width: 168, height: 217 }} /> : null}
        </View>
      </View>
      <Buttons left={access.unlocked ? <Button title="Other Options" disabled={access.busy} onPress={() => void more()} /> : undefined}>
        <Button title="Close" onPress={access.close} />
        {access.unlocked
          ? <Button title="Save…" kind="primary" disabled={access.busy} onPress={() => void save("pdf")} />
          : <Button title={access.busy ? "Unlocking…" : "Unlock Recovery Kit"} kind="primary" disabled={access.busy} onPress={() => void unlock()} />}
      </Buttons>
    </Sheet>
  );
}

export function showPhraseEntry(folder: FolderInfo | null, onChooseFolder?: () => void) {
  showSettingsSheet(<PhraseSheet folder={folder} onChooseFolder={onChooseFolder} />);
}

const phraseError = (r: Awaited<ReturnType<typeof enterRecoveryPhrase>>): string | null => {
  if ("ok" in r) return null;
  switch (r.error) {
    case "wordCount":
      return "Recovery phrase must be exactly 24 words.";
    case "unknownWord":
      return `“${r.word}” is not a valid recovery phrase word.`;
    case "checksum":
      return "This recovery phrase is not valid. Please check for typos.";
    case "mismatch":
      return "This recovery phrase doesn’t match the synced data in this folder. Check the phrase, or choose the folder your other devices sync to.";
    case "noData":
      return "There’s no synced data in this folder yet. Choose the folder your other devices sync to, or wait for it to finish downloading.";
    case "keychain":
      return "Couldn’t save the sync key in your Keychain.";
    case "unavailable":
      return "Sync isn’t available in this build.";
  }
};

function PhraseSheet({ folder, onChooseFolder }: { folder: FolderInfo | null; onChooseFolder?: () => void }) {
  const theme = useTheme();
  const colors = useFormColors();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const count = text.toLowerCase().split(/[^a-z]+/).filter(Boolean).length;
  const submit = async () => {
    if (!folder || busy) return;
    setBusy(true);
    setError(null);
    const result = await enterRecoveryPhrase(folder.path, text);
    setBusy(false);
    const message = phraseError(result);
    if (message) setError(message);
    else closeSettingsSheet();
  };
  return (
    <Sheet width={440} onClose={closeSettingsSheet}>
      <Title>Connect with Recovery Phrase</Title>
      <Body>Enter your 24-word recovery phrase to sync with another device.</Body>
      <View
        style={{
          marginTop: 12,
          height: 96,
          borderRadius: 7,
          padding: 8,
          backgroundColor: colors.field,
          borderWidth: StyleSheet.hairlineWidth * 2,
          borderColor: error ? colors.destructive : colors.fieldBorder,
        }}
      >
        <TextInput
          value={text}
          onChangeText={(t) => {
            setText(t);
            setError(null);
          }}
          multiline
          autoFocus
          placeholder="Enter your 24-word recovery phrase"
          placeholderTextColor={theme.textTertiary}
          selectionColor={theme.selection}
          enableFocusRing={false}
          autoCorrect={false}
          spellCheck={false}
          style={{ flex: 1, fontSize: 13, lineHeight: 18, color: theme.textPrimary, fontFamily: "Menlo" }}
        />
      </View>
      <View style={{ flexDirection: "row", marginTop: 6 }}>
        <Text style={{ flex: 1, fontSize: 11.5, lineHeight: 15, color: error ? colors.destructive : theme.textSecondary }}>{error ?? ""}</Text>
        <Text style={{ fontSize: 11.5, color: count > WORDS ? colors.destructive : theme.textTertiary, fontVariant: ["tabular-nums"] }}>
          {count > WORDS ? "too many words" : `${count}/${WORDS} words`}
        </Text>
      </View>
      {folder ? (
        <View style={{ flexDirection: "row", alignItems: "center", gap: 6, marginTop: 10 }}>
          <Symbol name="folder" size={11} color={theme.textSecondary} style={{ width: 14, height: 14 }} />
          <Text numberOfLines={1} style={{ flex: 1, fontSize: 11.5, color: theme.textSecondary }}>
            {folderLabel(folder)}
          </Text>
          {onChooseFolder ? <Button title="Change…" kind="plain" onPress={onChooseFolder} /> : null}
        </View>
      ) : null}
      <Buttons>
        <Button title="Cancel" onPress={closeSettingsSheet} />
        <Button title={busy ? "Connecting…" : "Connect"} kind="primary" disabled={busy || count !== WORDS || !folder} onPress={() => void submit()} />
      </Buttons>
    </Sheet>
  );
}

export function showConnectDevice() {
  showSettingsSheet(<ConnectDeviceSheet />);
}

function ConnectDeviceSheet() {
  const theme = useTheme();
  const colors = useFormColors();
  const [qr, setQr] = useState<string | null>(null);
  const [words, setWords] = useState<string[] | null>(null);
  const access = useRecoveryAccess(() => { setQr(null); setWords(null); }, "Couldn’t show the recovery code. Please try again.");
  const unlock = () => access.run(async () => SyncNative?.qrCode(), setQr, true);
  return (
    <Sheet width={480} onClose={access.close}>
      <Title>Connect Another Device</Title>
      <Body>
        On your other Mac, open Ardia › Settings › Sync and choose the same sync folder. Then click Enter Recovery Phrase and enter the 24 words
        of your recovery phrase.
      </Body>
      {access.unlocked ? <View style={{ flexDirection: "row", alignItems: "center", gap: 16, marginTop: 16 }}>
        <View style={{ width: 132, height: 132, borderRadius: 8, backgroundColor: "#FFFFFF", alignItems: "center", justifyContent: "center" }}>
          {qr ? <Image source={{ uri: qr }} style={{ width: 120, height: 120 }} /> : null}
        </View>
        <Text style={{ flex: 1, fontSize: 12, lineHeight: 16, color: theme.textSecondary }}>
          This code contains your recovery phrase. Anyone with it can read your synced data. Clipboard copies stay on this Mac and expire after one minute.
        </Text>
      </View> : <Body>Unlock with Touch ID or your Mac password to reveal your recovery phrase.</Body>}
      {access.error ? <Body>{access.error}</Body> : null}
      {words ? (
        <View style={{ flexDirection: "row", flexWrap: "wrap", marginTop: 14, padding: 10, borderRadius: 8, backgroundColor: colors.group }}>
          {words.map((w, i) => (
            <Text key={i} style={{ width: "25%", paddingVertical: 3, fontSize: 12.5, color: theme.textPrimary, fontFamily: "Menlo" }}>
              <Text style={{ color: theme.textTertiary }}>{`${i + 1}`.padStart(2, " ")} </Text>
              {w}
            </Text>
          ))}
        </View>
      ) : null}
      <Buttons
        left={
          access.unlocked ? <>
            <Button title={words ? "Hide Words" : "Show Words"} disabled={access.busy} onPress={() => (words ? setWords(null) : void access.run(async () => SyncNative?.recoveryWords(), setWords))} />
            <Button title="Copy Words" disabled={access.busy} onPress={() => void access.run(async () => SyncNative?.copyRecoveryPhrase(false), undefined, false, "Recovery phrase wasn’t copied. Please try again.")} />
          </> : undefined
        }
      >
        <Button title="Done" kind={access.unlocked ? "primary" : undefined} onPress={access.close} />
        {!access.unlocked ? <Button title={access.busy ? "Unlocking…" : "Unlock Recovery Phrase"} kind="primary" disabled={access.busy} onPress={() => void unlock()} /> : null}
      </Buttons>
    </Sheet>
  );
}

export function showStopSync() {
  showSettingsSheet(<StopSheet />);
}

function StopSheet() {
  return (
    <Sheet width={420} onClose={closeSettingsSheet}>
      <Title>Stop Syncing This Device?</Title>
      <Body>
        Syncing will stop on this device. To re-enable sync, you’ll need another device that is currently syncing, or the recovery phrase from your
        Recovery Kit. Everything on this Mac stays as it is.
      </Body>
      <Buttons left={<Button title="Save Recovery Kit" onPress={() => showSettingsSheet(<RecoveryKitSheet />)} />}>
        <Button title="Cancel" onPress={closeSettingsSheet} />
        <Button title="Stop Syncing" kind="destructive" onPress={() => showSettingsSheet(<DeleteDataSheet />)} />
      </Buttons>
    </Sheet>
  );
}

function DeleteDataSheet() {
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const finish = async (deleteData: boolean) => {
    setBusy(true);
    await stopSync({ deleteData });
    closeSettingsSheet();
  };
  return (
    <Sheet width={420} onClose={() => void finish(false)}>
      <Title>Delete Sync Data?</Title>
      <Body>
        Would you also like to permanently delete your synced data from the sync folder? This will stop syncing on all your other devices too. To sync
        again, you’ll need to set up each device from scratch. Your data on each Mac stays.
      </Body>
      <View style={{ marginTop: 12 }}>
        <Checkbox value={understood} onChange={setUnderstood} label="I understand this cannot be undone" />
      </View>
      <Buttons>
        <Button title="Keep Sync Data" disabled={busy} onPress={() => void finish(false)} />
        <Button title="Delete My Sync Data" kind="destructive" disabled={!understood || busy} onPress={() => void finish(true)} />
      </Buttons>
    </Sheet>
  );
}

export function folderLabel(folder: Pick<FolderInfo, "path" | "inICloud">): string {
  if (folder.inICloud) {
    const rest = folder.path.split("com~apple~CloudDocs")[1]?.split("/").filter(Boolean) ?? [];
    return ["iCloud Drive", ...rest].join(" › ");
  }
  return folder.path.replace(/^\/Users\/[^/]+/, "~");
}
