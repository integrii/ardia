# Recovery protection checks

On macOS with the Swift command-line tools and repository dependencies installed:

```sh
bash packages/sync/scripts/recovery-protection.sh /path/to/scratch
```

Set `NODE` if Node is outside your shell’s PATH. These checks compile the production authorization, clipboard, and export helpers. They use injected authentication, mock secrets, private pasteboards, and isolated files; no app or authentication dialog opens. The JavaScript check executes the production recovery hook with controlled hook/native boundaries, rather than rendering the UI.

Authorization lasts 60 seconds. Clipboard copies expire after 60 seconds unless replaced first. Temporary shared kits and retained sharing delegates have an explicit five-minute maximum lifetime, even if a sharing service has not finished consuming the file. Completion or cancellation can clean up earlier. Sharing notifications cannot recall bytes already handed to another service.

Full Xcode, Expo integration, actual OS notification delivery, and rendered UI behavior require separate integration checks. These standalone assertions do not replace those checks.
