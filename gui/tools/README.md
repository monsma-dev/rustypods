# webkit-snapshot

Render a URL in WebKitGTK — the same engine the Tauri app uses — and save a
PNG. Used to produce the screenshots under docs/screenshots/ without a
running Tauri window (the GUI's mock mode renders demo data when no
`__TAURI_INTERNALS__` is present, e.g. `?detail=dev`, `?newpod=1`).

Build & run (inside the arch distrobox):

    gcc -O2 -o webkit-snapshot webkit-snapshot.c \
      $(pkg-config --cflags --libs gtk+-3.0 webkit2gtk-4.1)
    npm run dev   # serve :1420
    DISPLAY=:0 ./webkit-snapshot 'http://localhost:1420/?newpod=1' out.png
