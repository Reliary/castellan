# castellan desktop controls (Hyprland / Omarchy)

Two `systemctl --user` oneshot units are installed by `castellan service
install`:

- `castellan-freeze.service` — freeze every session scope
- `castellan-thaw.service` — thaw every session scope

They run `castellan freeze --daemonless` / `castellan thaw --daemonless`
against cgroupfs directly: no daemon round trip, no tty gate. Equal power
to the plain CLI verb: an enveloped agent cannot write `cgroup.freeze`
(the Landlock denial that stops a direct write stops this binary too),
and an unconfined same-uid process needs no unit to do it.

## Hyprland keybind

Append to `~/.config/hypr/hyprland.conf`:

```
bind = SUPER, Escape, exec, systemctl --user start castellan-freeze.service
bind = SUPER SHIFT, Escape, exec, systemctl --user start castellan-thaw.service
```

`SUPER+Escape` freezes; `SUPER+Shift+Escape` thaws. Both are
idempotent — starting an already-started oneshot is a no-op, and
freezing an already-frozen session succeeds without disturbing it.

## Quickshell panel

`panel.qml` is a minimal Quickshell panel that reads `castellan status
--json` and offers a freeze/thaw toggle. See the file header for install
notes.
