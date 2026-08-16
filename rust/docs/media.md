# Retail media

Playback is a modern presentation layer in `imperialism-app`. The 1997 MCI / DirectSound /
Video for Windows devices are not reconstructed. File discovery and WAVE extraction live on
`RetailAssets`.

## Movies

`TAssetMgr::PlayMovieClipAndDispatchTurnStateFollowup` builds `Movies/<name>.avi` and continues
immediately when the file cannot be opened. `kTurnEventOpeningCinematic` is the shared cinematic
dispatcher; `TViewMgr::HandleTurnEventDialogFactorySlotF4` picks the stem from `TSimMgr::mode`:

| Mode | Clip | When |
| --- | --- | --- |
| 1 | `open` | Startup opening |
| `0x0e` | `vote` | Decade / quarter-gate |
| `0x16` | `win` | Top-ten / victory |
| `0x17` | `lose` | Defeat cinematic mode |
| `0x19` | `win` or `lose` | Elimination, from nation eligibility |

Natural EOS and skip share `HandleTurnStateExitAndPostFollowupEventCode(0)`. Mouse down on
`TMovieView` and Escape / Space / Enter through `TGameWindow::DoKeyEvent` all call
`StopMovieIfActive` (MCI_STOP). Missing movies never enter that wait; they post followup
immediately.

A movie also stops CD/music, tears down DirectSound so AVI audio can open the wave device, and
paints the host frame black (`PALETTEINDEX(0)`). Destruction restores the tiled BITMAP `0x119`
surround and DirectSound.

This checkout's GStreamer 1.24 stack decodes Cinepak (`cvid`) plus PCM via `playbin` /
`avdec_cinepak`. Untouched GOG `Movies/*.avi` codecs still need a machine with
`IMPERIALISM_RETAIL_DIR`; the ignored `decodes_untouched_retail_open_avi` test is that proof.

## Music

Retail music is CD-DA through `TCdAudioDevice` using TMSF range `[cue, cue+1)`. GOG replaces the
CD with ripped files. The synthetic-install negative test already names `MUSIC/Track06.ogg`,
which matches ogg-winmm's `TrackNN` spelling for cue 6 (main menu).

Known cue ids from `TSoundPlayer` call sites:

| Cue | Use |
| --- | --- |
| 2, 3 | Load/save, credits, turn-flow pool |
| 4 | Diplomacy / deal book (`SetActiveAudioCueAndResetQueue(4, true)`) |
| 5 | Battle report |
| 6 | Main menu |
| 9 / 10 | Tactical victory / defeat |
| 11 | High score / game score |
| 12 | Credits |

`TSoundPlayer` is game policy, not an OS wrapper: active and pending cues, fade-before-switch
(`GetTickCountDiv16` + 6-tick timer), a cue pool, and a remaining pool sampled without
replacement. Volume is preference slot 3 (0..=255). Rust keeps that policy in `MusicDirector`
and drives one Bevy `AudioSink`. Presentation RNG is independent of the gameplay CRT stream;
native semantic captures do not pump `SelectAndScheduleRandomAudioCue`. Screen wiring today:
main menu cue 6, diplomacy/deal book `set_cue(4, fade)`, offer sheet `request_preset(4, fade)`,
load/save pool 2+3, credits cue 12. Missing GOG `MUSIC/TrackNN` files are skipped.

## Sound effects

WAVE resources live in `Data/wave.gob` (language IRG string `0x80` / `ImperialismApp::field_DC`),
not in `Imperialism.exe`. Load is `<id>.wav` on disk first, then `FindResourceA(..., "WAVE")`.
Retail had six DirectSound PCM channels; Rust plays ordinary one-shot Bevy `AudioPlayer`s and
despawns them when finished. Volume is preference slot 2 (0..=100); slot 2 at 0 skips playback.
Shared UI click is WAVE 7000 / `0x1b58`, fired from generated `Button` `Activate` and from the
sound slider's track-end (`TTwoPicSlider` mode 2). Missing WAVE resources continue silently.

## Chrome

`CMainFrame::OnEraseBkgnd` tiles `Imperialism.exe` BITMAP `0x119` in 128×128 chunks when the
background color is the tiled sentinel. Confirmed on the GOG exe: 128×128, 8 bpp, 17448-byte
DIB. Movie construction replaces that with black.

## Follow-up order

Persistent tiled chrome and a centered 640×480 `RetailViewport`, then wire `MovieBackend` to
`AppState::Cinematic`, then opening / decade / victory sequences. DirectSound's six-voice steal,
the millibel SFX curve, and exact CD fade tick timing stay evidence-driven.
