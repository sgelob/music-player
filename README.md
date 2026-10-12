# TC Music

An iPhone/iPad app that plays the music stored on an **AirPort Time Capsule** and sends it to
**AirPlay** speakers (HomePod, Apple TV, AirPlay 2 speakers).

## Why a custom app is needed

The Time Capsule only speaks **SMB1** (and AFP). Starting with iOS 13, Apple's SMB client (and the
Files app) only supports SMB2/3, so iOS can't open a Time Capsule on its own. This app includes
its own small SMB1 client, **TimeCapsuleKit**, written in pure Swift with no dependencies.

## Features

- Finds Time Capsules on your Wi-Fi automatically (Bonjour), or connects by address.
- Signs in with the disk password, base station password or an account. NTLMv2 and NTLMv1,
  with or without NTLMSSP, are tried in turn and the one that works is remembered.
- Browse folders, Play / Shuffle a folder, or tap a song to start there.
- AirPlay button in the mini player and in Now Playing. Control Center and lock-screen
  controls work too.
- Plays in the background. The next song is fetched while the current one plays.
- Songs are copied to the phone before playing, so seeking is instant and Wi-Fi drops don't stop
  the music. The cache is capped at 3 GB and can be cleared in Settings.
- Plays MP3, AAC/M4A, ALAC, FLAC, WAV and AIFF.

## Run it on your iPhone

1. Open `TimeCapsuleMusic.xcodeproj` in Xcode (16 or newer).
2. Select the **TimeCapsuleMusic** target → *Signing & Capabilities* → choose your Team, and
   change the bundle identifier (`com.example.TimeCapsuleMusic`) to something unique to you.
   A free Apple ID works; the app then needs re-installing every 7 days.
3. Plug in your iPhone, select it as the run destination, and press **Run**.
4. On first launch, allow **Local Network** access. Pick your Time Capsule, enter the password
   from AirPort Utility (any user name works with a disk password), and choose the disk
   (usually **Data**).

## Layout

| Path | What |
| --- | --- |
| `Sources/TimeCapsuleKit` | SMB1 client: NTLM auth (MD4/MD5/DES implemented here), share and folder listing, pipelined reads, auto-reconnect |
| `Sources/tcmusic` | CLI for testing a server from a Mac/Linux: `swift run tcmusic <host> <user> <password> ls Data Music` |
| `Tests/TimeCapsuleKitTests` | Crypto and NTLM tests using the MS-NLMP spec vectors |
| `App/TimeCapsuleMusic` | SwiftUI app: setup, browser, player (AVPlayer + AirPlay), track cache |
| `project.yml` | XcodeGen spec. The `.xcodeproj` is generated from it (`xcodegen` after editing) |

## Troubleshooting

- **"Couldn't find … on the network"**: use the IP address shown in AirPort Utility instead
  of the `.local` name. Also check *Settings → Privacy → Local Network → TC Music*.
- **"Wrong user name or password"**: with *Secure Shared Disks: With accounts*, use the
  account name. Otherwise any name plus the disk/base station password should work.
- To check what your Time Capsule supports from a Mac:
  `TC_AUTH=v1 swift run tcmusic Time-Capsule.local admin PASSWORD shares` (try `v1`, `v2`,
  `v1-basic`, `v2-basic`).
