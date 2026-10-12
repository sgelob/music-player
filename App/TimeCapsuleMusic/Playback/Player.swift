import AVFoundation
import MediaPlayer
import Observation
import TimeCapsuleKit
import UIKit

/// Plays a queue of Time Capsule tracks through AVPlayer.
///
/// AirPlay: the audio session uses the `.longFormAudio` route-sharing policy, so the system
/// AirPlay picker (Control Center, lock screen, or the in-app button) offers AirPlay 2 speakers
/// and Apple TVs, and playback, remote controls and Now Playing follow the chosen route.
@MainActor @Observable
final class Player {
    var client: SMBClient?

    private(set) var queue: [Track] = []
    private(set) var index: Int?
    private(set) var isPlaying = false
    private(set) var isLoading = false
    private(set) var currentTime: Double = 0
    private(set) var duration: Double = 0
    private(set) var title = ""
    private(set) var artist = ""
    private(set) var album = ""
    private(set) var artwork: UIImage?
    /// Download progress per track path (0...1), for tracks being fetched.
    private(set) var downloadProgress: [String: Double] = [:]
    var errorMessage: String?

    var current: Track? { index.map { queue[$0] } }
    var hasNext: Bool { index.map { $0 + 1 < queue.count } ?? false }

    @ObservationIgnored private let player = AVPlayer()
    @ObservationIgnored private let cache = TrackCache.shared
    @ObservationIgnored private var loadTask: Task<Void, Never>?
    @ObservationIgnored private var prefetch: (path: String, task: Task<URL, Error>)?
    @ObservationIgnored private var observers: [NSObjectProtocol] = []
    @ObservationIgnored private var statusObservation: NSKeyValueObservation?
    @ObservationIgnored private var timeObserver: Any?
    @ObservationIgnored private var sessionActive = false

    init() {
        player.allowsExternalPlayback = true
        player.automaticallyWaitsToMinimizeStalling = false // local files
        observePlayer()
        setUpRemoteCommands()
    }

    // MARK: - Queue control

    func play(_ tracks: [Track], startingAt start: Int = 0) {
        guard !tracks.isEmpty else { return }
        queue = tracks
        index = min(max(start, 0), tracks.count - 1)
        startCurrent()
    }

    func shuffle(_ tracks: [Track]) {
        play(tracks.shuffled())
    }

    func togglePlayPause() {
        if isPlaying { pause() } else { resume() }
    }

    func resume() {
        guard player.currentItem != nil else {
            if current != nil { startCurrent() }
            return
        }
        activateSession()
        player.play()
        updateNowPlaying()
    }

    func pause() {
        player.pause()
        updateNowPlaying()
    }

    func next() {
        guard let i = index, i + 1 < queue.count else { return }
        index = i + 1
        startCurrent()
    }

    func previous() {
        guard let i = index else { return }
        if currentTime > 3 || i == 0 {
            seek(to: 0)
        } else {
            index = i - 1
            startCurrent()
        }
    }

    func seek(to seconds: Double) {
        currentTime = seconds
        player.seek(to: CMTime(seconds: seconds, preferredTimescale: 600), toleranceBefore: .zero, toleranceAfter: .zero) {
            [weak self] _ in Task { @MainActor in self?.updateNowPlaying() }
        }
    }

    func stop() {
        loadTask?.cancel()
        prefetch?.task.cancel()
        prefetch = nil
        player.replaceCurrentItem(with: nil)
        queue = []
        index = nil
        isLoading = false
        MPNowPlayingInfoCenter.default().nowPlayingInfo = nil
    }

    // MARK: - Loading

    private func startCurrent() {
        guard let track = current, let client else { return }
        loadTask?.cancel()
        player.replaceCurrentItem(with: nil)
        currentTime = 0
        duration = 0
        title = track.displayName
        artist = ""
        album = ""
        artwork = nil
        errorMessage = nil
        isLoading = true
        updateNowPlaying()

        loadTask = Task { [weak self] in
            guard let self else { return }
            do {
                let url = try await self.localFile(for: track, client: client)
                guard !Task.isCancelled, self.current == track else { return }
                let item = AVPlayerItem(url: url)
                self.player.replaceCurrentItem(with: item)
                self.activateSession()
                self.player.play()
                self.isLoading = false
                await self.loadMetadata(from: item.asset, for: track)
                self.prefetchNext()
            } catch is CancellationError {
            } catch {
                guard self.current == track else { return }
                self.isLoading = false
                self.errorMessage = "Couldn't load \(track.displayName): \(error.localizedDescription)"
            }
        }
    }

    /// Uses the prefetched download when it's for this track; otherwise cancels it (the SMB
    /// connection is shared, so a stale download would delay this one) and downloads now.
    private func localFile(for track: Track, client: SMBClient) async throws -> URL {
        if let p = prefetch, p.path == track.path {
            prefetch = nil
            return try await withTaskCancellationHandler { try await p.task.value } onCancel: { p.task.cancel() }
        }
        prefetch?.task.cancel()
        prefetch = nil
        return try await cache.file(for: track, client: client, progress: progressHandler(for: track))
    }

    private func prefetchNext() {
        guard let i = index, i + 1 < queue.count, let client else { return }
        let track = queue[i + 1]
        guard prefetch?.path != track.path else { return }
        prefetch?.task.cancel()
        let progress = progressHandler(for: track)
        prefetch = (track.path, Task { [cache] in
            try await cache.file(for: track, client: client, progress: progress)
        })
    }

    private func progressHandler(for track: Track) -> @Sendable (Double) -> Void {
        let path = track.path
        return { [weak self] fraction in
            Task { @MainActor in
                guard let self else { return }
                if fraction >= 1 {
                    self.downloadProgress[path] = nil
                } else if fraction - (self.downloadProgress[path] ?? 0) >= 0.01 {
                    self.downloadProgress[path] = fraction
                }
            }
        }
    }

    private func loadMetadata(from asset: AVAsset, for track: Track) async {
        guard let items = try? await asset.load(.commonMetadata) else { return }
        func string(_ id: AVMetadataIdentifier) async -> String? {
            guard let item = AVMetadataItem.metadataItems(from: items, filteredByIdentifier: id).first else { return nil }
            return try? await item.load(.stringValue)
        }
        let title = await string(.commonIdentifierTitle)
        let artist = await string(.commonIdentifierArtist)
        let album = await string(.commonIdentifierAlbumName)
        var image: UIImage?
        if let art = AVMetadataItem.metadataItems(from: items, filteredByIdentifier: .commonIdentifierArtwork).first,
           let data = try? await art.load(.dataValue) {
            image = UIImage(data: data)
        }
        guard current == track else { return }
        if let title, !title.isEmpty { self.title = title }
        self.artist = artist ?? ""
        self.album = album ?? ""
        self.artwork = image
        updateNowPlaying()
    }

    // MARK: - System integration

    private func activateSession() {
        guard !sessionActive else { return }
        let session = AVAudioSession.sharedInstance()
        do {
            try session.setCategory(.playback, mode: .default, policy: .longFormAudio)
            try session.setActive(true)
            sessionActive = true
        } catch {
            errorMessage = "Audio session error: \(error.localizedDescription)"
        }
    }

    private func observePlayer() {
        timeObserver = player.addPeriodicTimeObserver(
            forInterval: CMTime(seconds: 0.5, preferredTimescale: 600), queue: .main
        ) { [weak self] time in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.currentTime = time.seconds.isFinite ? time.seconds : 0
                if let d = self.player.currentItem?.duration.seconds, d.isFinite, d != self.duration {
                    self.duration = d
                    self.updateNowPlaying()
                }
            }
        }
        statusObservation = player.observe(\.timeControlStatus, options: [.new]) { [weak self] player, _ in
            let playing = player.timeControlStatus != .paused
            Task { @MainActor in self?.isPlaying = playing }
        }
        let center = NotificationCenter.default
        observers.append(center.addObserver(forName: AVPlayerItem.didPlayToEndTimeNotification, object: nil, queue: .main) {
            [weak self] note in
            MainActor.assumeIsolated {
                guard let self, (note.object as? AVPlayerItem) === self.player.currentItem else { return }
                if self.hasNext { self.next() } else { self.player.pause(); self.seek(to: 0) }
            }
        })
        observers.append(center.addObserver(forName: AVAudioSession.interruptionNotification, object: nil, queue: .main) {
            [weak self] note in
            guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
                  AVAudioSession.InterruptionType(rawValue: raw) == .ended,
                  let opts = note.userInfo?[AVAudioSessionInterruptionOptionKey] as? UInt,
                  AVAudioSession.InterruptionOptions(rawValue: opts).contains(.shouldResume) else { return }
            MainActor.assumeIsolated { self?.player.play() }
        })
    }

    private func setUpRemoteCommands() {
        let c = MPRemoteCommandCenter.shared()
        c.playCommand.addTarget { [weak self] _ in self?.resume(); return .success }
        c.pauseCommand.addTarget { [weak self] _ in self?.pause(); return .success }
        c.togglePlayPauseCommand.addTarget { [weak self] _ in self?.togglePlayPause(); return .success }
        c.nextTrackCommand.addTarget { [weak self] _ in self?.next(); return .success }
        c.previousTrackCommand.addTarget { [weak self] _ in self?.previous(); return .success }
        c.changePlaybackPositionCommand.addTarget { [weak self] event in
            guard let e = event as? MPChangePlaybackPositionCommandEvent else { return .commandFailed }
            self?.seek(to: e.positionTime)
            return .success
        }
    }

    private func updateNowPlaying() {
        guard current != nil else {
            MPNowPlayingInfoCenter.default().nowPlayingInfo = nil
            return
        }
        var info: [String: Any] = [
            MPMediaItemPropertyTitle: title,
            MPMediaItemPropertyArtist: artist,
            MPMediaItemPropertyAlbumTitle: album,
            MPMediaItemPropertyPlaybackDuration: duration,
            MPNowPlayingInfoPropertyElapsedPlaybackTime: player.currentTime().seconds.isFinite ? player.currentTime().seconds : 0,
            MPNowPlayingInfoPropertyPlaybackRate: player.rate,
            MPNowPlayingInfoPropertyMediaType: MPNowPlayingInfoMediaType.audio.rawValue,
        ]
        if let index {
            info[MPNowPlayingInfoPropertyPlaybackQueueIndex] = index
            info[MPNowPlayingInfoPropertyPlaybackQueueCount] = queue.count
        }
        if let artwork {
            info[MPMediaItemPropertyArtwork] = MPMediaItemArtwork(boundsSize: artwork.size) { _ in artwork }
        }
        MPNowPlayingInfoCenter.default().nowPlayingInfo = info
    }
}
