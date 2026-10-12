import AVKit
import SwiftUI

/// The system AirPlay route picker (AirPlay 2 speakers, HomePods, Apple TVs, Bluetooth).
struct AirPlayButton: UIViewRepresentable {
    var tint: Color = .primary

    func makeUIView(context: Context) -> AVRoutePickerView {
        let view = AVRoutePickerView()
        view.prioritizesVideoDevices = false
        view.tintColor = UIColor(tint)
        view.activeTintColor = UIColor(Color.accentColor)
        return view
    }

    func updateUIView(_ view: AVRoutePickerView, context: Context) {
        view.tintColor = UIColor(tint)
    }
}
