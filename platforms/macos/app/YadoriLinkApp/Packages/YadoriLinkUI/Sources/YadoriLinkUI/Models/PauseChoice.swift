import Foundation
import YadoriLinkModel

extension PauseDuration {
    /// The menu item that starts a pause of this length.
    public var menuTitle: String {
        switch self {
        case .thirtyMinutes: "Pause for 30 Minutes"
        case .oneHour: "Pause for 1 Hour"
        case .untilTomorrow: "Pause Until Tomorrow"
        case .untilResumed: "Pause Until I Resume"
        }
    }
}

/// How a paused folder says when it starts again. Only a timed pause has an end to name.
public enum PauseText {
    public static func status(until: Date?, now: Date, calendar: Calendar = .current) -> String {
        guard let until else { return "Paused" }
        let time = DateFormatter()
        time.locale = Format.locale
        time.calendar = calendar
        time.timeZone = calendar.timeZone
        if calendar.isDate(until, inSameDayAs: now) {
            time.dateFormat = "h:mm a"
            return "Paused until \(time.string(from: until))"
        }
        if let tomorrow = calendar.date(byAdding: .day, value: 1, to: calendar.startOfDay(for: now)), tomorrow == until {
            return "Paused until tomorrow"
        }
        time.dateFormat = "MMM d, h:mm a"
        return "Paused until \(time.string(from: until))"
    }
}
