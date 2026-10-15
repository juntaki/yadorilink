/// Words VoiceOver speaks where the screen shows only an icon or a colour.
extension Notice {
    /// A failure says so in words; a success line reads as is.
    var spokenText: String {
        kind == .failure ? "Error: \(text)" : text
    }
}

extension SignInModel {
    /// The sign-in status line, with the failure marked in words.
    var spokenStatusText: String {
        if case .failed = phase { return "Error: \(statusText)" }
        return statusText
    }
}
