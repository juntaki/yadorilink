// Shared building blocks, implemented once: tones, badges, banners, notices,
// section headers, loading and empty states.

import AppKit
import SwiftUI
import YadoriLinkModel

extension StatusTone {
    public var color: Color {
        switch self {
        case .ok: .green
        case .info: .blue
        case .neutral: .secondary
        case .warning: .orange
        case .danger: .red
        }
    }

    public var symbol: String {
        switch self {
        case .ok: "checkmark.circle.fill"
        case .info: "arrow.triangle.2.circlepath.circle.fill"
        case .neutral: "pause.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .danger: "xmark.octagon.fill"
        }
    }
}

public struct StatusBadge: View {
    let title: String
    let tone: StatusTone

    public init(_ title: String, tone: StatusTone) {
        self.title = title
        self.tone = tone
    }

    public var body: some View {
        Text(title)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(tone.color)
            .background(tone.color.opacity(0.14), in: Capsule())
    }
}

public struct OnlineDot: View {
    let online: Bool
    public init(online: Bool) { self.online = online }
    public var body: some View {
        Circle()
            .fill(online ? Color.green : Color.secondary.opacity(0.5))
            .frame(width: 7, height: 7)
            .accessibilityLabel(online ? "Online" : "Offline")
    }
}

/// The one banner a screen shows when the parts below it can't work.
public struct AppBannerView: View {
    let banner: AppBanner
    let isWorking: Bool
    let action: () -> Void

    public init(_ banner: AppBanner, isWorking: Bool = false, action: @escaping () -> Void) {
        self.banner = banner
        self.isWorking = isWorking
        self.action = action
    }

    public var body: some View {
        HStack(spacing: 12) {
            Image(systemName: banner == .daemonUnavailable ? "bolt.horizontal.circle" : "person.crop.circle.badge.exclamationmark")
                .font(.title2)
                .foregroundStyle(.orange)
            Text(banner.title)
                .font(.headline)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if isWorking { ProgressView().controlSize(.small) }
            Button(banner.actionTitle, action: action)
                .buttonStyle(.borderedProminent)
                .disabled(isWorking)
        }
        .padding(12)
        .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.orange.opacity(0.3)))
    }
}

/// A single result line at the top of a window.
public struct NoticeView: View {
    let notice: Notice
    let dismiss: () -> Void

    public init(_ notice: Notice, dismiss: @escaping () -> Void) {
        self.notice = notice
        self.dismiss = dismiss
    }

    public var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: notice.kind == .success ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                .foregroundStyle(notice.kind == .success ? .green : .red)
            Text(notice.text)
                .fixedSize(horizontal: false, vertical: true)
                .help(notice.detail ?? "")
            Spacer()
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark").font(.caption)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Dismiss")
        }
        .padding(10)
        .background((notice.kind == .success ? Color.green : Color.red).opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }
}

extension View {
    /// Shows `notice` as a result line above the content.
    public func noticeBar(_ notice: Binding<Notice?>) -> some View {
        VStack(spacing: 0) {
            if let current = notice.wrappedValue {
                NoticeView(current) { notice.wrappedValue = nil }
                    .padding([.horizontal, .top], 16)
                    .transition(.opacity)
            }
            self
        }
    }
}

public struct SectionHeader: View {
    let title: String
    let trailing: AnyView?

    public init(_ title: String) {
        self.title = title
        trailing = nil
    }

    public init(_ title: String, @ViewBuilder trailing: () -> some View) {
        self.title = title
        self.trailing = AnyView(trailing())
    }

    public var body: some View {
        HStack {
            Text(title).font(.headline)
            Spacer()
            trailing
        }
    }
}

public struct LoadingRow: View {
    let text: String
    public init(_ text: String = "Loading…") { self.text = text }
    public var body: some View {
        HStack(spacing: 8) {
            ProgressView().controlSize(.small)
            Text(text).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
    }
}

public struct EmptyStateText: View {
    let text: String
    public init(_ text: String) { self.text = text }
    public var body: some View {
        Text(text)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 4)
    }
}

public struct FieldRow<Value: View>: View {
    let label: String
    let value: Value
    public init(_ label: String, @ViewBuilder value: () -> Value) {
        self.label = label
        self.value = value()
    }
    public var body: some View {
        LabeledContent(label) { value }
    }
}

/// A card-like container used for list groups outside `Form`.
struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 10) { content }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
}

/// A confirmation step for removals refused on durability grounds.
struct OverrideAlert: ViewModifier {
    @Binding var prompt: OverridePrompt?
    let confirm: () async -> Void

    func body(content: Content) -> some View {
        content.alert(
            "No other device has a complete copy yet",
            isPresented: Binding(get: { prompt != nil }, set: { if !$0 { prompt = nil } }),
            presenting: prompt
        ) { prompt in
            Button("Cancel", role: .cancel) {}
            Button(prompt.buttonTitle, role: .destructive) { Task { await confirm() } }
        } message: { prompt in
            Text("Removing \(prompt.targetName) now could lose files that only exist there.\n\n\(prompt.message)")
        }
    }
}

struct WarningList: View {
    let warnings: [MembershipWarning]
    var body: some View {
        ForEach(warnings, id: \.self) { warning in
            Label(warning.text, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

extension View {
    func overrideAlert(_ prompt: Binding<OverridePrompt?>, confirm: @escaping () async -> Void) -> some View {
        modifier(OverrideAlert(prompt: prompt, confirm: confirm))
    }
}
