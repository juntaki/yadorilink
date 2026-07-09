/*
 * bridging header exposing the Rust FFI core
 * (`yadorilink_fileprovider_core`, see shell-ext/macos/fileprovider-core/)
 * to the Swift `NSFileProviderReplicatedExtension`. Compiled in via
 * `swiftc -import-objc-header` / Xcode's SWIFT_OBJC_BRIDGING_HEADER
 * (see ../project.yml) with `-I ../../fileprovider-core/include` on the
 * search path, so the relative #include below resolves without
 * hardcoding an absolute path — matches the exact pattern
 * `YadoriLinkFinderSync-Bridging-Header.h` uses for `core`.
 */
#include "yadorilink_fileprovider_core.h"
