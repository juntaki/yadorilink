/*
 * bridging header exposing the Rust FFI core
 * (`yadorilink_shell_core`, see shell-ext/macos/core/) to the Swift
 * `FIFinderSync` extension (FinderSync.swift). Compiled in via
 * `swiftc -import-objc-header` (see ../build.sh) with
 * `-I ../../core/include` on the search path, so the relative #include
 * below resolves without hardcoding an absolute path.
 */
#include "yadorilink_shell_core.h"
