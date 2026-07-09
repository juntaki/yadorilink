/*
 * on-demand-sync task 7.2: bridging header exposing the Rust FFI core
 * (`yadorilink_fileprovider_core`, see shell-ext/macos/fileprovider-core/)
 * to the host app's DomainRegistration.swift, which needs
 * yadorilink_fp_list_on_demand_folders to discover which OnDemand folder
 * groups to register as NSFileProviderDomains.
 */
#include "yadorilink_fileprovider_core.h"
