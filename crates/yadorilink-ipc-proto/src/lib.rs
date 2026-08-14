pub mod framing;

pub mod sync {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.sync.v1.rs"));
}

pub mod shellipc {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.shellipc.v1.rs"));
}

pub mod local_discovery {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.local_discovery.v1.rs"));
}

pub mod daemonctl {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.daemonctl.v1.rs"));

    /// Exact daemon-control protocol generation for the current pre-release
    /// source tree. The CLI, desktop app, and daemon are shipped as one unit;
    /// development builds are not required to interoperate across protocol
    /// generations. A version mismatch should fail clearly rather than select a
    /// backward-compatibility path.
    pub const CONTROL_PROTOCOL_VERSION: u32 = 6;
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::daemonctl::daemon_control_request::Payload as ReqPayload;
    use crate::daemonctl::{
        create_and_link_command_response, daemon_control_response, remove_device_command_response,
        CreateAndLinkCommandRequest, CreateAndLinkCommandResponse, DaemonControlRequest,
        DaemonControlResponse, EnrollmentCommandOutcome, MembershipHandoffResult,
        RemoveDeviceCommandRequest, RemoveDeviceCommandResponse, ReplicaMembershipCommandOutcome,
        StatusRequest,
    };

    /// A request built by a current CLI carries `protocol_version ==
    /// CONTROL_PROTOCOL_VERSION` alongside its payload, and both round-trip
    /// through encode/decode untouched by each other — the top-level version
    /// field and the `oneof payload` are independent.
    #[test]
    fn current_daemon_control_request_round_trips_protocol_version_and_payload() {
        let req = DaemonControlRequest {
            payload: Some(ReqPayload::Status(StatusRequest {})),
            protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let decoded = DaemonControlRequest::decode(req.encode_to_vec().as_slice()).unwrap();

        assert_eq!(decoded.protocol_version, crate::daemonctl::CONTROL_PROTOCOL_VERSION);
        assert!(matches!(decoded.payload, Some(ReqPayload::Status(_))));
    }

    #[test]
    fn high_level_membership_command_round_trips() {
        let request = DaemonControlRequest {
            payload: Some(ReqPayload::RemoveDeviceCommand(RemoveDeviceCommandRequest {
                device_id: "device-b".into(),
                force: true,
            })),
            protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let decoded = DaemonControlRequest::decode(request.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(decoded.payload, Some(ReqPayload::RemoveDeviceCommand(_))));

        let response = DaemonControlResponse {
            payload: Some(daemon_control_response::Payload::RemoveDeviceCommand(
                RemoveDeviceCommandResponse {
                    result: Some(remove_device_command_response::Result::Outcome(
                        ReplicaMembershipCommandOutcome {
                            handoffs: vec![MembershipHandoffResult {
                                group_id: "group-1".into(),
                                target_device_id: "device-c".into(),
                                lease_id: "lease-1".into(),
                                membership_generation: 2,
                            }],
                            forced_group_ids: Vec::new(),
                            unknown_scope_operation_id: String::new(),
                        },
                    )),
                },
            )),
            daemon_protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let decoded = DaemonControlResponse::decode(response.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(
            decoded.payload,
            Some(daemon_control_response::Payload::RemoveDeviceCommand(_))
        ));
    }

    #[test]
    fn high_level_enrollment_command_round_trips() {
        let request = DaemonControlRequest {
            payload: Some(ReqPayload::CreateAndLinkCommand(CreateAndLinkCommandRequest {
                group_name: "documents".into(),
                local_path: "/tmp/documents".into(),
                on_demand: false,
                acknowledge_risks: true,
            })),
            protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let decoded = DaemonControlRequest::decode(request.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(decoded.payload, Some(ReqPayload::CreateAndLinkCommand(_))));

        let response = DaemonControlResponse {
            payload: Some(daemon_control_response::Payload::CreateAndLinkCommand(
                CreateAndLinkCommandResponse {
                    result: Some(create_and_link_command_response::Result::Outcome(
                        EnrollmentCommandOutcome {
                            operation_id: "operation-1".into(),
                            group_id: "group-1".into(),
                            local_path: "/tmp/documents".into(),
                        },
                    )),
                },
            )),
            daemon_protocol_version: crate::daemonctl::CONTROL_PROTOCOL_VERSION,
        };
        let decoded = DaemonControlResponse::decode(response.encode_to_vec().as_slice()).unwrap();
        assert!(matches!(
            decoded.payload,
            Some(daemon_control_response::Payload::CreateAndLinkCommand(_))
        ));
    }
}
