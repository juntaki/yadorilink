//! `LinkRuntimeController`-backed [`LinkRuntimePort`].

use std::sync::Arc;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::application::ports::{BoxFuture, LinkRuntimePort};

pub(crate) struct DaemonLinkRuntimeAdapter {
    controller: Arc<LinkRuntimeController>,
}

impl DaemonLinkRuntimeAdapter {
    pub(crate) fn new(controller: Arc<LinkRuntimeController>) -> Self {
        Self { controller }
    }
}

impl LinkRuntimePort for DaemonLinkRuntimeAdapter {
    fn start_link_watch(&self, local_path: String, group_id: String) -> Result<(), String> {
        self.controller.start(local_path, group_id).map_err(|e| e.to_string())
    }

    fn stop_link_watch<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.controller.stop(local_path))
    }
}
