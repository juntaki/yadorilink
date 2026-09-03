use std::sync::Arc;

use crate::sync_error::SyncError;

use super::ports::{EvictOutcome, MaterializationPort, MaterializationStatusSummary};

pub(crate) struct MaterializationService {
    port: Arc<dyn MaterializationPort>,
}

impl MaterializationService {
    pub(crate) fn new(port: Arc<dyn MaterializationPort>) -> Self {
        Self { port }
    }

    pub(crate) async fn hydrate(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.port.hydrate(group_id, path).await
    }

    pub(crate) async fn pin(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.port.pin(group_id, path).await
    }

    pub(crate) async fn unpin(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.port.unpin(group_id, path).await
    }

    pub(crate) fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError> {
        self.port.evict(group_id, path)
    }

    pub(crate) fn status(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationStatusSummary>, SyncError> {
        self.port.status(group_id, path)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::application::ports::BoxFuture;

    #[derive(Default)]
    struct FakeMaterializationPort {
        calls: Mutex<Vec<String>>,
    }

    impl MaterializationPort for FakeMaterializationPort {
        fn hydrate<'a>(
            &'a self,
            group_id: &'a str,
            path: &'a str,
        ) -> BoxFuture<'a, Result<(), SyncError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(format!("hydrate({group_id},{path})"));
                Ok(())
            })
        }

        fn pin<'a>(
            &'a self,
            group_id: &'a str,
            path: &'a str,
        ) -> BoxFuture<'a, Result<(), SyncError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(format!("pin({group_id},{path})"));
                Ok(())
            })
        }

        fn unpin<'a>(
            &'a self,
            group_id: &'a str,
            path: &'a str,
        ) -> BoxFuture<'a, Result<(), SyncError>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(format!("unpin({group_id},{path})"));
                Ok(())
            })
        }

        fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError> {
            self.calls.lock().unwrap().push(format!("evict({group_id},{path})"));
            Ok(EvictOutcome { dehydrated: true, ..Default::default() })
        }

        fn status(
            &self,
            group_id: &str,
            path: &str,
        ) -> Result<Option<MaterializationStatusSummary>, SyncError> {
            self.calls.lock().unwrap().push(format!("status({group_id},{path})"));
            Ok(Some(MaterializationStatusSummary {
                state: super::super::ports::MaterializationStateSummary::Hydrated,
                pinned: false,
            }))
        }
    }

    #[tokio::test]
    async fn every_method_delegates_to_the_port_with_the_same_arguments() {
        let port = Arc::new(FakeMaterializationPort::default());
        let service = MaterializationService::new(port.clone());

        service.hydrate("group-1", "/a").await.unwrap();
        service.pin("group-1", "/b").await.unwrap();
        service.unpin("group-1", "/c").await.unwrap();
        service.evict("group-1", "/d").unwrap();
        service.status("group-1", "/e").unwrap();

        assert_eq!(
            *port.calls.lock().unwrap(),
            vec![
                "hydrate(group-1,/a)".to_string(),
                "pin(group-1,/b)".to_string(),
                "unpin(group-1,/c)".to_string(),
                "evict(group-1,/d)".to_string(),
                "status(group-1,/e)".to_string(),
            ]
        );
    }

    /// A path the daemon has never indexed must surface as `None`, never
    /// as a guessed default state -- a caller (CLI/desktop app) must be
    /// able to distinguish "not currently known" from any real state.
    #[tokio::test]
    async fn status_reports_none_for_an_unknown_path() {
        #[derive(Default)]
        struct UnknownPathPort;
        impl MaterializationPort for UnknownPathPort {
            fn hydrate<'a>(
                &'a self,
                _group_id: &'a str,
                _path: &'a str,
            ) -> BoxFuture<'a, Result<(), SyncError>> {
                Box::pin(async { Ok(()) })
            }
            fn pin<'a>(
                &'a self,
                _group_id: &'a str,
                _path: &'a str,
            ) -> BoxFuture<'a, Result<(), SyncError>> {
                Box::pin(async { Ok(()) })
            }
            fn unpin<'a>(
                &'a self,
                _group_id: &'a str,
                _path: &'a str,
            ) -> BoxFuture<'a, Result<(), SyncError>> {
                Box::pin(async { Ok(()) })
            }
            fn evict(&self, _group_id: &str, _path: &str) -> Result<EvictOutcome, SyncError> {
                Ok(EvictOutcome::default())
            }
            fn status(
                &self,
                _group_id: &str,
                _path: &str,
            ) -> Result<Option<MaterializationStatusSummary>, SyncError> {
                Ok(None)
            }
        }

        let service = MaterializationService::new(Arc::new(UnknownPathPort));
        assert_eq!(service.status("group-1", "/never-seen.bin").unwrap(), None);
    }

    /// M4 Pass 4: `evict` must pass the REAL `EvictOutcome` back to the
    /// caller, not just `Ok(())` -- this is what closes the gap where a
    /// silently-no-op'd eviction (pinned/busy/not-yet-hydrated/changed on
    /// disk) used to be indistinguishable from a real one all the way up
    /// to the CLI/shell-extension response.
    #[tokio::test]
    async fn evict_returns_the_ports_real_outcome_not_a_bare_ok() {
        #[derive(Default)]
        struct NoOpEvictionPort;
        impl MaterializationPort for NoOpEvictionPort {
            fn hydrate<'a>(
                &'a self,
                _group_id: &'a str,
                _path: &'a str,
            ) -> BoxFuture<'a, Result<(), SyncError>> {
                Box::pin(async { Ok(()) })
            }
            fn pin<'a>(
                &'a self,
                _group_id: &'a str,
                _path: &'a str,
            ) -> BoxFuture<'a, Result<(), SyncError>> {
                Box::pin(async { Ok(()) })
            }
            fn unpin<'a>(
                &'a self,
                _group_id: &'a str,
                _path: &'a str,
            ) -> BoxFuture<'a, Result<(), SyncError>> {
                Box::pin(async { Ok(()) })
            }
            fn evict(&self, _group_id: &str, _path: &str) -> Result<EvictOutcome, SyncError> {
                // Simulates a pinned/busy/not-yet-hydrated file: the call
                // succeeds, but nothing was actually freed.
                Ok(EvictOutcome { dehydrated: false, ..Default::default() })
            }
            fn status(
                &self,
                _group_id: &str,
                _path: &str,
            ) -> Result<Option<MaterializationStatusSummary>, SyncError> {
                Ok(None)
            }
        }

        let service = MaterializationService::new(Arc::new(NoOpEvictionPort));
        let outcome = service.evict("group-1", "/pinned.bin").unwrap();
        assert!(
            !outcome.dehydrated,
            "a no-op eviction must surface dehydrated=false, not an indistinguishable Ok"
        );
    }
}
