use std::sync::Arc;

use crate::sync_error::SyncError;

use super::ports::MaterializationPort;

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

    pub(crate) fn evict(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        self.port.evict(group_id, path)
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

        fn evict(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
            self.calls.lock().unwrap().push(format!("evict({group_id},{path})"));
            Ok(())
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

        assert_eq!(
            *port.calls.lock().unwrap(),
            vec![
                "hydrate(group-1,/a)".to_string(),
                "pin(group-1,/b)".to_string(),
                "unpin(group-1,/c)".to_string(),
                "evict(group-1,/d)".to_string(),
            ]
        );
    }
}
