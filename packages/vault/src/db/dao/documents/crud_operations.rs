//! CRUD operations for SurrealDbDao

use super::core::SurrealDbDao;
use crate::db::dao::Error;
use futures::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

impl<T> SurrealDbDao<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    pub fn create<'life0, 'fut>(
        &'life0 self,
        doc: T,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
    {
        let (tx, rx) = mpsc::channel(16);
        let db = Arc::clone(self.db());
        let table = self.table_name().to_string();
        let doc_to_send = doc.clone();

        // Avoid the content method's lifetime limitations by doing the serialization manually
        let content_string = match serde_json::to_string(&doc) {
            Ok(content) => content,
            Err(e) => {
                let _ = tx.try_send(Err(Error::Database(format!("Serialization failed: {e}"))));
                return Box::pin(ReceiverStream::new(rx));
            }
        };

        tokio::spawn(async move {
            let id = Uuid::new_v4().to_string();

            // Use raw SQL query to avoid content() method's lifetime issues
            let query = format!("CREATE {table}:{id} CONTENT {content_string}");

            match db.query(query).await {
                Ok(_) => {
                    let _ = tx.send(Ok(doc_to_send)).await;
                }
                Err(e) => {
                    let _ = tx.send(Err(Error::Database(e.to_string()))).await;
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }

    pub fn find_by_id<'life0, 'life1, 'fut>(
        &'life0 self,
        id: &'life1 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
    {
        let (tx, rx) = mpsc::channel(16);
        let db = Arc::clone(self.db());
        let table = self.table_name().to_string();
        let id = id.to_string();

        tokio::spawn(async move {
            match db.select::<Option<T>>((table, id)).await {
                Ok(response) => match response {
                    Some(item) => {
                        let _ = tx.send(Ok(item)).await;
                    }
                    None => {
                        let _ = tx.send(Err(Error::NotFound)).await;
                    }
                },
                Err(e) => {
                    let _ = tx.send(Err(Error::Database(e.to_string()))).await;
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }

    pub fn find_all<'life0, 'fut>(
        &'life0 self,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
    {
        let (tx, rx) = mpsc::channel(16);
        let db = Arc::clone(self.db());
        let table = self.table_name().to_string();

        tokio::spawn(async move {
            match db.select::<Vec<T>>(table).await {
                Ok(items) => {
                    for item in items {
                        if tx.send(Ok(item)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(Error::Database(e.to_string()))).await;
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }

    pub fn update<'life0, 'life1, 'fut>(
        &'life0 self,
        id: &'life1 str,
        doc: T,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
    {
        let (tx, rx) = mpsc::channel(16);
        let db = Arc::clone(self.db());
        let table = self.table_name().to_string();
        let id = id.to_string();
        let doc_to_send = doc.clone();

        // Avoid the content method's lifetime limitations by doing the serialization manually
        let content_string = match serde_json::to_string(&doc) {
            Ok(content) => content,
            Err(e) => {
                let _ = tx.try_send(Err(Error::Database(format!("Serialization failed: {e}"))));
                return Box::pin(ReceiverStream::new(rx));
            }
        };

        tokio::spawn(async move {
            // Use raw SQL query to avoid content() method's lifetime issues
            let query = format!("UPDATE {table}:{id} CONTENT {content_string}");

            match db.query(query).await {
                Ok(mut response) => {
                    // Try to extract the updated document
                    match response.take::<Option<T>>((0_usize, "")) {
                        Ok(Some(updated)) => {
                            let _ = tx.send(Ok(updated)).await;
                        }
                        Ok(None) => {
                            // If no record was updated, return the original document
                            let _ = tx.send(Ok(doc_to_send)).await;
                        }
                        Err(e) => {
                            let _ = tx.send(Err(Error::Database(e.to_string()))).await;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(Error::Database(e.to_string()))).await;
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }

    pub fn delete<'life0, 'life1, 'fut>(
        &'life0 self,
        id: &'life1 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
    {
        let (tx, rx) = mpsc::channel(16);
        let db = Arc::clone(self.db());
        let table = self.table_name().to_string();
        let id = id.to_string();

        tokio::spawn(async move {
            match db.delete::<Option<T>>((table, id)).await {
                Ok(response) => match response {
                    Some(deleted) => {
                        let _ = tx.send(Ok(deleted)).await;
                    }
                    None => {
                        let _ = tx.send(Err(Error::NotFound)).await;
                    }
                },
                Err(e) => {
                    let _ = tx.send(Err(Error::Database(e.to_string()))).await;
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}
