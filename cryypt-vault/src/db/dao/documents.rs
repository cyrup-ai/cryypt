//! Document operations implementation
//!
//! Provides SurrealDB implementation of the GenericDao trait
//! with CRUD operations and streaming support.

use super::{Error, GenericDao, TableType};
use futures::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::pin::Pin;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::any::Any;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

/// SurrealDB implementation of the GenericDao trait
#[derive(Debug, Clone)]
pub struct SurrealDbDao<T> {
    pub db: Arc<Surreal<Any>>,
    pub table: String,
    pub table_type: TableType,
    pub _marker: std::marker::PhantomData<T>,
}

impl<T> SurrealDbDao<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    pub fn new(db: Arc<Surreal<Any>>, table: impl Into<String>, table_type: TableType) -> Self {
        Self {
            db,
            table: table.into(),
            table_type,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn table_name(&self) -> &str {
        &self.table
    }

    pub fn table_type(&self) -> &TableType {
        &self.table_type
    }

    pub fn db(&self) -> &Arc<Surreal<Any>> {
        &self.db
    }
}

impl<T> GenericDao<T> for SurrealDbDao<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    fn table_name(&self) -> &str {
        self.table_name()
    }

    fn table_type(&self) -> &TableType {
        self.table_type()
    }

    fn db(&self) -> &Arc<Surreal<Any>> {
        self.db()
    }

    fn create<'life0, 'fut>(
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
                let _ = tx.send(Err(Error::Database(format!("Serialization failed: {}", e))));
                return Box::pin(ReceiverStream::new(rx));
            }
        };

        tokio::spawn(async move {
            let id = Uuid::new_v4().to_string();

            // Use raw SQL query to avoid content() method's lifetime issues
            let query = format!("CREATE {}:{} CONTENT {}", table, id, content_string);

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

    fn find_by_id<'life0, 'life1, 'fut>(
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

    fn find_all<'life0, 'fut>(
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

    fn update<'life0, 'life1, 'fut>(
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
                let _ = tx.send(Err(Error::Database(format!("Serialization failed: {}", e))));
                return Box::pin(ReceiverStream::new(rx));
            }
        };

        tokio::spawn(async move {
            // Use raw SQL query to avoid content() method's lifetime issues
            let query = format!("UPDATE {}:{} CONTENT {}", table, id, content_string);

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

    fn delete<'life0, 'life1, 'fut>(
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

    fn relate<'life0, 'life1, 'life2, 'fut>(
        &'life0 self,
        from_id: &'life1 str,
        relation: &'life2 str,
        to_id: &'life1 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
        'life2: 'fut,
    {
        let (tx, rx) = mpsc::channel(16);
        let db = Arc::clone(self.db());
        let table = self.table_name().to_string();
        let from_id = from_id.to_string();
        let relation = relation.to_string();
        let to_id = to_id.to_string();

        tokio::spawn(async move {
            let query = format!(
                "RELATE {}:{}->{}->{}:{}",
                table, from_id, relation, table, to_id
            );

            match db.query(query).await {
                Ok(mut response) => {
                    // Use a tuple with 0_usize to get the first result set, and empty string for all fields
                    let items: Vec<T> = match response.take::<Vec<T>>((0_usize, "")) {
                        Ok(items) => items,
                        Err(e) => {
                            let _ = tx.send(Err(Error::Database(e.to_string()))).await;
                            return;
                        }
                    };

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

    fn find_similar<'life0, 'fut>(
        &'life0 self,
        _doc: &T,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
    {
        let (tx, rx) = mpsc::channel(16);
        let _ = tx.send(Err(Error::Database(
            "Similarity search not implemented".into(),
        )));
        Box::pin(ReceiverStream::new(rx))
    }

    fn query_time_range<'life0, 'fut>(
        &'life0 self,
        start: OffsetDateTime,
        end: OffsetDateTime,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
    {
        let (tx, rx) = mpsc::channel(16);
        let db = Arc::clone(self.db());
        let table = self.table_name().to_string();

        tokio::spawn(async move {
            let query = format!(
                "SELECT * FROM {} WHERE created_at >= $start AND created_at <= $end",
                table
            );

            match db
                .query(query)
                .bind(("start", start))
                .bind(("end", end))
                .await
            {
                Ok(mut response) => match response.take::<Vec<T>>((0_usize, "")) {
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
                },
                Err(e) => {
                    let _ = tx.send(Err(Error::Database(e.to_string()))).await;
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }
}