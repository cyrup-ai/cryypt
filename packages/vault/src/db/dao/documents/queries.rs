//! Query operations for SurrealDbDao

use super::super::Error;
use super::core::SurrealDbDao;
use chrono::{DateTime, Utc};
use futures::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

impl<T> SurrealDbDao<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    pub fn find_similar<'life0, 'fut>(
        &'life0 self,
        doc: &T,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
    {
        // Delegate to the trait implementation in GenericDao
        use crate::db::dao::GenericDao;
        GenericDao::find_similar(self, doc)
    }

    pub fn query_time_range<'life0, 'fut>(
        &'life0 self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
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
