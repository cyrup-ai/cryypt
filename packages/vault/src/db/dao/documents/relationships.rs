//! Relationship operations for SurrealDbDao

use super::super::Error;
use super::core::SurrealDbDao;
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
    pub fn relate<'life0, 'life1, 'life2, 'fut>(
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
}
