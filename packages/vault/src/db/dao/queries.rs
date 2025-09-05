//! Query building functionality for DAO operations
//!
//! Provides helper functions for building complex queries
//! including relations, joins, and custom query patterns.

use super::{Error, GenericDao};
use futures::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::pin::Pin;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::any::Any;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Build and execute a relation query
pub fn find_by_relation<T>(
    db: Arc<Surreal<Any>>,
    table: String,
    relation: String,
    target_id: String,
) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send>>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel(16);

    tokio::spawn(async move {
        let query = format!(
            "SELECT * FROM {} WHERE id IN (SELECT in FROM {} WHERE out = $target AND type = $relation)",
            table, relation
        );

        match db
            .query(query)
            .bind(("target", target_id))
            .bind(("relation", relation))
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

/// Build and execute a join query
pub fn join_tables<T>(
    db: Arc<Surreal<Any>>,
    table: String,
    other_table: String,
    join_field: String,
) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send>>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel(16);

    tokio::spawn(async move {
        let query = format!(
            "SELECT * FROM {} INNER JOIN {} ON {}.{} = {}.id",
            table, other_table, table, join_field, other_table
        );

        match db.query(query).await {
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

/// Default implementation helper for find_by_relation trait method
pub fn default_find_by_relation<'a, D, T>(
    dao: &'a D,
    relation: &str,
    target_id: &str,
) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'a>>
where
    D: GenericDao<T>,
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    find_by_relation(
        Arc::clone(dao.db()),
        dao.table_name().to_string(),
        relation.to_string(),
        target_id.to_string(),
    )
}

/// Default implementation helper for join trait method
pub fn default_join<'a, D, T>(
    dao: &'a D,
    other_table: &str,
    join_field: &str,
) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'a>>
where
    D: GenericDao<T>,
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    join_tables(
        Arc::clone(dao.db()),
        dao.table_name().to_string(),
        other_table.to_string(),
        join_field.to_string(),
    )
}
