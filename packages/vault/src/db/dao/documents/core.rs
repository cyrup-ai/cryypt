//! Core SurrealDbDao struct and basic methods

use super::super::{Error, GenericDao, TableType};
use async_stream;
use chrono::{DateTime, Utc};
use futures::Stream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::pin::Pin;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::any::Any;

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
        let db = self.db.clone();
        let table_name = self.table_name().to_string();

        Box::pin(futures::stream::once(async move {
            match db.create(table_name.as_str()).content(doc).await {
                Ok(Some(record)) => Ok(record),
                Ok(None) => Err(Error::Other("Create operation returned None".to_string())),
                Err(e) => Err(Error::Database(e.to_string())),
            }
        }))
    }

    fn find_by_id<'life0, 'life1, 'fut>(
        &'life0 self,
        id: &'life1 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
    {
        let id = id.to_string();
        let db = self.db.clone();
        let table_name = self.table_name().to_string();

        Box::pin(futures::stream::once(async move {
            match db
                .select::<Option<T>>((table_name.as_str(), id.as_str()))
                .await
            {
                Ok(Some(record)) => Ok(record),
                Ok(None) => Err(Error::NotFound),
                Err(e) => Err(Error::Database(e.to_string())),
            }
        }))
    }

    fn find_all<'life0, 'fut>(
        &'life0 self,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
    {
        let db = self.db.clone();
        let table_name = self.table_name().to_string();

        Box::pin(async_stream::stream! {
            match db.select::<Vec<T>>(table_name.as_str()).await {
                Ok(records) => {
                    for record in records {
                        yield Ok(record);
                    }
                }
                Err(e) => yield Err(Error::Database(e.to_string())),
            }
        })
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
        let id = id.to_string();
        let db = self.db.clone();
        let table_name = self.table_name().to_string();

        Box::pin(futures::stream::once(async move {
            match db
                .update::<Option<T>>((table_name.as_str(), id.as_str()))
                .content(doc)
                .await
            {
                Ok(Some(record)) => Ok(record),
                Ok(None) => Err(Error::NotFound),
                Err(e) => Err(Error::Database(e.to_string())),
            }
        }))
    }

    fn delete<'life0, 'life1, 'fut>(
        &'life0 self,
        id: &'life1 str,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
        'life1: 'fut,
    {
        let id = id.to_string();
        let db = self.db.clone();
        let table_name = self.table_name().to_string();

        Box::pin(futures::stream::once(async move {
            match db
                .delete::<Option<T>>((table_name.as_str(), id.as_str()))
                .await
            {
                Ok(Some(record)) => Ok(record),
                Ok(None) => Err(Error::NotFound),
                Err(e) => Err(Error::Database(e.to_string())),
            }
        }))
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
        let from_id = from_id.to_string();
        let relation = relation.to_string();
        let to_id = to_id.to_string();
        let db = self.db.clone();

        Box::pin(futures::stream::once(async move {
            let table_name = self.table_name().to_string();
            match db
                .query(format!(
                    "RELATE {}:{} -> {} -> {}:{}",
                    table_name, from_id, relation, table_name, to_id
                ))
                .await
            {
                Ok(mut response) => match response.take::<Vec<T>>(0) {
                    Ok(mut records) => {
                        if let Some(record) = records.pop() {
                            Ok(record)
                        } else {
                            Err(Error::Database("No relation created".to_string()))
                        }
                    }
                    Err(e) => Err(Error::Database(e.to_string())),
                },
                Err(e) => Err(Error::Database(e.to_string())),
            }
        }))
    }

    fn find_similar<'life0, 'fut>(
        &'life0 self,
        doc: &T,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
    {
        let db = self.db.clone();
        let table_name = self.table_name().to_string();
        let doc = doc.clone(); // Clone to avoid lifetime issues
        let self_clone = self.clone();

        Box::pin(async_stream::stream! {
            // Extract searchable content from the document
            let search_vector = match self_clone.extract_search_vector(&doc).await {
                Ok(vector) => vector,
                Err(e) => {
                    yield Err(Error::Other(format!("Failed to extract search vector: {e}")));
                    return;
                }
            };

            // Query all documents for similarity comparison
            let query = format!("SELECT * FROM {table_name}");
            let mut response = match db.query(query).await {
                Ok(resp) => resp,
                Err(e) => {
                    yield Err(Error::Database(e.to_string()));
                    return;
                }
            };

            let documents: Vec<T> = match response.take(0) {
                Ok(docs) => docs,
                Err(e) => {
                    yield Err(Error::Database(e.to_string()));
                    return;
                }
            };

            // Calculate similarities and sort by relevance
            let mut similarities = Vec::new();

            for candidate in documents {
                match self_clone.extract_search_vector(&candidate).await {
                    Ok(candidate_vector) => {
                        let similarity = cosine_similarity(&search_vector, &candidate_vector);
                        if similarity > 0.1 { // Minimum similarity threshold
                            similarities.push((candidate, similarity));
                        }
                    }
                    Err(_) => continue, // Skip documents that can't be vectorized
                }
            }

            // Sort by similarity (highest first)
            similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            // Yield similar documents
            for (document, _similarity) in similarities.into_iter().take(10) {
                yield Ok(document);
            }
        })
    }

    fn query_time_range<'life0, 'fut>(
        &'life0 self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Pin<Box<dyn Stream<Item = Result<T, Error>> + Send + 'fut>>
    where
        'life0: 'fut,
    {
        let db = self.db.clone();
        let table_name = self.table_name().to_string();

        Box::pin(futures::stream::once(async move {
            let query = format!(
                "SELECT * FROM {} WHERE created_at >= $start AND created_at <= $end",
                table_name
            );

            match db
                .query(query)
                .bind(("start", start))
                .bind(("end", end))
                .await
            {
                Ok(mut response) => match response.take::<Vec<T>>(0) {
                    Ok(mut records) => {
                        if let Some(record) = records.pop() {
                            Ok(record)
                        } else {
                            Err(Error::NotFound)
                        }
                    }
                    Err(e) => Err(Error::Database(e.to_string())),
                },
                Err(e) => Err(Error::Database(e.to_string())),
            }
        }))
    }
}

impl<T> SurrealDbDao<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + Clone + 'static,
{
    /// Extract search vector from document content
    async fn extract_search_vector(&self, doc: &T) -> Result<Vec<f32>, Error> {
        // Convert document to searchable text representation
        let text = serde_json::to_string(doc)
            .map_err(|e| Error::Other(format!("Failed to serialize document: {e}")))?;

        // Create simple TF-IDF vector representation
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut word_freq = std::collections::HashMap::new();

        for word in &words {
            *word_freq.entry(word.to_lowercase()).or_insert(0) += 1;
        }

        // Convert to normalized vector (simple bag-of-words with TF weighting)
        let total_words = words.len() as f32;
        let mut vector = Vec::with_capacity(word_freq.len());

        for (_, freq) in word_freq {
            vector.push(freq as f32 / total_words);
        }

        // Normalize vector
        let magnitude: f32 = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
        if magnitude > 0.0 {
            for value in &mut vector {
                *value /= magnitude;
            }
        }

        Ok(vector)
    }
}

/// Calculate cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let min_len = a.len().min(b.len());
    let dot_product: f32 = a
        .iter()
        .take(min_len)
        .zip(b.iter().take(min_len))
        .map(|(x, y)| x * y)
        .sum();

    let norm_a: f32 = a.iter().take(min_len).map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().take(min_len).map(|x| x * x).sum::<f32>().sqrt();

    if norm_a > 0.0 && norm_b > 0.0 {
        dot_product / (norm_a * norm_b)
    } else {
        0.0
    }
}
