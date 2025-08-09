# Cryypt Architecture

## Fundamental Truths

### 1. All Methods Come in Two Flavors

Every operation in cryypt has both a Future and Stream variant:

- **Future variant**: `encrypt()`, `decrypt()`, `compute()`, `compress()`, `sign()`, `verify()`
- **Stream variant**: `encrypt_stream()`, `decrypt_stream()`, `compute_stream()`, `compress_stream()`

### 2. Two Entry Points - Both Equal

Every example can be written two ways:

```rust
// Using Cryypt:: master builder
Cryypt::cipher()
    .aes()
    .with_key(key)
    .encrypt(data)

// Using direct builder
Cipher::aes()
    .with_key(key)
    .encrypt(data)
```

Both are first-class. Neither is preferred.

### 3. Future Operations

Future operations return a single result and use `on_result`:

```rust
// Using Cryypt:: master builder
let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result(|result| {
        Ok => Ok(result),
        Err(e) => Err(e)
    })
    .encrypt(data)
    .await?;

// Using direct builder (same result)
let encrypted = Cipher::aes()
    .with_key(key)
    .on_result(|result| {
        Ok => Ok(result),
        Err(e) => Err(e)
    })
    .encrypt(data)
    .await?;
```

- Returns `Future<Output = Result<T>>`
- `on_result` handles `Result<T>` and returns `Result<T>`
- Use `.await?` to get the final value

### 4. Stream Operations

Stream operations return multiple chunks and use `on_chunk`:

```rust
// Using Cryypt:: master builder
let mut encrypted_stream = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_chunk(|chunk| {
        Ok => chunk.into(),
        Err(e) => {
            log::error!("Error: {}", e);
            return;
        }
    })
    .encrypt_stream(input_stream);

// Using direct builder (same result)
let mut encrypted_stream = Cipher::aes()
    .with_key(key)
    .on_chunk(|chunk| {
        Ok => chunk.into(),
        Err(e) => {
            log::error!("Error: {}", e);
            return;
        }
    })
    .encrypt_stream(input_stream);

// Process chunks
while let Some(chunk) = encrypted_stream.next().await {
    // chunk is already unwrapped by on_chunk
    output_file.write_all(&chunk).await?;
}
```

- Returns `Stream<Item = T>` (not `Stream<Item = Result<T>>`)
- `on_chunk` unwraps each chunk - you get `T` not `Result<T>`
- Bad chunks are skipped with `return`

### 5. Actions Take Arguments

The action method (final verb) always takes the data:

- `encrypt(data)` not `with_data(data).encrypt()`
- `compute(data)` not `with_data(data).compute()`
- `sign(claims)` not `with_claims(claims).sign()`

### 6. Error Handling Before Action

Error handling is configured BEFORE the action method:

- `on_result(...)` comes before `.encrypt(data).await?`
- `on_chunk(...)` comes before `.encrypt_stream(data)`

### 7. No Exposed Macros

Macros are implementation details:

- User writes: `vault.put_all({ "key" => "value" })`
- Implementation uses: `hash_map!` internally
- User never sees macro syntax

### 8. Keys Are First-Class

Keys have methods:

```rust
// Key as starting point
key.aes().encrypt(data)

// Equivalent to
Cipher::aes().with_key(key).encrypt(data)
```

### 9. Progressive Type Safety

Each builder method returns a new type:

1. Algorithm selection → algorithm-specific builder
2. Configuration → configured builder  
3. Error handling → executable builder
4. Action method → Future or Stream

### 10. Automatic Type Inference

- File extensions: `.encrypt_file("doc.pdf")` → saves as `doc.pdf.zst`
- Map values: `"localhost"` → `VaultValue::String`, `5432` → `VaultValue::Number`
- No manual wrapping
