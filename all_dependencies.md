# All Unique Dependencies in cryypt Workspace

## Analysis Summary

Based on analysis of all Cargo.toml files in the workspace, here are all unique dependencies sorted alphabetically with their current versions:

### Regular Dependencies

1. **aes-gcm** - 0.10.3
2. **arc-swap** - 1.7.1
3. **argon2** - 0.5.3
4. **atty** - 0.2.14
5. **aws-config** - 1.8.0
6. **aws-sdk-secretsmanager** - 1.77.0
7. **base64** - 0.22.1
8. **base64-url** - 3.0.0
9. **base64ct** - 1 (in workspace-hack)
10. **bincode** - 2.0.1
11. **blake2** - 0.10.6
12. **blake3** - 1.8.2 (only in workspace deps)
13. **bytes** - 1 (in workspace-hack)
14. **bzip2** - 0.5.2, 0.6.0 (inconsistent versions)
15. **chacha20poly1305** - 0.10.1
16. **chrono** - 0.4.41
17. **clap** - 4.5.40
18. **clap_builder** - 4 (in workspace-hack)
19. **clap_complete** - 4.5.54
20. **crossbeam-channel** - 0.5.13
21. **crossterm** - 0.29.0
22. **crypto-common** - 0.1 (in workspace-hack)
23. **dashmap** - 6.1.0
24. **deranged** - 0.4 (in workspace-hack)
25. **dialoguer** - 0.11.0
26. **digest** - 0.10 (in workspace-hack)
27. **dirs** - 6.0.0
28. **either** - 1 (in workspace-hack)
29. **flate2** - 1.1.1, 1.1.2 (inconsistent versions)
30. **futures** - 0.3.31
31. **futures-core** - 0.3.31
32. **futures-io** - 0.3 (in workspace-hack)
33. **futures-sink** - 0.3 (in workspace-hack)
34. **generic-array** - 0.14 (in workspace-hack)
35. **getrandom** - 0.2, 0.3.3 (inconsistent versions)
36. **hashbrown** - 0.14.5, 0.15.4 (inconsistent versions)
37. **hex** - 0.4.3
38. **hkdf** - 0.12.4
39. **hmac** - 0.12.1
40. **indexmap** - 2 (in workspace-hack)
41. **itertools** - 0.11 (in workspace-hack)
42. **keyring** - 3.6.2
43. **lalrpop-util** - 0.20 (in workspace-hack)
44. **log** - 0.4.27
45. **memchr** - 2 (in workspace-hack)
46. **num-traits** - 0.2 (in workspace-hack)
47. **once_cell** - 1.21.3
48. **p256** - 0.13.2
49. **password-hash** - 0.5 (in workspace-hack)
50. **pbkdf2** - 0.12 (in workspace-hack)
51. **phf_shared** - 0.11 (in workspace-hack)
52. **pin-project** - 1.1.10
53. **pqcrypto** - 0.18.1
54. **pqcrypto-falcon** - 0.4.0
55. **pqcrypto-mldsa** - 0.1.1
56. **pqcrypto-mlkem** - 0.1.0
57. **pqcrypto-sphincsplus** - 0.7.1
58. **pqcrypto-traits** - 0.3.5
59. **proc-macro2** - 1 (in workspace-hack build-deps)
60. **quiche** - 0.24.2, 0.24.4 (inconsistent versions)
61. **quote** - 1 (in workspace-hack build-deps)
62. **rand** - 0.8, 0.9.1 (inconsistent versions)
63. **rand_core** - 0.6, 0.9.3 (inconsistent versions)
64. **ratatui** - 0.29.0
65. **regex** - 1.11.1
66. **regex-automata** - 0.4 (in workspace-hack)
67. **secrecy** - 0.10.3
68. **serde** - 1.0.219
69. **serde_json** - 1.0.140
70. **sha2** - 0.10.9
71. **sha3** - 0.10.8
72. **shellexpand** - 3.1.1
73. **smallvec** - 1 (in workspace-hack)
74. **string_cache** - 0.8 (in workspace-hack)
75. **subtle** - 2.6.1
76. **surrealdb** - 2.3.6
77. **surrealdb-migrations** - 2.3.0
78. **syn** - 2 (in workspace-hack build-deps)
79. **thiserror** - 2.0.12
80. **time** - 0.3.41
81. **tokio** - 1.45.1
82. **tokio-stream** - 0.1.17
83. **tracing** - 0.1.41
84. **tracing-core** - 0.1 (in workspace-hack)
85. **twox-hash** - 2.1.0, 2.1.1 (inconsistent versions)
86. **unicode-xid** - 0.2 (in workspace-hack)
87. **uuid** - 1.17.0
88. **zeroize** - 1.8.1
89. **zip** - 4.0.0, 4.2.0 (inconsistent versions)
90. **zstd** - 0.13.3

### Dev Dependencies (additional to above)

1. **criterion** - 0.6.0
2. **hex-literal** - 1.0.0
3. **proptest** - 1.6.0, 1.7.0 (inconsistent versions)

## Inconsistent Versions Found

The following dependencies have multiple versions across different crates:

1. **bzip2**: 0.5.2 vs 0.6.0
2. **flate2**: 1.1.1 vs 1.1.2
3. **getrandom**: 0.2 vs 0.3.3
4. **hashbrown**: 0.14.5 vs 0.15.4
5. **proptest**: 1.6.0 vs 1.7.0
6. **quiche**: 0.24.2 vs 0.24.4
7. **rand**: 0.8 vs 0.9.1
8. **rand_core**: 0.6 vs 0.9.3
9. **twox-hash**: 2.1.0 vs 2.1.1
10. **zip**: 4.0.0 vs 4.2.0

## Workspace vs Individual Crate Dependencies

- Most crates have their own copy of dependencies rather than using workspace inheritance
- The workspace defines many dependencies that could be inherited
- Only `cryypt` and `vault` crates use workspace inheritance for dependencies

## Notes

1. The `vault` crate has edition = "2024" which seems incorrect (should be "2021")
2. Many crates duplicate the same dependencies instead of using workspace inheritance
3. The workspace-hack crate is managed by hakari for dependency optimization
4. Some dependencies in individual crates have older versions than those defined in the workspace