# Verifying the load_key_certs_crls() memory leak and fix (issue #30364)

## 1. Code-level reasoning

### Why there is a leak (without the patch)

- **CERT path:** `OSSL_STORE_INFO_get1_CERT(info)` returns a **newly allocated** `X509*` (caller owns it). That pointer is passed straight into `X509_add_cert(*pcerts, cert, X509_ADD_FLAG_DEFAULT)`. If `X509_add_cert()` fails (e.g. `sk_X509_insert()` fails due to realloc), the cert is never inserted and the original code never frees it → **leak**.
- **CRL path:** Same pattern: `OSSL_STORE_INFO_get1_CRL(info)` returns a new `X509_CRL*`; it is passed to `sk_X509_CRL_push(*pcrls, crl)`. If `sk_X509_CRL_push()` fails (e.g. realloc), the CRL is never pushed and the original code never frees it → **leak**.

So the leak only happens on the **failure path** of `X509_add_cert()` / `sk_X509_CRL_push()` (typically allocation failure inside the stack).

### Why the patch fixes it

The patch stores the object in a temporary variable, calls the add/push function, and **on failure** calls `X509_free(cert)` or `X509_CRL_free(crl)`. So the object is freed exactly when it is not added to the stack → no leak.

---

## 2. How to prove the leak exists (without patch) and is fixed (with patch)

You need to (a) hit the code path that adds a cert/CRL to a stack, and (b) make that add/push **fail** (e.g. by forcing an allocation failure). Then run under a leak detector.

### Build for leak detection and allocation failure

Allocation failure is only honored when OpenSSL is built with the crypto-mdebug / allocfail-tests support:

```bash
# From repo root
./Configure darwin64-arm64-cc no-shared enable-crypto-mdebug enable-allocfail-tests --prefix=/tmp/openssl-leaktest
make -j4
```

For leak reporting you can use either:

- **Valgrind** (no need to rebuild; use the build above):
  ```bash
  valgrind --leak-check=full --error-exitcode=1 -q ./apps/openssl ...
  ```
- **ASan + LeakSanitizer** (optional; often enabled with enable-asan):
  ```bash
  ./Configure darwin64-arm64-cc no-shared enable-asan enable-crypto-mdebug enable-allocfail-tests --prefix=/tmp/openssl-leaktest
  make -j4
  # Then run the same openssl command; LSan will print leak summary on exit.
  ```

### Triggering the code path and the failure

- The **cert** leak path is used when loading **multiple certs** into a stack, e.g. via `load_certs_multifile()` → `load_cert_certs(..., NULL, &certs, ...)` → `load_key_certs_crls(..., pcerts= &certs)`. That is used by the **ts** and **cmp** apps (e.g. `openssl ts -query ...` with extra certs, or `openssl cmp` with cert loading).
- The **CRL** leak path is used when loading CRLs into a stack (any app that passes `pcrls` into `load_key_certs_crls`).

Example that exercises the **cert** path: use the `ts` app with a store or file that contains a cert, so that one cert is loaded and then added to the stack. The allocation that fails must be the one inside `sk_X509_insert()` (or the realloc inside the stack). To force that allocation to fail, use `OPENSSL_MALLOC_FAILURES` (see `doc/man3/OPENSSL_malloc.pod`).

Format of `OPENSSL_MALLOC_FAILURES`:  
`skip@0;idx@0;1@100;0@0` means: skip first `skip` allocations, then let `idx` allocations succeed, then force the **next** allocation to fail with 100% probability.

You need to choose `skip` and `idx` so that the failing allocation is the one inside the cert (or CRL) add path. One way to find them:

1. Run the same command with allocation logging to see counts:
   ```bash
   OPENSSL_MALLOC_FD=3 OPENSSL_MALLOC_FAILURES='0@0.001' ./apps/openssl ts -query -data /dev/null -cert test/certs/servercert.pem 3>/tmp/alloc.log
   ```
   Then inspect `/tmp/alloc.log` to see allocation counts when the ts command runs. Pick a count that is clearly after store/cert loading starts and before the process exits.

2. Then run under Valgrind with that allocation forced to fail (replace `SKIP` and `IDX` with the numbers you found):
   ```bash
   OPENSSL_MALLOC_FAILURES='SKIP@0;IDX@0;1@100;0@0' valgrind --leak-check=full --error-exitcode=1 -q ./apps/openssl ts -query -data /dev/null -cert test/certs/servercert.pem
   ```

**Without the patch:** Valgrind should report a "definitely lost" block (the `X509` or `X509_CRL` that was never freed).  
**With the patch:** The same run should not show that block as "definitely lost", because the code now frees it on the failure path.

### Minimal “sanity” check without finding exact allocation index

- Build with **enable-asan** (and optionally enable-allocfail-tests). Run any command that loads certs/CRLs into a stack and that can hit an allocation failure somewhere in that path (e.g. use `OPENSSL_MALLOC_FAILURES='5000@0;1@100;0@0'` to make one allocation fail after 5000 successes). Compare:
  - **Without patch:** If the failure happens to land in `sk_X509_insert` or `sk_X509_CRL_push`, LSan may report a leak.
  - **With patch:** That leak should disappear.

Because the exact allocation index is environment-dependent, the most reliable approach is to use a **dedicated test** (see below) that counts allocations for a minimal workload that only does the store load + add, then forces the Nth allocation to fail and checks for leaks.

---

## 3. Valgrind reproducer (Linux in Docker)

On macOS Valgrind is not fully supported (e.g. arm64-darwin). To get Valgrind evidence on a Linux build, use the script that runs OpenSSL in a Debian container:

```bash
# From repo root (unpatched / leaky code)
./util/valgrind-leak-repro.sh [allocation_index] "$(pwd)"
```

- **allocation_index** (default 3500): the Nth allocation that will be forced to fail. When that allocation is inside `sk_X509_insert()` or `sk_X509_CRL_push()` during cert/CRL loading, Valgrind will report a "definitely lost" block (the leaked X509 or X509_CRL).
- Requires Docker. The script configures and builds OpenSSL for Linux (no-shared, no-asm, enable-crypto-mdebug, enable-allocfail-tests), then runs `openssl ts -query -cert test/certs/servercert.pem` under Valgrind with `OPENSSL_MALLOC_FAILURES="N@0;1@100;0@0"`.

**Example run (no leak at this index):**

```
==14895== HEAP SUMMARY:
==14895==     in use at exit: 0 bytes in 0 blocks
==14895==   total heap usage: 2,472 allocs, 2,472 frees, 124,810 bytes allocated
==14895== All heap blocks were freed -- no leaks are possible
```

So at index 3500 the failing allocation did not land in the cert-add path. To observe the leak, try other indices (e.g. 2500–4500) or use a probabilistic setting (e.g. `OPENSSL_MALLOC_FAILURES="3000@0;0@20"` so that after 3000 allocations each subsequent one has 20% chance to fail; repeat runs until Valgrind reports "definitely lost"). With the **patch** applied, the same scenario should never report a leak for that code path.

---

## 4. Regression test (implemented)

A dedicated memfail-style test ensures the leak does not return:

- **Program:** `test/load_key_certs_crls_memfail.c` — in **count** mode runs `load_key_certs_crls("file:<cert>", ..., &certs, ...)` and reports skip/count; in **run** mode runs the same with `OPENSSL_MALLOC_FAILURES` set by the recipe.
- **Recipe:** `test/recipes/90-test_memfail.t` runs `load_key_certs_crls_memfail` in count mode, then runs one iteration per allocation index (like `handshake-memfail` and `x509-memfail`). When the failing allocation lands in the cert-add or CRL-push path, the fix ensures no leak; under Valgrind (`make OSSL_USE_VALGRIND=yes test TESTS=test_memfail`) a regression would be reported as a leak.

**Build and run:**

- Configure with **enable-crypto-mdebug** and **enable-allocfail-tests** (allocfail-tests is only available when crypto-mdebug is enabled):
  ```bash
  ./Configure <target> enable-crypto-mdebug enable-allocfail-tests
  make -j4
  ```
- Run the memfail tests (uses the wrapper so shared libs are found):
  ```bash
  make test TESTS=test_memfail
  ```
  This can take a long time (thousands of allocation-failure iterations across handshake, x509, and load_key_certs_crls_memfail).
- Quick sanity check for the new test only (from repo root):
  ```bash
  util/shlib_wrap.sh test/load_key_certs_crls_memfail count test/certs/servercert.pem
  # Expect: ok 1, ok 2 and a line "skip: N count M"
  ```

---

## 5. Summary

| Question | Answer |
|----------|--------|
| Is there a leak on master? | Yes: on the path where `pcerts` or `pcrls` is set, when `X509_add_cert()` or `sk_X509_CRL_push()` fails, the newly obtained cert/CRL is never freed. |
| Does the patch fix it? | Yes: the patch frees the cert/CRL when the add/push fails. |
| How to prove it? | Build with allocfail-tests (and optionally ASan), run a command that loads certs/CRLs into a stack, use `OPENSSL_MALLOC_FAILURES` to make the relevant allocation fail, run under Valgrind or LSan. Without patch → leak reported; with patch → no leak. |
| Most robust proof? | The dedicated memfail-style test `load_key_certs_crls_memfail` (recipe `test_memfail`) forces the failure in the add path; under Valgrind it would report a leak if the fix were reverted. |
