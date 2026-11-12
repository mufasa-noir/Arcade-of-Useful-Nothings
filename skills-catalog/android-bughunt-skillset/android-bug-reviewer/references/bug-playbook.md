# Bug Reviewer Playbook

Concrete things to grep for / read for, per category. This is a checklist, not a tutorial — skip categories that don't apply to the app (e.g. no native code, no custom views).

## Lifecycle bugs
- Context leaks: a `static` field or singleton holding an `Activity`/`View`/`Context` reference, listener registrations (`LocationManager`, `SensorManager`, broadcast receivers) registered in `onCreate`/`onResume` without a matching unregister in `onDestroy`/`onPause`.
- Background work (threads, coroutines, `AsyncTask`, `RxJava` subscriptions) started in a lifecycle method but never cancelled when the component is destroyed — look for missing `onDestroy`/`onCleared` cancellation.
- `onSaveInstanceState`/`onRestoreInstanceState` present but incomplete — fields read elsewhere that aren't saved/restored, which surfaces as "bug only after rotation."
- Fragment `onCreateView` returning a view whose children are referenced after `onDestroyView` (returns null but listeners captured earlier are still live) — common NPE source in older code.

## Null safety
- Kotlin `!!` on a value that isn't locally proven non-null.
- Java fields read without a null check where the class's own constructor/setters allow null.
- Nullability lost at Kotlin/Java boundaries — a Java method annotated `@Nullable` (or not annotated at all) consumed by Kotlin code that treats it as non-null.
- Deserialized/parsed data (JSON, Intent extras, Bundle) used immediately without checking the parse/extraction succeeded.

## Resource leaks
- `Cursor`, `InputStream`/`OutputStream`, `FileDescriptor`, `Camera`/`CameraDevice`, `MediaPlayer` opened without a `try-with-resources` / `use {}` / explicit `close()` in a `finally`.
- Database connections (`SQLiteOpenHelper`) opened per-call instead of reused/closed.

## Concurrency
- Shared mutable field (not `volatile`, not behind a lock) written from a background thread and read from the main thread, or vice versa.
- `HashMap`/`ArrayList` (non-thread-safe collections) mutated from more than one thread.
- Coroutines launched without structured concurrency (no scope cancellation tied to lifecycle) — look for `GlobalScope.launch`.
- Double-checked locking on a singleton without `volatile` on the backing field.

## Logic errors
- Conditionals that look inverted relative to their variable/method name (e.g. `isValid` used as if it meant "is invalid").
- Loop bounds using `<=` where array indexing expects `<`, or vice versa.
- Branches that are provably unreachable given earlier checks (dead code — also worth flagging to the convention reviewer).
- Copy-paste artifacts: two near-identical blocks where one still references the other's variable names.

## State management
- Cached/in-memory data read without checking staleness against a timestamp or version the code itself tracks.
- UI state updated from a background callback that doesn't check whether the UI is still attached/visible (common in `ViewModel`/`LiveData` observers that outlive their view).
- Pagination logic where the "has more" check and the actual fetch offset can drift out of sync.

## Error handling
- Empty `catch` blocks, or catch blocks that only log and continue as if nothing happened in a path where that's unsafe (e.g. swallowing a crypto or auth exception).
- Catching `Exception`/`Throwable` broadly where a narrower catch would reveal the real failure mode.
- Retry loops without a max-attempts guard or backoff, risking infinite loops or battery drain.
