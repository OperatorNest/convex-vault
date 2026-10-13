# 0008: Export result validators, not stored-row validators

The client package exports an explicit list of argument validators, result validators and types. It exports no validator of a stored row, so `credentialValidator` stays internal to the component schema. Every public component function's `returns` uses an exported result validator, including `keys.getStatus` with `keyStatusResultValidator`.

Apps declare `returns` for wrapper functions with the same validators the component uses. Schema fields can change without changing the package's exports. Adding a validator to the public surface requires adding it to the export list.
