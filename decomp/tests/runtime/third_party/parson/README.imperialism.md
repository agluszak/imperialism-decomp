Parson 1.5.3 is vendored from commit
`ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3` of
https://github.com/kgabis/parson.

It is compiled only when `IMPERIALISM_RUNTIME_TESTS` is enabled. The native
runtime self-test exercises nested object/array construction and serialization
with the MSVC 5.0 toolchain.
