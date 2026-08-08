# C++ recovery notes

- Model a real class method as a method; model a verified dispatch as a virtual method in the owning
  class. Do not use function-pointer casts or raw vtable indexing as permanent source.
- Construction order follows declaration order. Use real member objects and normal inheritance instead
  of raw storage, manual vptr writes, placement-base construction, or compiler-helper facades.
- Let VC5 emit EH cleanup and scalar deleting destructors from ordinary C++ ownership. Do not hand-port
  compiler helpers.
- Use actual MFC types at MFC boundaries. If a cast is required to reach an API, the receiver or field
  type is likely still wrong.
- Treat a repeated `this + offset` as evidence for a typed field once attribution is established; leave
  genuinely unresolved storage opaque rather than naming it a dual-use compatibility field.
