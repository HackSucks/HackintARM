# Shared LZBITMAP codec

The decoder and original encoder were moved from
`deploymenttheory/go-macos-pkg/pkg/lzbitmap` at commit
`a91762f6c9bfe36b18451e3dca92762f7a5fd59a`. That implementation translates
Ernesto A. Fernandez's MIT-licensed
[libzbitmap](https://github.com/eafer/libzbitmap), copyright 2022 Corellium LLC,
at `574abeae25b25c3319b9b6a9225cc7464e08ae88`. The upstream MIT notice and
original project license remain in this directory.

The encoder now follows native macOS hash matching, descriptor selection and
bounded-output behavior. Independent native captures qualify exact output for
407 samples and 1,413 destination-capacity cases, including dictionary changes,
position wrap and multi-chunk inputs. See
[the writer qualification](../../../docs/compression-writer.md) for sources and
reproduction commands.

The five historical scalar outputs remain unchanged as decoder fixtures, with
their original hashes. Native `aa` compressed/plain fixtures remain independent
format controls. The full 8 MiB incompressible performance workload keeps its
20-second ordinary-build limit and existing race allowance; a separate test
checks fixed history storage across chunks and position wraps. Downstream
projects use this shared package rather than maintaining another codec copy.
