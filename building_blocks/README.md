(nb: I'm writing this as I go along, I don't yet grok SLH-DSA as a whole so aspects may be wrong/misleading)

SLH-DSA itself is a composition of existing building-blocks. In dependency order: (where "->" means "is used as part of")

```
Hashing -> WOTS+ -> XMSS -> FORS -> hypertree (?)
```

(not really certain about the latter two yet, and a more correct dependency graph may not be a straight line)

Spec-wise, SLH-DSA is self-contained but a bit terse. For learning purposes, I think I'm better off studying the individual components from other sources.

Here's an accessible explanation of WOTS (no "+"): https://www.geeksforgeeks.org/winternitz-one-time-signature-scheme/

RFC-8391 specifies WOTS+ and how it's used in XMSS: https://datatracker.ietf.org/doc/html/rfc8391

The difference between vanilla WOTS and WOTS+ is that [TODO...]
