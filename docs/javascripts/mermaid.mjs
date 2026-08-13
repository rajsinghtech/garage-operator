import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11.12.0/dist/mermaid.esm.min.mjs";

mermaid.initialize({
  startOnLoad: false,
  securityLevel: "strict",
});

document$.subscribe(() => {
  mermaid.run({
    querySelector: ".mermaid:not([data-processed])",
  });
});
