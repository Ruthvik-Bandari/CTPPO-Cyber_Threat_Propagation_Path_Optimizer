"""Graph Neural Network for attack-graph exploitability prediction.

A Kipf & Welling GCN (hand-rolled in pure torch, no torch_geometric dependency) that
predicts a per-node exploitability / compromise-likelihood score over an attack graph.
See docs/RESEARCH/00_VISION.md (Phase 3) and 02_COST_MODEL_SPEC.md (the GNN refines the
rule-based cost prior; it must beat that baseline in evaluation).
"""
