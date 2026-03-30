# Graph Service

This folder contains graph-based risk logic focused on topology patterns.

## Main component

- `graph_agent.py`
  - Builds transaction graph windows.
  - Detects suspicious structures such as fan-in/fan-out/cycle/scatter behaviors.
  - Produces risk delta updates for downstream fusion.

## Purpose

Augment model-based scoring with network-structure intelligence.
