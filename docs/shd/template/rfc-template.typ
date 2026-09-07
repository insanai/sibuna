#let shd-number = "XXXXX"
#let shd-title = "Title Goes Here"
#let shd-state = "prediscussion"
#let shd-created = "YYYY-MM-DD"
#let shd-discussion = "Draft discussion note"
#let shd-labels = ("documentation", "engineering",)
#let shd-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let shd-category = "Engineering Discussion"
#let shd-status = "Internal Draft"
#let shd-last-updated = "None"

#import "../../shared/shd.typ": shd-document

#show: doc => shd-document(
  shd-number,
  shd-title,
  doc,
  authors: shd-authors,
  state: shd-state,
  created: shd-created,
  discussion: shd-discussion,
  labels: shd-labels,
  category: shd-category,
  status: shd-status,
  last-updated: shd-last-updated,
)

= Abstract

State the problem, the proposed direction, and the reason this document exists.

= Introduction

Provide the background and the constraints that make the topic worth discussing now.

= Terminology and Scope

Define the terms used in the document and state what is in scope versus explicitly out of scope.

= Problem Statement

Describe the gap in the current system, workflow, or design.

= Goals and Non-Goals

== Goals

- List the properties the proposal must satisfy.

== Non-Goals

- List adjacent problems that this document does not solve.

= Design Overview

Explain the high-level proposal in a way that lets the reader understand the rest of the document.

= Detailed Design

Break the design into the main mechanisms, data flows, interfaces, or document structures.

= Verification and Testing

State the required test matrix, simulation boundaries, or benchmark gates.

= Security Considerations

Analyze trust boundaries, abuse vectors, and cryptographic constraints.

= Rollout and Operational Plan

Describe deployment topologies, configuration migrations, and observability.

= References
