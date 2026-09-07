#let sid-number = "XXXXX"
#let sid-title = "Title Goes Here"
#let sid-state = "prediscussion"
#let sid-created = "YYYY-MM-DD"
#let sid-discussion = "Draft discussion note"
#let sid-labels = ("documentation", "engineering",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Engineering Discussion"
#let sid-status = "Internal Draft"
#let sid-last-updated = "None"

#import "../../shared/sid.typ": sid-document

#show: doc => sid-document(
  sid-number,
  sid-title,
  doc,
  authors: sid-authors,
  state: sid-state,
  created: sid-created,
  discussion: sid-discussion,
  labels: sid-labels,
  category: sid-category,
  status: sid-status,
  last-updated: sid-last-updated,
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
