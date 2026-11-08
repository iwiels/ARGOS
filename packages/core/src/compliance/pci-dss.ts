/**
 * PCI DSS reference identifiers used to associate security findings with
 * potentially related controls. Argos does not reproduce the standard text
 * or provide a PCI DSS compliance assessment.
 */

import { FRAMEWORKS, type ControlCoverage, type ControlLevel, type OwnCatalogFramework } from "./types"
import { SEMANTIC } from "./derive"

export const PCI_DSS_VERSION = "v4.0.1"

export const PCI_DSS_SOURCE =
  "PCI DSS v4.0.1 — Requirements and Testing Procedures (PCI Security Standards Council, June 2024)"

export const PCI_DSS_SOURCE_URL = "https://www.pcisecuritystandards.org/document_library/"

/** Reference identifiers for the top-level PCI DSS groups. */
export const PCI_DSS_REQUIREMENTS: readonly (readonly [id: string, title: string])[] = [
  ["1", "PCI DSS reference 1"],
  ["2", "PCI DSS reference 2"],
  ["3", "PCI DSS reference 3"],
  ["4", "PCI DSS reference 4"],
  ["5", "PCI DSS reference 5"],
  ["6", "PCI DSS reference 6"],
  ["7", "PCI DSS reference 7"],
  ["8", "PCI DSS reference 8"],
  ["9", "PCI DSS reference 9"],
  ["10", "PCI DSS reference 10"],
  ["11", "PCI DSS reference 11"],
  ["12", "PCI DSS reference 12"],
]

/**
 * PCI DSS reference nodes: `[id, parent reference id, neutral title, neutral description]`.
 */
export const PCI_DSS_CONTROLS: readonly (readonly [id: string, parentId: string, title: string, description: string])[] = [
  ["1.1", "1", "PCI DSS reference 1.1", "Consult the official PCI DSS documentation for reference 1.1."],
  ["1.1.1", "1.1", "PCI DSS reference 1.1.1", "Consult the official PCI DSS documentation for reference 1.1.1."],
  ["1.1.2", "1.1", "PCI DSS reference 1.1.2", "Consult the official PCI DSS documentation for reference 1.1.2."],
  ["1.2", "1", "PCI DSS reference 1.2", "Consult the official PCI DSS documentation for reference 1.2."],
  ["1.2.1", "1.2", "PCI DSS reference 1.2.1", "Consult the official PCI DSS documentation for reference 1.2.1."],
  ["1.2.2", "1.2", "PCI DSS reference 1.2.2", "Consult the official PCI DSS documentation for reference 1.2.2."],
  ["1.2.3", "1.2", "PCI DSS reference 1.2.3", "Consult the official PCI DSS documentation for reference 1.2.3."],
  ["1.2.4", "1.2", "PCI DSS reference 1.2.4", "Consult the official PCI DSS documentation for reference 1.2.4."],
  ["1.2.5", "1.2", "PCI DSS reference 1.2.5", "Consult the official PCI DSS documentation for reference 1.2.5."],
  ["1.2.6", "1.2", "PCI DSS reference 1.2.6", "Consult the official PCI DSS documentation for reference 1.2.6."],
  ["1.2.7", "1.2", "PCI DSS reference 1.2.7", "Consult the official PCI DSS documentation for reference 1.2.7."],
  ["1.2.8", "1.2", "PCI DSS reference 1.2.8", "Consult the official PCI DSS documentation for reference 1.2.8."],
  ["1.3", "1", "PCI DSS reference 1.3", "Consult the official PCI DSS documentation for reference 1.3."],
  ["1.3.1", "1.3", "PCI DSS reference 1.3.1", "Consult the official PCI DSS documentation for reference 1.3.1."],
  ["1.3.2", "1.3", "PCI DSS reference 1.3.2", "Consult the official PCI DSS documentation for reference 1.3.2."],
  ["1.3.3", "1.3", "PCI DSS reference 1.3.3", "Consult the official PCI DSS documentation for reference 1.3.3."],
  ["1.4", "1", "PCI DSS reference 1.4", "Consult the official PCI DSS documentation for reference 1.4."],
  ["1.4.1", "1.4", "PCI DSS reference 1.4.1", "Consult the official PCI DSS documentation for reference 1.4.1."],
  ["1.4.2", "1.4", "PCI DSS reference 1.4.2", "Consult the official PCI DSS documentation for reference 1.4.2."],
  ["1.4.3", "1.4", "PCI DSS reference 1.4.3", "Consult the official PCI DSS documentation for reference 1.4.3."],
  ["1.4.4", "1.4", "PCI DSS reference 1.4.4", "Consult the official PCI DSS documentation for reference 1.4.4."],
  ["1.4.5", "1.4", "PCI DSS reference 1.4.5", "Consult the official PCI DSS documentation for reference 1.4.5."],
  ["1.5", "1", "PCI DSS reference 1.5", "Consult the official PCI DSS documentation for reference 1.5."],
  ["2.1", "2", "PCI DSS reference 2.1", "Consult the official PCI DSS documentation for reference 2.1."],
  ["2.1.1", "2.1", "PCI DSS reference 2.1.1", "Consult the official PCI DSS documentation for reference 2.1.1."],
  ["2.1.2", "2.1", "PCI DSS reference 2.1.2", "Consult the official PCI DSS documentation for reference 2.1.2."],
  ["2.2", "2", "PCI DSS reference 2.2", "Consult the official PCI DSS documentation for reference 2.2."],
  ["2.2.1", "2.2", "PCI DSS reference 2.2.1", "Consult the official PCI DSS documentation for reference 2.2.1."],
  ["2.2.2", "2.2", "PCI DSS reference 2.2.2", "Consult the official PCI DSS documentation for reference 2.2.2."],
  ["2.2.3", "2.2", "PCI DSS reference 2.2.3", "Consult the official PCI DSS documentation for reference 2.2.3."],
  ["2.2.4", "2.2", "PCI DSS reference 2.2.4", "Consult the official PCI DSS documentation for reference 2.2.4."],
  ["2.2.5", "2.2", "PCI DSS reference 2.2.5", "Consult the official PCI DSS documentation for reference 2.2.5."],
  ["2.2.6", "2.2", "PCI DSS reference 2.2.6", "Consult the official PCI DSS documentation for reference 2.2.6."],
  ["2.2.7", "2.2", "PCI DSS reference 2.2.7", "Consult the official PCI DSS documentation for reference 2.2.7."],
  ["2.3", "2", "PCI DSS reference 2.3", "Consult the official PCI DSS documentation for reference 2.3."],
  ["2.3.1", "2.3", "PCI DSS reference 2.3.1", "Consult the official PCI DSS documentation for reference 2.3.1."],
  ["2.3.2", "2.3", "PCI DSS reference 2.3.2", "Consult the official PCI DSS documentation for reference 2.3.2."],
  ["3.1", "3", "PCI DSS reference 3.1", "Consult the official PCI DSS documentation for reference 3.1."],
  ["3.1.1", "3.1", "PCI DSS reference 3.1.1", "Consult the official PCI DSS documentation for reference 3.1.1."],
  ["3.1.2", "3.1", "PCI DSS reference 3.1.2", "Consult the official PCI DSS documentation for reference 3.1.2."],
  ["3.2", "3", "PCI DSS reference 3.2", "Consult the official PCI DSS documentation for reference 3.2."],
  ["3.2.1", "3.2", "PCI DSS reference 3.2.1", "Consult the official PCI DSS documentation for reference 3.2.1."],
  ["3.3", "3", "PCI DSS reference 3.3", "Consult the official PCI DSS documentation for reference 3.3."],
  ["3.3.1", "3.3", "PCI DSS reference 3.3.1", "Consult the official PCI DSS documentation for reference 3.3.1."],
  ["3.3.2", "3.3", "PCI DSS reference 3.3.2", "Consult the official PCI DSS documentation for reference 3.3.2."],
  ["3.3.3", "3.3", "PCI DSS reference 3.3.3", "Consult the official PCI DSS documentation for reference 3.3.3."],
  ["3.4", "3", "PCI DSS reference 3.4", "Consult the official PCI DSS documentation for reference 3.4."],
  ["3.4.1", "3.4", "PCI DSS reference 3.4.1", "Consult the official PCI DSS documentation for reference 3.4.1."],
  ["3.4.2", "3.4", "PCI DSS reference 3.4.2", "Consult the official PCI DSS documentation for reference 3.4.2."],
  ["3.5", "3", "PCI DSS reference 3.5", "Consult the official PCI DSS documentation for reference 3.5."],
  ["3.5.1", "3.5", "PCI DSS reference 3.5.1", "Consult the official PCI DSS documentation for reference 3.5.1."],
  ["3.6", "3", "PCI DSS reference 3.6", "Consult the official PCI DSS documentation for reference 3.6."],
  ["3.6.1", "3.6", "PCI DSS reference 3.6.1", "Consult the official PCI DSS documentation for reference 3.6.1."],
  ["3.7", "3", "PCI DSS reference 3.7", "Consult the official PCI DSS documentation for reference 3.7."],
  ["3.7.1", "3.7", "PCI DSS reference 3.7.1", "Consult the official PCI DSS documentation for reference 3.7.1."],
  ["3.7.2", "3.7", "PCI DSS reference 3.7.2", "Consult the official PCI DSS documentation for reference 3.7.2."],
  ["3.7.3", "3.7", "PCI DSS reference 3.7.3", "Consult the official PCI DSS documentation for reference 3.7.3."],
  ["3.7.4", "3.7", "PCI DSS reference 3.7.4", "Consult the official PCI DSS documentation for reference 3.7.4."],
  ["3.7.5", "3.7", "PCI DSS reference 3.7.5", "Consult the official PCI DSS documentation for reference 3.7.5."],
  ["3.7.6", "3.7", "PCI DSS reference 3.7.6", "Consult the official PCI DSS documentation for reference 3.7.6."],
  ["3.7.7", "3.7", "PCI DSS reference 3.7.7", "Consult the official PCI DSS documentation for reference 3.7.7."],
  ["3.7.8", "3.7", "PCI DSS reference 3.7.8", "Consult the official PCI DSS documentation for reference 3.7.8."],
  ["3.7.9", "3.7", "PCI DSS reference 3.7.9", "Consult the official PCI DSS documentation for reference 3.7.9."],
  ["4.1", "4", "PCI DSS reference 4.1", "Consult the official PCI DSS documentation for reference 4.1."],
  ["4.1.1", "4.1", "PCI DSS reference 4.1.1", "Consult the official PCI DSS documentation for reference 4.1.1."],
  ["4.1.2", "4.1", "PCI DSS reference 4.1.2", "Consult the official PCI DSS documentation for reference 4.1.2."],
  ["4.2", "4", "PCI DSS reference 4.2", "Consult the official PCI DSS documentation for reference 4.2."],
  ["4.2.1", "4.2", "PCI DSS reference 4.2.1", "Consult the official PCI DSS documentation for reference 4.2.1."],
  ["4.2.2", "4.2", "PCI DSS reference 4.2.2", "Consult the official PCI DSS documentation for reference 4.2.2."],
  ["5.1", "5", "PCI DSS reference 5.1", "Consult the official PCI DSS documentation for reference 5.1."],
  ["5.1.1", "5.1", "PCI DSS reference 5.1.1", "Consult the official PCI DSS documentation for reference 5.1.1."],
  ["5.1.2", "5.1", "PCI DSS reference 5.1.2", "Consult the official PCI DSS documentation for reference 5.1.2."],
  ["5.2", "5", "PCI DSS reference 5.2", "Consult the official PCI DSS documentation for reference 5.2."],
  ["5.2.1", "5.2", "PCI DSS reference 5.2.1", "Consult the official PCI DSS documentation for reference 5.2.1."],
  ["5.2.2", "5.2", "PCI DSS reference 5.2.2", "Consult the official PCI DSS documentation for reference 5.2.2."],
  ["5.2.3", "5.2", "PCI DSS reference 5.2.3", "Consult the official PCI DSS documentation for reference 5.2.3."],
  ["5.3", "5", "PCI DSS reference 5.3", "Consult the official PCI DSS documentation for reference 5.3."],
  ["5.3.1", "5.3", "PCI DSS reference 5.3.1", "Consult the official PCI DSS documentation for reference 5.3.1."],
  ["5.3.2", "5.3", "PCI DSS reference 5.3.2", "Consult the official PCI DSS documentation for reference 5.3.2."],
  ["5.3.3", "5.3", "PCI DSS reference 5.3.3", "Consult the official PCI DSS documentation for reference 5.3.3."],
  ["5.3.4", "5.3", "PCI DSS reference 5.3.4", "Consult the official PCI DSS documentation for reference 5.3.4."],
  ["5.3.5", "5.3", "PCI DSS reference 5.3.5", "Consult the official PCI DSS documentation for reference 5.3.5."],
  ["5.4", "5", "PCI DSS reference 5.4", "Consult the official PCI DSS documentation for reference 5.4."],
  ["5.4.1", "5.4", "PCI DSS reference 5.4.1", "Consult the official PCI DSS documentation for reference 5.4.1."],
  ["6.1", "6", "PCI DSS reference 6.1", "Consult the official PCI DSS documentation for reference 6.1."],
  ["6.1.1", "6.1", "PCI DSS reference 6.1.1", "Consult the official PCI DSS documentation for reference 6.1.1."],
  ["6.1.2", "6.1", "PCI DSS reference 6.1.2", "Consult the official PCI DSS documentation for reference 6.1.2."],
  ["6.2", "6", "PCI DSS reference 6.2", "Consult the official PCI DSS documentation for reference 6.2."],
  ["6.2.1", "6.2", "PCI DSS reference 6.2.1", "Consult the official PCI DSS documentation for reference 6.2.1."],
  ["6.2.2", "6.2", "PCI DSS reference 6.2.2", "Consult the official PCI DSS documentation for reference 6.2.2."],
  ["6.2.3", "6.2", "PCI DSS reference 6.2.3", "Consult the official PCI DSS documentation for reference 6.2.3."],
  ["6.2.4", "6.2", "PCI DSS reference 6.2.4", "Consult the official PCI DSS documentation for reference 6.2.4."],
  ["6.3", "6", "PCI DSS reference 6.3", "Consult the official PCI DSS documentation for reference 6.3."],
  ["6.3.1", "6.3", "PCI DSS reference 6.3.1", "Consult the official PCI DSS documentation for reference 6.3.1."],
  ["6.3.2", "6.3", "PCI DSS reference 6.3.2", "Consult the official PCI DSS documentation for reference 6.3.2."],
  ["6.3.3", "6.3", "PCI DSS reference 6.3.3", "Consult the official PCI DSS documentation for reference 6.3.3."],
  ["6.4", "6", "PCI DSS reference 6.4", "Consult the official PCI DSS documentation for reference 6.4."],
  ["6.4.1", "6.4", "PCI DSS reference 6.4.1", "Consult the official PCI DSS documentation for reference 6.4.1."],
  ["6.4.2", "6.4", "PCI DSS reference 6.4.2", "Consult the official PCI DSS documentation for reference 6.4.2."],
  ["6.4.3", "6.4", "PCI DSS reference 6.4.3", "Consult the official PCI DSS documentation for reference 6.4.3."],
  ["6.5", "6", "PCI DSS reference 6.5", "Consult the official PCI DSS documentation for reference 6.5."],
  ["6.5.1", "6.5", "PCI DSS reference 6.5.1", "Consult the official PCI DSS documentation for reference 6.5.1."],
  ["6.5.2", "6.5", "PCI DSS reference 6.5.2", "Consult the official PCI DSS documentation for reference 6.5.2."],
  ["6.5.3", "6.5", "PCI DSS reference 6.5.3", "Consult the official PCI DSS documentation for reference 6.5.3."],
  ["6.5.4", "6.5", "PCI DSS reference 6.5.4", "Consult the official PCI DSS documentation for reference 6.5.4."],
  ["6.5.5", "6.5", "PCI DSS reference 6.5.5", "Consult the official PCI DSS documentation for reference 6.5.5."],
  ["6.5.6", "6.5", "PCI DSS reference 6.5.6", "Consult the official PCI DSS documentation for reference 6.5.6."],
  ["7.1", "7", "PCI DSS reference 7.1", "Consult the official PCI DSS documentation for reference 7.1."],
  ["7.1.1", "7.1", "PCI DSS reference 7.1.1", "Consult the official PCI DSS documentation for reference 7.1.1."],
  ["7.1.2", "7.1", "PCI DSS reference 7.1.2", "Consult the official PCI DSS documentation for reference 7.1.2."],
  ["7.2", "7", "PCI DSS reference 7.2", "Consult the official PCI DSS documentation for reference 7.2."],
  ["7.2.1", "7.2", "PCI DSS reference 7.2.1", "Consult the official PCI DSS documentation for reference 7.2.1."],
  ["7.2.2", "7.2", "PCI DSS reference 7.2.2", "Consult the official PCI DSS documentation for reference 7.2.2."],
  ["7.2.3", "7.2", "PCI DSS reference 7.2.3", "Consult the official PCI DSS documentation for reference 7.2.3."],
  ["7.2.4", "7.2", "PCI DSS reference 7.2.4", "Consult the official PCI DSS documentation for reference 7.2.4."],
  ["7.2.5", "7.2", "PCI DSS reference 7.2.5", "Consult the official PCI DSS documentation for reference 7.2.5."],
  ["7.2.6", "7.2", "PCI DSS reference 7.2.6", "Consult the official PCI DSS documentation for reference 7.2.6."],
  ["7.3", "7", "PCI DSS reference 7.3", "Consult the official PCI DSS documentation for reference 7.3."],
  ["7.3.1", "7.3", "PCI DSS reference 7.3.1", "Consult the official PCI DSS documentation for reference 7.3.1."],
  ["7.3.2", "7.3", "PCI DSS reference 7.3.2", "Consult the official PCI DSS documentation for reference 7.3.2."],
  ["7.3.3", "7.3", "PCI DSS reference 7.3.3", "Consult the official PCI DSS documentation for reference 7.3.3."],
  ["8.1", "8", "PCI DSS reference 8.1", "Consult the official PCI DSS documentation for reference 8.1."],
  ["8.1.1", "8.1", "PCI DSS reference 8.1.1", "Consult the official PCI DSS documentation for reference 8.1.1."],
  ["8.1.2", "8.1", "PCI DSS reference 8.1.2", "Consult the official PCI DSS documentation for reference 8.1.2."],
  ["8.2", "8", "PCI DSS reference 8.2", "Consult the official PCI DSS documentation for reference 8.2."],
  ["8.2.1", "8.2", "PCI DSS reference 8.2.1", "Consult the official PCI DSS documentation for reference 8.2.1."],
  ["8.2.2", "8.2", "PCI DSS reference 8.2.2", "Consult the official PCI DSS documentation for reference 8.2.2."],
  ["8.2.3", "8.2", "PCI DSS reference 8.2.3", "Consult the official PCI DSS documentation for reference 8.2.3."],
  ["8.2.4", "8.2", "PCI DSS reference 8.2.4", "Consult the official PCI DSS documentation for reference 8.2.4."],
  ["8.2.5", "8.2", "PCI DSS reference 8.2.5", "Consult the official PCI DSS documentation for reference 8.2.5."],
  ["8.2.6", "8.2", "PCI DSS reference 8.2.6", "Consult the official PCI DSS documentation for reference 8.2.6."],
  ["8.2.7", "8.2", "PCI DSS reference 8.2.7", "Consult the official PCI DSS documentation for reference 8.2.7."],
  ["8.2.8", "8.2", "PCI DSS reference 8.2.8", "Consult the official PCI DSS documentation for reference 8.2.8."],
  ["8.3", "8", "PCI DSS reference 8.3", "Consult the official PCI DSS documentation for reference 8.3."],
  ["8.3.1", "8.3", "PCI DSS reference 8.3.1", "Consult the official PCI DSS documentation for reference 8.3.1."],
  ["8.3.2", "8.3", "PCI DSS reference 8.3.2", "Consult the official PCI DSS documentation for reference 8.3.2."],
  ["8.3.3", "8.3", "PCI DSS reference 8.3.3", "Consult the official PCI DSS documentation for reference 8.3.3."],
  ["8.3.4", "8.3", "PCI DSS reference 8.3.4", "Consult the official PCI DSS documentation for reference 8.3.4."],
  ["8.3.5", "8.3", "PCI DSS reference 8.3.5", "Consult the official PCI DSS documentation for reference 8.3.5."],
  ["8.3.6", "8.3", "PCI DSS reference 8.3.6", "Consult the official PCI DSS documentation for reference 8.3.6."],
  ["8.3.7", "8.3", "PCI DSS reference 8.3.7", "Consult the official PCI DSS documentation for reference 8.3.7."],
  ["8.3.8", "8.3", "PCI DSS reference 8.3.8", "Consult the official PCI DSS documentation for reference 8.3.8."],
  ["8.3.9", "8.3", "PCI DSS reference 8.3.9", "Consult the official PCI DSS documentation for reference 8.3.9."],
  ["8.3.10", "8.3", "PCI DSS reference 8.3.10", "Consult the official PCI DSS documentation for reference 8.3.10."],
  ["8.3.11", "8.3", "PCI DSS reference 8.3.11", "Consult the official PCI DSS documentation for reference 8.3.11."],
  ["8.4", "8", "PCI DSS reference 8.4", "Consult the official PCI DSS documentation for reference 8.4."],
  ["8.4.1", "8.4", "PCI DSS reference 8.4.1", "Consult the official PCI DSS documentation for reference 8.4.1."],
  ["8.4.2", "8.4", "PCI DSS reference 8.4.2", "Consult the official PCI DSS documentation for reference 8.4.2."],
  ["8.4.3", "8.4", "PCI DSS reference 8.4.3", "Consult the official PCI DSS documentation for reference 8.4.3."],
  ["8.5", "8", "PCI DSS reference 8.5", "Consult the official PCI DSS documentation for reference 8.5."],
  ["8.5.1", "8.5", "PCI DSS reference 8.5.1", "Consult the official PCI DSS documentation for reference 8.5.1."],
  ["8.6", "8", "PCI DSS reference 8.6", "Consult the official PCI DSS documentation for reference 8.6."],
  ["8.6.1", "8.6", "PCI DSS reference 8.6.1", "Consult the official PCI DSS documentation for reference 8.6.1."],
  ["8.6.2", "8.6", "PCI DSS reference 8.6.2", "Consult the official PCI DSS documentation for reference 8.6.2."],
  ["8.6.3", "8.6", "PCI DSS reference 8.6.3", "Consult the official PCI DSS documentation for reference 8.6.3."],
  ["9.1", "9", "PCI DSS reference 9.1", "Consult the official PCI DSS documentation for reference 9.1."],
  ["9.1.1", "9.1", "PCI DSS reference 9.1.1", "Consult the official PCI DSS documentation for reference 9.1.1."],
  ["9.1.2", "9.1", "PCI DSS reference 9.1.2", "Consult the official PCI DSS documentation for reference 9.1.2."],
  ["9.2", "9", "PCI DSS reference 9.2", "Consult the official PCI DSS documentation for reference 9.2."],
  ["9.2.1", "9.2", "PCI DSS reference 9.2.1", "Consult the official PCI DSS documentation for reference 9.2.1."],
  ["9.2.2", "9.2", "PCI DSS reference 9.2.2", "Consult the official PCI DSS documentation for reference 9.2.2."],
  ["9.2.3", "9.2", "PCI DSS reference 9.2.3", "Consult the official PCI DSS documentation for reference 9.2.3."],
  ["9.2.4", "9.2", "PCI DSS reference 9.2.4", "Consult the official PCI DSS documentation for reference 9.2.4."],
  ["9.3", "9", "PCI DSS reference 9.3", "Consult the official PCI DSS documentation for reference 9.3."],
  ["9.3.1", "9.3", "PCI DSS reference 9.3.1", "Consult the official PCI DSS documentation for reference 9.3.1."],
  ["9.3.2", "9.3", "PCI DSS reference 9.3.2", "Consult the official PCI DSS documentation for reference 9.3.2."],
  ["9.3.3", "9.3", "PCI DSS reference 9.3.3", "Consult the official PCI DSS documentation for reference 9.3.3."],
  ["9.3.4", "9.3", "PCI DSS reference 9.3.4", "Consult the official PCI DSS documentation for reference 9.3.4."],
  ["9.4", "9", "PCI DSS reference 9.4", "Consult the official PCI DSS documentation for reference 9.4."],
  ["9.4.1", "9.4", "PCI DSS reference 9.4.1", "Consult the official PCI DSS documentation for reference 9.4.1."],
  ["9.4.2", "9.4", "PCI DSS reference 9.4.2", "Consult the official PCI DSS documentation for reference 9.4.2."],
  ["9.4.3", "9.4", "PCI DSS reference 9.4.3", "Consult the official PCI DSS documentation for reference 9.4.3."],
  ["9.4.4", "9.4", "PCI DSS reference 9.4.4", "Consult the official PCI DSS documentation for reference 9.4.4."],
  ["9.4.5", "9.4", "PCI DSS reference 9.4.5", "Consult the official PCI DSS documentation for reference 9.4.5."],
  ["9.4.6", "9.4", "PCI DSS reference 9.4.6", "Consult the official PCI DSS documentation for reference 9.4.6."],
  ["9.4.7", "9.4", "PCI DSS reference 9.4.7", "Consult the official PCI DSS documentation for reference 9.4.7."],
  ["9.5", "9", "PCI DSS reference 9.5", "Consult the official PCI DSS documentation for reference 9.5."],
  ["9.5.1", "9.5", "PCI DSS reference 9.5.1", "Consult the official PCI DSS documentation for reference 9.5.1."],
  ["10.1", "10", "PCI DSS reference 10.1", "Consult the official PCI DSS documentation for reference 10.1."],
  ["10.1.1", "10.1", "PCI DSS reference 10.1.1", "Consult the official PCI DSS documentation for reference 10.1.1."],
  ["10.1.2", "10.1", "PCI DSS reference 10.1.2", "Consult the official PCI DSS documentation for reference 10.1.2."],
  ["10.2", "10", "PCI DSS reference 10.2", "Consult the official PCI DSS documentation for reference 10.2."],
  ["10.2.1", "10.2", "PCI DSS reference 10.2.1", "Consult the official PCI DSS documentation for reference 10.2.1."],
  ["10.2.2", "10.2", "PCI DSS reference 10.2.2", "Consult the official PCI DSS documentation for reference 10.2.2."],
  ["10.3", "10", "PCI DSS reference 10.3", "Consult the official PCI DSS documentation for reference 10.3."],
  ["10.3.1", "10.3", "PCI DSS reference 10.3.1", "Consult the official PCI DSS documentation for reference 10.3.1."],
  ["10.3.2", "10.3", "PCI DSS reference 10.3.2", "Consult the official PCI DSS documentation for reference 10.3.2."],
  ["10.3.3", "10.3", "PCI DSS reference 10.3.3", "Consult the official PCI DSS documentation for reference 10.3.3."],
  ["10.3.4", "10.3", "PCI DSS reference 10.3.4", "Consult the official PCI DSS documentation for reference 10.3.4."],
  ["10.4", "10", "PCI DSS reference 10.4", "Consult the official PCI DSS documentation for reference 10.4."],
  ["10.4.1", "10.4", "PCI DSS reference 10.4.1", "Consult the official PCI DSS documentation for reference 10.4.1."],
  ["10.4.2", "10.4", "PCI DSS reference 10.4.2", "Consult the official PCI DSS documentation for reference 10.4.2."],
  ["10.4.3", "10.4", "PCI DSS reference 10.4.3", "Consult the official PCI DSS documentation for reference 10.4.3."],
  ["10.5", "10", "PCI DSS reference 10.5", "Consult the official PCI DSS documentation for reference 10.5."],
  ["10.5.1", "10.5", "PCI DSS reference 10.5.1", "Consult the official PCI DSS documentation for reference 10.5.1."],
  ["10.6", "10", "PCI DSS reference 10.6", "Consult the official PCI DSS documentation for reference 10.6."],
  ["10.6.1", "10.6", "PCI DSS reference 10.6.1", "Consult the official PCI DSS documentation for reference 10.6.1."],
  ["10.6.2", "10.6", "PCI DSS reference 10.6.2", "Consult the official PCI DSS documentation for reference 10.6.2."],
  ["10.6.3", "10.6", "PCI DSS reference 10.6.3", "Consult the official PCI DSS documentation for reference 10.6.3."],
  ["10.7", "10", "PCI DSS reference 10.7", "Consult the official PCI DSS documentation for reference 10.7."],
  ["10.7.1", "10.7", "PCI DSS reference 10.7.1", "Consult the official PCI DSS documentation for reference 10.7.1."],
  ["10.7.2", "10.7", "PCI DSS reference 10.7.2", "Consult the official PCI DSS documentation for reference 10.7.2."],
  ["10.7.3", "10.7", "PCI DSS reference 10.7.3", "Consult the official PCI DSS documentation for reference 10.7.3."],
  ["11.1", "11", "PCI DSS reference 11.1", "Consult the official PCI DSS documentation for reference 11.1."],
  ["11.1.1", "11.1", "PCI DSS reference 11.1.1", "Consult the official PCI DSS documentation for reference 11.1.1."],
  ["11.1.2", "11.1", "PCI DSS reference 11.1.2", "Consult the official PCI DSS documentation for reference 11.1.2."],
  ["11.2", "11", "PCI DSS reference 11.2", "Consult the official PCI DSS documentation for reference 11.2."],
  ["11.2.1", "11.2", "PCI DSS reference 11.2.1", "Consult the official PCI DSS documentation for reference 11.2.1."],
  ["11.2.2", "11.2", "PCI DSS reference 11.2.2", "Consult the official PCI DSS documentation for reference 11.2.2."],
  ["11.3", "11", "PCI DSS reference 11.3", "Consult the official PCI DSS documentation for reference 11.3."],
  ["11.3.1", "11.3", "PCI DSS reference 11.3.1", "Consult the official PCI DSS documentation for reference 11.3.1."],
  ["11.3.2", "11.3", "PCI DSS reference 11.3.2", "Consult the official PCI DSS documentation for reference 11.3.2."],
  ["11.4", "11", "PCI DSS reference 11.4", "Consult the official PCI DSS documentation for reference 11.4."],
  ["11.4.1", "11.4", "PCI DSS reference 11.4.1", "Consult the official PCI DSS documentation for reference 11.4.1."],
  ["11.4.2", "11.4", "PCI DSS reference 11.4.2", "Consult the official PCI DSS documentation for reference 11.4.2."],
  ["11.4.3", "11.4", "PCI DSS reference 11.4.3", "Consult the official PCI DSS documentation for reference 11.4.3."],
  ["11.4.4", "11.4", "PCI DSS reference 11.4.4", "Consult the official PCI DSS documentation for reference 11.4.4."],
  ["11.4.5", "11.4", "PCI DSS reference 11.4.5", "Consult the official PCI DSS documentation for reference 11.4.5."],
  ["11.4.6", "11.4", "PCI DSS reference 11.4.6", "Consult the official PCI DSS documentation for reference 11.4.6."],
  ["11.4.7", "11.4", "PCI DSS reference 11.4.7", "Consult the official PCI DSS documentation for reference 11.4.7."],
  ["11.5", "11", "PCI DSS reference 11.5", "Consult the official PCI DSS documentation for reference 11.5."],
  ["11.5.1", "11.5", "PCI DSS reference 11.5.1", "Consult the official PCI DSS documentation for reference 11.5.1."],
  ["11.5.2", "11.5", "PCI DSS reference 11.5.2", "Consult the official PCI DSS documentation for reference 11.5.2."],
  ["11.6", "11", "PCI DSS reference 11.6", "Consult the official PCI DSS documentation for reference 11.6."],
  ["11.6.1", "11.6", "PCI DSS reference 11.6.1", "Consult the official PCI DSS documentation for reference 11.6.1."],
  ["12.1", "12", "PCI DSS reference 12.1", "Consult the official PCI DSS documentation for reference 12.1."],
  ["12.1.1", "12.1", "PCI DSS reference 12.1.1", "Consult the official PCI DSS documentation for reference 12.1.1."],
  ["12.1.2", "12.1", "PCI DSS reference 12.1.2", "Consult the official PCI DSS documentation for reference 12.1.2."],
  ["12.1.3", "12.1", "PCI DSS reference 12.1.3", "Consult the official PCI DSS documentation for reference 12.1.3."],
  ["12.1.4", "12.1", "PCI DSS reference 12.1.4", "Consult the official PCI DSS documentation for reference 12.1.4."],
  ["12.2", "12", "PCI DSS reference 12.2", "Consult the official PCI DSS documentation for reference 12.2."],
  ["12.2.1", "12.2", "PCI DSS reference 12.2.1", "Consult the official PCI DSS documentation for reference 12.2.1."],
  ["12.3", "12", "PCI DSS reference 12.3", "Consult the official PCI DSS documentation for reference 12.3."],
  ["12.3.1", "12.3", "PCI DSS reference 12.3.1", "Consult the official PCI DSS documentation for reference 12.3.1."],
  ["12.3.2", "12.3", "PCI DSS reference 12.3.2", "Consult the official PCI DSS documentation for reference 12.3.2."],
  ["12.3.3", "12.3", "PCI DSS reference 12.3.3", "Consult the official PCI DSS documentation for reference 12.3.3."],
  ["12.3.4", "12.3", "PCI DSS reference 12.3.4", "Consult the official PCI DSS documentation for reference 12.3.4."],
  ["12.4", "12", "PCI DSS reference 12.4", "Consult the official PCI DSS documentation for reference 12.4."],
  ["12.4.1", "12.4", "PCI DSS reference 12.4.1", "Consult the official PCI DSS documentation for reference 12.4.1."],
  ["12.4.2", "12.4", "PCI DSS reference 12.4.2", "Consult the official PCI DSS documentation for reference 12.4.2."],
  ["12.5", "12", "PCI DSS reference 12.5", "Consult the official PCI DSS documentation for reference 12.5."],
  ["12.5.1", "12.5", "PCI DSS reference 12.5.1", "Consult the official PCI DSS documentation for reference 12.5.1."],
  ["12.5.2", "12.5", "PCI DSS reference 12.5.2", "Consult the official PCI DSS documentation for reference 12.5.2."],
  ["12.5.3", "12.5", "PCI DSS reference 12.5.3", "Consult the official PCI DSS documentation for reference 12.5.3."],
  ["12.6", "12", "PCI DSS reference 12.6", "Consult the official PCI DSS documentation for reference 12.6."],
  ["12.6.1", "12.6", "PCI DSS reference 12.6.1", "Consult the official PCI DSS documentation for reference 12.6.1."],
  ["12.6.2", "12.6", "PCI DSS reference 12.6.2", "Consult the official PCI DSS documentation for reference 12.6.2."],
  ["12.6.3", "12.6", "PCI DSS reference 12.6.3", "Consult the official PCI DSS documentation for reference 12.6.3."],
  ["12.7", "12", "PCI DSS reference 12.7", "Consult the official PCI DSS documentation for reference 12.7."],
  ["12.7.1", "12.7", "PCI DSS reference 12.7.1", "Consult the official PCI DSS documentation for reference 12.7.1."],
  ["12.8", "12", "PCI DSS reference 12.8", "Consult the official PCI DSS documentation for reference 12.8."],
  ["12.8.1", "12.8", "PCI DSS reference 12.8.1", "Consult the official PCI DSS documentation for reference 12.8.1."],
  ["12.8.2", "12.8", "PCI DSS reference 12.8.2", "Consult the official PCI DSS documentation for reference 12.8.2."],
  ["12.8.3", "12.8", "PCI DSS reference 12.8.3", "Consult the official PCI DSS documentation for reference 12.8.3."],
  ["12.8.4", "12.8", "PCI DSS reference 12.8.4", "Consult the official PCI DSS documentation for reference 12.8.4."],
  ["12.8.5", "12.8", "PCI DSS reference 12.8.5", "Consult the official PCI DSS documentation for reference 12.8.5."],
  ["12.9", "12", "PCI DSS reference 12.9", "Consult the official PCI DSS documentation for reference 12.9."],
  ["12.9.1", "12.9", "PCI DSS reference 12.9.1", "Consult the official PCI DSS documentation for reference 12.9.1."],
  ["12.9.2", "12.9", "PCI DSS reference 12.9.2", "Consult the official PCI DSS documentation for reference 12.9.2."],
  ["12.10", "12", "PCI DSS reference 12.10", "Consult the official PCI DSS documentation for reference 12.10."],
  ["12.10.1", "12.10", "PCI DSS reference 12.10.1", "Consult the official PCI DSS documentation for reference 12.10.1."],
  ["12.10.2", "12.10", "PCI DSS reference 12.10.2", "Consult the official PCI DSS documentation for reference 12.10.2."],
  ["12.10.3", "12.10", "PCI DSS reference 12.10.3", "Consult the official PCI DSS documentation for reference 12.10.3."],
  ["12.10.4", "12.10", "PCI DSS reference 12.10.4", "Consult the official PCI DSS documentation for reference 12.10.4."],
  ["12.10.5", "12.10", "PCI DSS reference 12.10.5", "Consult the official PCI DSS documentation for reference 12.10.5."],
  ["12.10.6", "12.10", "PCI DSS reference 12.10.6", "Consult the official PCI DSS documentation for reference 12.10.6."],
  ["12.10.7", "12.10", "PCI DSS reference 12.10.7", "Consult the official PCI DSS documentation for reference 12.10.7."],
]

/**
 * Reference identifiers that this Argos mapping does not expand. This is not
 * a completeness statement about the standard.
 */
export const PCI_DSS_EXCLUDED_NESTED_CONTROLS: readonly string[] = [
  "3.3.1.1",
  "3.3.1.2",
  "3.3.1.3",
  "3.5.1.1",
  "3.5.1.2",
  "3.5.1.3",
  "3.6.1.1",
  "3.6.1.2",
  "3.6.1.3",
  "4.2.1.1",
  "4.2.1.2",
  "5.2.3.1",
  "5.3.2.1",
  "6.2.3.1",
  "7.2.5.1",
  "8.3.10.1",
  "9.2.1.1",
  "9.3.1.1",
  "9.4.1.1",
  "9.4.1.2",
  "9.4.5.1",
  "9.5.1.1",
  "9.5.1.2",
  "9.5.1.2.1",
  "9.5.1.3",
  "10.2.1.1",
  "10.2.1.2",
  "10.2.1.3",
  "10.2.1.4",
  "10.2.1.5",
  "10.2.1.6",
  "10.4.1.1",
  "10.4.2.1",
  "11.3.1.1",
  "11.3.1.2",
  "11.3.1.3",
  "11.3.2.1",
  "11.5.1.1",
  "12.4.2.1",
  "12.5.2.1",
  "12.6.3.1",
  "12.6.3.2",
  "12.10.4.1"
]

export interface PciDssCatalogControl {
  id: string
  title: string
  parentId: string | null
  level: ControlLevel
  sortId: string
  framework: OwnCatalogFramework
  attributes: Record<string, unknown>
  source: string
}

export interface PciDssCatalogMeta {
  framework: string
  title: string
  version: string
  generatedFrom: string
  source: string
  sourceUrl: string
  disclaimer: string
  requirements: number
  controls: number
  evaluableControls: number
  notEvaluableControls: number
  excludedNestedControls: string[]
}

export interface PciDssCatalog {
  meta: PciDssCatalogMeta
  controls: PciDssCatalogControl[]
}

const LEVEL_BY_DEPTH: Record<number, ControlLevel> = {
  1: "theme",
  2: "category",
  3: "control",
}

/** Señales de Argos (tags/CWE) que activan un control de PCI-DSS. */
export interface PciDssSignals {
  tags: string[]
  cwes: string[]
}

/**
 * Señales que pueden activar cada control, derivadas de las reglas
 * semánticas. Un control sin reglas apuntando a él no es evaluable.
 */
export function pciDssSignalsByControl(): Map<string, PciDssSignals> {
  const out = new Map<string, PciDssSignals>()
  for (const rule of SEMANTIC) {
    for (const [framework, controlId] of rule.targets) {
      if (framework !== FRAMEWORKS.pciDssV4) continue
      const entry = out.get(controlId) ?? { tags: [], cwes: [] }
      for (const tag of rule.tags ?? []) if (!entry.tags.includes(tag)) entry.tags.push(tag)
      for (const cwe of rule.cwes ?? []) if (!entry.cwes.includes(cwe)) entry.cwes.push(cwe)
      out.set(controlId, entry)
    }
  }
  return out
}

/**
 * Builds the reference map and its potential finding associations. Derived
 * statuses are heuristic signals and must not be interpreted as compliance.
 */
export function buildPciDssCatalog(): PciDssCatalog {
  const signals = pciDssSignalsByControl()
  const requirementTitle = new Map(PCI_DSS_REQUIREMENTS.map(([id, title]) => [id, title]))
  const description = new Map<string, string>()
  for (const [id, , , text] of PCI_DSS_CONTROLS) description.set(id, text)

  interface Node {
    id: string
    title: string
    parentId: string | null
    level: ControlLevel
    requirement: string
    description: string
    sortId: string
  }

  const nodes: Node[] = []
  let sort = 0
  const nextSort = () => String(++sort).padStart(5, "0")

  for (const [id, title] of PCI_DSS_REQUIREMENTS) {
    nodes.push({
      id,
      title,
      parentId: null,
      level: LEVEL_BY_DEPTH[1],
      requirement: id,
      description: `Consult the official PCI DSS documentation for reference ${id}.`,
      sortId: nextSort(),
    })
  }
  for (const [id, parentId, title, text] of PCI_DSS_CONTROLS) {
    const depth = id.split(".").length
    nodes.push({
      id,
      title,
      parentId,
      level: LEVEL_BY_DEPTH[depth],
      requirement: id.split(".")[0],
      description: text,
      sortId: nextSort(),
    })
  }

  // Cobertura: un control es evaluable cuando alguna regla semántica lo
  // apunta — es decir, cuando un hallazgo de Argos puede activarlo y el motor
  // puede afirmar algo sobre él. Los nodos agregadores (requisito / sub-requisito)
  // son evaluables solo si una regla los apunta; si no, su estado sale del
  // rollup de sus hijos.
  const controls: PciDssCatalogControl[] = nodes.map((node) => {
    const coverage: ControlCoverage = signals.has(node.id) ? "evaluable" : "not-evaluable"
    const nodeSignals = signals.get(node.id)
    const attributes: Record<string, unknown> = {
      requirement: node.requirement,
      requirementTitle: requirementTitle.get(node.requirement) ?? node.requirement,
      description: node.description,
      coverage,
      mappingBasis: "argos-finding-signals",
    }
    if (nodeSignals) attributes["signals"] = nodeSignals
    return {
      id: node.id,
      title: node.title,
      parentId: node.parentId,
      level: node.level,
      sortId: node.sortId,
      framework: FRAMEWORKS.pciDssV4,
      attributes,
      source: PCI_DSS_SOURCE,
    }
  })

  const leafControls = controls.filter((control) => control.level === "control")
  const evaluableControls = leafControls.filter((control) => control.attributes["coverage"] === "evaluable")

  return {
    meta: {
      framework: FRAMEWORKS.pciDssV4,
      title: "PCI DSS v4.0.1",
      version: PCI_DSS_VERSION,
      generatedFrom: "compliance/pci-dss.ts (PCI DSS v4.0.1)",
      source: PCI_DSS_SOURCE,
      sourceUrl: PCI_DSS_SOURCE_URL,
      disclaimer:
        "Argos provides reference identifiers and heuristic finding mappings only. This catalog does not reproduce PCI DSS requirement text and does not constitute a PCI DSS compliance assessment. Consult the official standard for authoritative requirements.",
      requirements: PCI_DSS_REQUIREMENTS.length,
      controls: leafControls.length,
      evaluableControls: evaluableControls.length,
      notEvaluableControls: leafControls.length - evaluableControls.length,
      excludedNestedControls: [...PCI_DSS_EXCLUDED_NESTED_CONTROLS],
    },
    controls,
  }
}
