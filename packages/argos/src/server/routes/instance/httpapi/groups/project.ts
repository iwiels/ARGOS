import { Project } from "@/project/project"
import { ProjectV2 } from "@argos/core/project"
import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiError, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { ProjectNotFoundError } from "../errors"
import { Authorization } from "../middleware/authorization"
import { InstanceContextMiddleware } from "../middleware/instance-context"
import { WorkspaceRoutingMiddleware, WorkspaceRoutingQuery } from "../middleware/workspace-routing"
import { described } from "./metadata"

const root = "/project"
const UpdatePayload = Project.UpdatePayload

const WebhookTestPayload = Schema.Struct({
  url: Schema.String,
  secret: Schema.optional(Schema.String),
  format: Schema.optional(Schema.Literals(["generic", "jira", "slack"])),
})

const WebhookTestResponse = Schema.Struct({
  ok: Schema.Boolean,
  statusCode: Schema.Number,
  responseBody: Schema.optional(Schema.String),
})

export const ProjectApi = HttpApi.make("project")
  .add(
    HttpApiGroup.make("project")
      .add(
        HttpApiEndpoint.get("list", root, {
          query: WorkspaceRoutingQuery,
          success: described(Schema.Array(Project.Info), "List of projects"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "project.list",
            summary: "List all projects",
            description: "Get a list of projects that have been opened with OpenCode.",
          }),
        ),
        HttpApiEndpoint.get("current", `${root}/current`, {
          query: WorkspaceRoutingQuery,
          success: described(Project.Info, "Current project information"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "project.current",
            summary: "Get current project",
            description: "Retrieve the currently active project that OpenCode is working with.",
          }),
        ),
        HttpApiEndpoint.post("initGit", `${root}/git/init`, {
          query: WorkspaceRoutingQuery,
          success: described(Project.Info, "Project information after git initialization"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "project.initGit",
            summary: "Initialize git repository",
            description: "Create a git repository for the current project and return the refreshed project info.",
          }),
        ),
        HttpApiEndpoint.patch("update", `${root}/:projectID`, {
          params: { projectID: ProjectV2.ID },
          query: WorkspaceRoutingQuery,
          payload: UpdatePayload,
          success: described(Project.Info, "Updated project information"),
          error: [HttpApiError.BadRequest, ProjectNotFoundError],
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "project.update",
            summary: "Update project",
            description: "Update project properties such as name, icon, and commands.",
          }),
        ),
        HttpApiEndpoint.get("directories", `${root}/:projectID/directories`, {
          params: { projectID: ProjectV2.ID },
          query: WorkspaceRoutingQuery,
          success: described(ProjectV2.Directories, "Project directories"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "project.directories",
            summary: "List project directories",
            description: "List known local absolute directories for a project.",
          }),
        ),
        HttpApiEndpoint.post("webhookTest", `${root}/:projectID/webhook/test`, {
          params: { projectID: ProjectV2.ID },
          query: WorkspaceRoutingQuery,
          payload: WebhookTestPayload,
          success: described(WebhookTestResponse, "Result of a test dispatch to the given webhook URL"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "project.webhookTest",
            summary: "Send a test dispatch to a webhook",
            description: "Dispatches a synthetic finding to the given URL/format without saving the configuration.",
          }),
        ),
      )
      .annotateMerge(
        OpenApi.annotations({
          title: "project",
          description: "Experimental HttpApi project routes.",
        }),
      )
      .middleware(InstanceContextMiddleware)
      .middleware(WorkspaceRoutingMiddleware)
      .middleware(Authorization),
  )
  .annotateMerge(
    OpenApi.annotations({
      title: "opencode experimental HttpApi",
      version: "0.0.1",
      description: "Experimental HttpApi surface for selected instance routes.",
    }),
  )
