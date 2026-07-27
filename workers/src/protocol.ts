import { z } from "zod";

type JsonObject = Record<string, unknown>;

export interface ToolInputSchema extends JsonObject {
  type: "object";
  properties?: Record<string, JsonObject>;
  required?: string[];
  additionalProperties?: boolean;
}

/** Structural MCP tool definition, independent of any transport SDK. */
export interface Tool {
  name: string;
  description?: string;
  inputSchema: ToolInputSchema;
}

/** Structural MCP tool result used by both HTTP and stdio adapters. */
export interface CallToolResult {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

type InputSchema = ToolInputSchema;

export interface CreateProjectInput {
  name: string;
  color?: string;
  icon?: string;
}

export interface UpdateProjectInput {
  name?: string;
  color?: string;
  icon?: string;
}

export interface CreateTaskInput {
  projectId: string;
  title: string;
  description?: string;
  dueDate?: string;
  dueTime?: string;
  priority?: number;
  parentId?: string;
  recurrenceRule?: string;
}

export interface UpdateTaskInput {
  title?: string;
  description?: string;
  dueDate?: string | null;
  dueTime?: string | null;
  priority?: number;
  projectId?: string;
  recurrenceRule?: string;
}

export interface CompleteTaskOperationResult {
  completedTask: unknown;
  nextTask: unknown | null;
}

/** Provider-neutral operations required by the Taskboi MCP protocol. */
export interface TaskboiOperations {
  listProjects(): Promise<unknown[]>;
  getInboxProject(): Promise<unknown>;
  getProject(id: string): Promise<unknown>;
  createProject(params: CreateProjectInput): Promise<unknown>;
  updateProject(id: string, params: UpdateProjectInput): Promise<unknown>;
  deleteProject(id: string): Promise<void>;
  listTasks(projectId?: string): Promise<unknown[]>;
  getTask(id: string): Promise<unknown>;
  getTodayTasks(): Promise<unknown[]>;
  getUpcomingTasks(): Promise<unknown[]>;
  getSubtasks(parentId: string): Promise<unknown[]>;
  createTask(params: CreateTaskInput): Promise<unknown>;
  updateTask(id: string, params: UpdateTaskInput): Promise<unknown>;
  completeTask(id: string): Promise<CompleteTaskOperationResult>;
  uncompleteTask(id: string): Promise<unknown>;
  deleteTask(id: string): Promise<void>;
}

const uuid = z.string().uuid();
const date = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const time = z.string().regex(/^\d{2}:\d{2}$/);
const priority = z.coerce.number().int().min(0).max(4);
const empty = z.object({});
const callToolRequest = z.object({
  method: z.literal("tools/call"),
  params: z.object({
    name: z.string(),
    arguments: z.record(z.string(), z.unknown()).optional(),
    _meta: z.record(z.string(), z.unknown()).optional(),
  }),
});

const toolValidators = {
  list_projects: empty,
  get_inbox: empty,
  get_project: z.object({ id: uuid }),
  create_project: z.object({
    name: z.string().min(1),
    color: z.string().regex(/^#[0-9A-Fa-f]{6}$/).optional(),
    icon: z.string().optional(),
  }),
  update_project: z.object({
    id: uuid,
    name: z.string().min(1).optional(),
    color: z.string().regex(/^#[0-9A-Fa-f]{6}$/).optional(),
    icon: z.string().optional(),
  }),
  delete_project: z.object({ id: uuid }),
  list_tasks: z.object({ projectId: uuid.optional() }),
  get_task: z.object({ id: uuid }),
  get_today_tasks: empty,
  get_upcoming_tasks: empty,
  get_subtasks: z.object({ parentId: uuid }),
  create_task: z.object({
    projectId: uuid,
    title: z.string().min(1),
    description: z.string().optional(),
    dueDate: date.optional(),
    dueTime: time.optional(),
    priority: priority.optional(),
    parentId: uuid.optional(),
    recurrenceRule: z.string().optional(),
  }),
  update_task: z.object({
    id: uuid,
    title: z.string().min(1).optional(),
    description: z.string().optional(),
    dueDate: date.optional(),
    clearDueDate: z.boolean().optional(),
    dueTime: time.nullable().optional(),
    priority: priority.optional(),
    projectId: uuid.optional(),
    recurrenceRule: z.string().optional(),
  }),
  complete_task: z.object({ id: uuid }),
  uncomplete_task: z.object({ id: uuid }),
  delete_task: z.object({ id: uuid }),
} satisfies Record<string, z.ZodType<JsonObject>>;

type ToolName = keyof typeof toolValidators;

const string = (description?: string, extra: JsonObject = {}): JsonObject => ({
  type: "string",
  ...(description ? { description } : {}),
  ...extra,
});
const prioritySchema = (description: string): JsonObject => ({
  type: "integer",
  minimum: 0,
  maximum: 4,
  description,
});
const boolean = (description: string): JsonObject => ({ type: "boolean", description });
const object = (
  properties: Record<string, JsonObject> = {},
  required: string[] = [],
): InputSchema => ({ type: "object", properties, required, additionalProperties: false });

export const taskboiTools: Tool[] = [
  { name: "list_projects", description: "List all projects in your Taskboi workspace", inputSchema: object() },
  { name: "get_inbox", description: "Get the default Inbox project", inputSchema: object() },
  { name: "get_project", description: "Get details of a specific project", inputSchema: object({ id: string("The project ID", { format: "uuid" }) }, ["id"]) },
  { name: "create_project", description: "Create a new project", inputSchema: object({
    name: string("The project name", { minLength: 1 }),
    color: string("Hex color code (e.g., #6366F1)", { pattern: "^#[0-9A-Fa-f]{6}$" }),
    icon: string("Icon name (e.g., folder, star, work)"),
  }, ["name"]) },
  { name: "update_project", description: "Update an existing project", inputSchema: object({
    id: string("The project ID", { format: "uuid" }),
    name: string("New project name", { minLength: 1 }),
    color: string("New hex color code", { pattern: "^#[0-9A-Fa-f]{6}$" }),
    icon: string("New icon name"),
  }, ["id"]) },
  { name: "delete_project", description: "Delete a project (cannot delete Inbox)", inputSchema: object({ id: string("The project ID to delete", { format: "uuid" }) }, ["id"]) },
  { name: "list_tasks", description: "List all tasks, optionally filtered by project", inputSchema: object({ projectId: string("Filter by project ID", { format: "uuid" }) }) },
  { name: "get_task", description: "Get details of a specific task", inputSchema: object({ id: string("The task ID", { format: "uuid" }) }, ["id"]) },
  { name: "get_today_tasks", description: "Get all tasks due today (including overdue recurring tasks)", inputSchema: object() },
  { name: "get_upcoming_tasks", description: "Get all upcoming tasks with due dates", inputSchema: object() },
  { name: "get_subtasks", description: "Get all subtasks of a parent task", inputSchema: object({ parentId: string("The parent task ID", { format: "uuid" }) }, ["parentId"]) },
  { name: "create_task", description: "Create a new task", inputSchema: object({
    projectId: string("The project ID to add the task to", { format: "uuid" }),
    title: string("The task title", { minLength: 1 }),
    description: string("Task description"),
    dueDate: string("Due date in YYYY-MM-DD format", { pattern: "^\\d{4}-\\d{2}-\\d{2}$" }),
    dueTime: string("Due time in HH:MM format (24-hour). Omit for no specific time.", { pattern: "^\\d{2}:\\d{2}$" }),
    priority: prioritySchema("Priority: 0=none, 1=urgent, 2=high, 3=normal, 4=low"),
    parentId: string("Parent task ID for subtasks", { format: "uuid" }),
    recurrenceRule: string("Recurrence rule (RRULE format): FREQ=DAILY, FREQ=WEEKLY, FREQ=MONTHLY, FREQ=YEARLY, or with options like FREQ=WEEKLY;BYDAY=MO,WE,FR"),
  }, ["projectId", "title"]) },
  { name: "update_task", description: "Update an existing task. Omitted fields are left unchanged; to remove the due date, pass clearDueDate: true.", inputSchema: object({
    id: string("The task ID", { format: "uuid" }),
    title: string("New task title", { minLength: 1 }),
    description: string("New description"),
    dueDate: string("New due date in YYYY-MM-DD format", { pattern: "^\\d{4}-\\d{2}-\\d{2}$" }),
    clearDueDate: boolean("Set to true to remove the task's due date"),
    dueTime: { type: ["string", "null"], description: "New due time in HH:MM format (24-hour). Pass null to remove the time.", pattern: "^\\d{2}:\\d{2}$" },
    priority: prioritySchema("New priority: 0=none, 1=urgent, 2=high, 3=normal, 4=low"),
    projectId: string("Move to a different project", { format: "uuid" }),
    recurrenceRule: string("New recurrence rule"),
  }, ["id"]) },
  { name: "complete_task", description: "Mark a task as complete. For recurring tasks, this also creates the next occurrence.", inputSchema: object({ id: string("The task ID to complete", { format: "uuid" }) }, ["id"]) },
  { name: "uncomplete_task", description: "Mark a completed task as incomplete", inputSchema: object({ id: string("The task ID to uncomplete", { format: "uuid" }) }, ["id"]) },
  { name: "delete_task", description: "Delete a task", inputSchema: object({ id: string("The task ID to delete", { format: "uuid" }) }, ["id"]) },
];

const json = (data: unknown): CallToolResult => ({
  content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
});

const errorResult = (error: unknown): CallToolResult => ({
  content: [{
    type: "text",
    text: `Error: ${error instanceof Error ? error.message : "Unknown error"}`,
  }],
  isError: true,
});

function dropUndefined<T extends JsonObject>(value: T): T {
  return Object.fromEntries(
    Object.entries(value).filter(([, item]) => item !== undefined),
  ) as T;
}

export async function dispatchTaskboiTool(
  name: string,
  args: JsonObject | undefined,
  operations: TaskboiOperations,
): Promise<CallToolResult> {
  const validator = toolValidators[name as ToolName];
  if (!validator) return errorResult(new Error(`Unknown tool: ${name}`));
  const parsed = validator.safeParse(args ?? {});
  if (!parsed.success) {
    return errorResult(new Error(`Invalid arguments for ${name}: ${parsed.error.message}`));
  }
  const input = parsed.data as JsonObject;

  try {
    switch (name as ToolName) {
      case "list_projects": return json({ projects: await operations.listProjects() });
      case "get_inbox": return json({ project: await operations.getInboxProject() });
      case "get_project": return json({ project: await operations.getProject(input.id as string) });
      case "create_project": return json({ success: true, project: await operations.createProject(input as unknown as CreateProjectInput) });
      case "update_project": {
        const { id, ...updates } = input;
        return json({ success: true, project: await operations.updateProject(id as string, dropUndefined(updates)) });
      }
      case "delete_project":
        await operations.deleteProject(input.id as string);
        return json({ success: true, message: "Project deleted" });
      case "list_tasks": return json({ tasks: await operations.listTasks(input.projectId as string | undefined) });
      case "get_task": return json({ task: await operations.getTask(input.id as string) });
      case "get_today_tasks": {
        const tasks = await operations.getTodayTasks();
        return json({ tasks, count: tasks.length });
      }
      case "get_upcoming_tasks": {
        const tasks = await operations.getUpcomingTasks();
        return json({ tasks, count: tasks.length });
      }
      case "get_subtasks": {
        const tasks = await operations.getSubtasks(input.parentId as string);
        return json({ tasks, count: tasks.length });
      }
      case "create_task": {
        const params = input as unknown as CreateTaskInput;
        return json({ success: true, task: await operations.createTask({ ...params, priority: params.priority ?? 0 }) });
      }
      case "update_task": {
        const { id, clearDueDate, ...updates } = input;
        const params = dropUndefined(updates) as UpdateTaskInput;
        if (clearDueDate === true) params.dueDate = null;
        return json({ success: true, task: await operations.updateTask(id as string, params) });
      }
      case "complete_task": {
        const result = await operations.completeTask(input.id as string);
        const response: JsonObject = { success: true, completedTask: result.completedTask };
        if (result.nextTask) {
          response.nextTask = result.nextTask;
          response.message = "Task completed and next occurrence created";
        } else {
          response.message = "Task completed";
        }
        return json(response);
      }
      case "uncomplete_task": return json({ success: true, task: await operations.uncompleteTask(input.id as string) });
      case "delete_task":
        await operations.deleteTask(input.id as string);
        return json({ success: true, message: "Task deleted" });
    }
  } catch (error) {
    return errorResult(error);
  }
}

export interface TaskboiJsonRpcResponse {
  jsonrpc: "2.0";
  id?: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

/**
 * Handles the stateless MCP methods used by HTTP adapters. Validation and
 * error shapes intentionally mirror the public SDK Server behavior.
 */
export async function handleTaskboiMcpRequest(
  request: unknown,
  operations: TaskboiOperations,
): Promise<TaskboiJsonRpcResponse | null> {
  const value = request && typeof request === "object"
    ? request as { method?: unknown; params?: unknown; id?: number | string }
    : {};
  if (typeof value.method === "string" &&
      !Object.prototype.hasOwnProperty.call(value, "id")) {
    return null;
  }
  const id = value.id;

  switch (value.method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "Taskboi", version: "1.0.0" },
        },
      };
    case "tools/list":
      return { jsonrpc: "2.0", id, result: { tools: taskboiTools } };
    case "tools/call": {
      const parsed = callToolRequest.safeParse(value);
      if (!parsed.success) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32603, message: parsed.error.message },
        };
      }
      return {
        jsonrpc: "2.0",
        id,
        result: await dispatchTaskboiTool(
          parsed.data.params.name,
          parsed.data.params.arguments,
          operations,
        ),
      };
    }
    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: "Method not found" },
      };
  }
}
