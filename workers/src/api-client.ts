// Taskboi API Client - Calls the Supabase Edge Function

import { apiRequestUrl, normalizeTaskboiApiBaseUrl } from "./api-base-url";

// Types
interface Project {
  id: string;
  user_id: string;
  name: string;
  color: string;
  icon: string | null;
  is_inbox: boolean;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

interface Task {
  id: string;
  project_id: string;
  user_id: string;
  parent_id: string | null;
  title: string;
  description: string | null;
  due_date: string | null;
  due_time: string | null;
  priority: number;
  is_completed: boolean;
  completed_at: string | null;
  sort_order: number;
  recurrence_rule: string | null;
  recurrence_parent_id: string | null;
  recurrence_anchor_date: string | null;
  created_at: string;
  updated_at: string;
}

interface ProjectsResponse { projects: Project[] }
interface ProjectResponse { project: Project }
interface TasksResponse { tasks: Task[] }
interface TaskResponse { task: Task }
interface CompleteTaskResponse { success: boolean; completedTask: Task; nextTask: Task | null }
interface SuccessResponse { success: boolean }

export class TaskboiApiClient {
  private apiKey: string;
  private apiBaseUrl: string;

  constructor(apiKey: string, apiBaseUrl: string) {
    this.apiKey = apiKey;
    this.apiBaseUrl = normalizeTaskboiApiBaseUrl(apiBaseUrl);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, unknown>
  ): Promise<T> {
    const response = await fetch(apiRequestUrl(this.apiBaseUrl, path), {
      method,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = (await response.json()) as T & { error?: string };

    if (!response.ok) {
      throw new Error(data.error || `API error: ${response.status}`);
    }

    return data;
  }

  // ============================================
  // PROJECTS
  // ============================================

  async listProjects(): Promise<Project[]> {
    const response = await this.request<ProjectsResponse>("GET", "/projects");
    return response.projects;
  }

  async getProject(id: string): Promise<Project> {
    const response = await this.request<ProjectResponse>("GET", `/projects/${encodeURIComponent(id)}`);
    return response.project;
  }

  async getInboxProject(): Promise<Project> {
    const response = await this.request<ProjectResponse>("GET", "/projects/inbox");
    return response.project;
  }

  async createProject(params: {
    name: string;
    color?: string;
    icon?: string;
  }): Promise<Project> {
    const response = await this.request<ProjectResponse>("POST", "/projects", params);
    return response.project;
  }

  async updateProject(
    id: string,
    params: {
      name?: string;
      color?: string;
      icon?: string;
    }
  ): Promise<Project> {
    const response = await this.request<ProjectResponse>("PATCH", `/projects/${encodeURIComponent(id)}`, params);
    return response.project;
  }

  async deleteProject(id: string): Promise<void> {
    await this.request<SuccessResponse>("DELETE", `/projects/${encodeURIComponent(id)}`);
  }

  // ============================================
  // TASKS
  // ============================================

  async listTasks(projectId?: string): Promise<Task[]> {
    const query = projectId ? `?projectId=${encodeURIComponent(projectId)}` : "";
    const response = await this.request<TasksResponse>("GET", `/tasks${query}`);
    return response.tasks;
  }

  async getTask(id: string): Promise<Task> {
    const response = await this.request<TaskResponse>("GET", `/tasks/${encodeURIComponent(id)}`);
    return response.task;
  }

  async getTodayTasks(): Promise<Task[]> {
    const response = await this.request<TasksResponse>("GET", "/tasks/today");
    return response.tasks;
  }

  async getUpcomingTasks(): Promise<Task[]> {
    const response = await this.request<TasksResponse>("GET", "/tasks/upcoming");
    return response.tasks;
  }

  async getSubtasks(parentId: string): Promise<Task[]> {
    const response = await this.request<TasksResponse>("GET", `/tasks/${encodeURIComponent(parentId)}/subtasks`);
    return response.tasks;
  }

  async createTask(params: {
    projectId: string;
    title: string;
    description?: string;
    dueDate?: string;
    dueTime?: string;
    priority?: number;
    parentId?: string;
    recurrenceRule?: string;
  }): Promise<Task> {
    const response = await this.request<TaskResponse>("POST", "/tasks", params);
    return response.task;
  }

  async updateTask(
    id: string,
    params: {
      title?: string;
      description?: string;
      dueDate?: string | null;
      dueTime?: string | null;
      priority?: number;
      projectId?: string;
      recurrenceRule?: string;
    }
  ): Promise<Task> {
    const response = await this.request<TaskResponse>("PATCH", `/tasks/${encodeURIComponent(id)}`, params);
    return response.task;
  }

  async completeTask(id: string): Promise<CompleteTaskResponse> {
    return await this.request<CompleteTaskResponse>("POST", `/tasks/${encodeURIComponent(id)}/complete`);
  }

  async uncompleteTask(id: string): Promise<Task> {
    const response = await this.request<TaskResponse>("POST", `/tasks/${encodeURIComponent(id)}/uncomplete`);
    return response.task;
  }

  async deleteTask(id: string): Promise<void> {
    await this.request<SuccessResponse>("DELETE", `/tasks/${encodeURIComponent(id)}`);
  }
}
