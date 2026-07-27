// Taskboi MCP Types

export interface Project {
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

export interface Task {
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

export interface ApiResponse<T> {
  data?: T;
  error?: string;
}

export interface ProjectsResponse {
  projects: Project[];
}

export interface ProjectResponse {
  project: Project;
}

export interface TasksResponse {
  tasks: Task[];
}

export interface TaskResponse {
  task: Task;
}

export interface CompleteTaskResponse {
  success: boolean;
  completedTask: Task;
  nextTask: Task | null;
}

export interface SuccessResponse {
  success: boolean;
}

// Recurrence rule constants
export const RecurrenceRule = {
  DAILY: "FREQ=DAILY",
  WEEKLY: "FREQ=WEEKLY",
  MONTHLY: "FREQ=MONTHLY",
  YEARLY: "FREQ=YEARLY",
  weeklyOn: (days: string[]) => `FREQ=WEEKLY;BYDAY=${days.join(",")}`,
  monthlyOnDay: (day: number) => `FREQ=MONTHLY;BYMONTHDAY=${day}`,
  everyNDays: (n: number) => `FREQ=DAILY;INTERVAL=${n}`,
  everyNWeeks: (n: number) => `FREQ=WEEKLY;INTERVAL=${n}`,
  everyNMonths: (n: number) => `FREQ=MONTHLY;INTERVAL=${n}`,
} as const;

// Priority levels
export const Priority = {
  NONE: 0,
  LOW: 4,
  NORMAL: 3,
  HIGH: 2,
  URGENT: 1,
} as const;
