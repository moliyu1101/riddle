import { reactive } from "vue";

// 新建 / 编辑共用同一个三步向导弹窗。editTaskId 非空表示编辑已有任务。
const state = reactive({ open: false, editTaskId: null });

export function openCreateTask() {
  state.editTaskId = null;
  state.open = true;
}

export function openEditTask(taskId) {
  state.editTaskId = taskId;
  state.open = true;
}

export function closeCreateTask() {
  state.open = false;
  state.editTaskId = null;
}

export function useCreateTask() {
  return state;
}
