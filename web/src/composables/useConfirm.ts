import { ElMessageBox } from 'element-plus'

interface UseConfirmOptions {
  title?: string
  message?: string
  confirmText?: string
  cancelText?: string
  type?: 'warning' | 'info' | 'success' | 'error'
}

export function useConfirm() {
  async function confirm(options: UseConfirmOptions = {}): Promise<boolean> {
    const {
      title = '确认操作',
      message = '确定要执行此操作吗？',
      confirmText = '确定',
      cancelText = '取消',
      type = 'warning',
    } = options

    try {
      await ElMessageBox.confirm(message, title, {
        confirmButtonText: confirmText,
        cancelButtonText: cancelText,
        type,
      })
      return true
    } catch {
      return false
    }
  }

  async function confirmDelete(itemName?: string): Promise<boolean> {
    return confirm({
      title: '删除确认',
      message: `确定要删除${itemName ? ` "${itemName}"` : '该项'}吗？此操作不可恢复。`,
      confirmText: '删除',
      type: 'warning',
    })
  }

  return {
    confirm,
    confirmDelete,
  }
}
