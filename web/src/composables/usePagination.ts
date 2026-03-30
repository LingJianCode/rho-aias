import { ref, computed, watch } from 'vue'
import type { Ref, ComputedRef } from 'vue'

interface UsePaginationOptions {
  defaultPage?: number
  defaultPageSize?: number
  pageSizes?: number[]
}

interface UsePaginationReturn {
  page: Ref<number>
  pageSize: Ref<number>
  pageSizes: number[]
  total: Ref<number>
  totalPages: ComputedRef<number>
  setPage: (p: number) => void
  setPageSize: (ps: number) => void
  setTotal: (t: number) => void
  reset: () => void
}

export function usePagination(options: UsePaginationOptions = {}): UsePaginationReturn {
  const {
    defaultPage = 1,
    defaultPageSize = 20,
    pageSizes = [10, 20, 50, 100],
  } = options

  const page = ref(defaultPage)
  const pageSize = ref(defaultPageSize)
  const total = ref(0)

  const totalPages = computed(() => Math.ceil(total.value / pageSize.value) || 1)

  watch(pageSize, () => {
    page.value = 1
  })

  function setPage(p: number) {
    page.value = p
  }

  function setPageSize(ps: number) {
    pageSize.value = ps
  }

  function setTotal(t: number) {
    total.value = t
  }

  function reset() {
    page.value = defaultPage
    pageSize.value = defaultPageSize
    total.value = 0
  }

  return {
    page,
    pageSize,
    pageSizes,
    total,
    totalPages,
    setPage,
    setPageSize,
    setTotal,
    reset,
  }
}
