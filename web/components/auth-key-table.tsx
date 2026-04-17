"use client"

import {
  type PaginationState,
  type RowSelectionState,
  type SortingState,
  type VisibilityState,
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table"
import { ArrowUpDown, Ban, Columns3 } from "lucide-react"
import {
  type ReactNode,
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react"

import { AuthKeyStateBadge } from "@/components/status-badges"
import { useConsole } from "@/components/console/console-context"
import { focusCollectionItem } from "@/components/console/interaction"
import { SearchField } from "@/components/console/primitives"
import { CONSOLE_COPY } from "@/components/console/strings"
import {
  useUrlQueryState,
  useUrlSortingState,
} from "@/components/console/use-url-query-state"
import { usePersistentUiState } from "@/components/console/use-persistent-ui-state"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { formatDateTime, joinTags, truncateMiddle } from "@/lib/format"
import type { AuthKey } from "@/lib/types"

const columnHelper = createColumnHelper<AuthKey>()
const DEFAULT_SORTING: SortingState = [{ id: "created_at_unix_secs", desc: true }]
const PAGE_SIZE_OPTIONS = [10, 25, 50]
const DEFAULT_PAGINATION: PaginationState = {
  pageIndex: 0,
  pageSize: 10,
}

function normalizePagination(value: PaginationState) {
  return {
    pageIndex:
      Number.isFinite(value.pageIndex) && value.pageIndex >= 0
        ? value.pageIndex
        : DEFAULT_PAGINATION.pageIndex,
    pageSize: PAGE_SIZE_OPTIONS.includes(value.pageSize)
      ? value.pageSize
      : DEFAULT_PAGINATION.pageSize,
  }
}

function normalizeDensity(value: "comfortable" | "compact") {
  return value === "compact" ? "compact" : "comfortable"
}

function normalizeColumnVisibility(value: VisibilityState) {
  return Object.fromEntries(
    Object.entries(value).filter(
      (entry): entry is [string, boolean] => typeof entry[1] === "boolean"
    )
  ) satisfies VisibilityState
}

function hasSortingOverride(current: SortingState, fallback: SortingState) {
  if (current.length !== fallback.length) {
    return true
  }

  return current.some((value, index) => {
    const target = fallback[index]
    return value.id !== target?.id || value.desc !== target?.desc
  })
}

function matchesAuthKey(key: AuthKey, query: string) {
  if (!query) {
    return true
  }

  const needle = query.toLowerCase()

  return [
    key.id,
    key.description ?? "",
    key.tags.join(", "),
    key.state,
    key.reusable ? "reusable" : "",
    key.ephemeral ? "ephemeral" : "",
  ]
    .join(" ")
    .toLowerCase()
    .includes(needle)
}

export function AuthKeyTable({
  authKeys,
  pendingKeyId,
  onRevoke,
  onBulkRevoke,
  onView,
  activeKeyId,
  bulkRevoking,
  resetSelectionKey,
  toolbarAction,
}: {
  authKeys: AuthKey[]
  pendingKeyId: string | null
  onRevoke: (authKey: AuthKey) => void
  onBulkRevoke: (authKeys: AuthKey[]) => void
  onView: (authKey: AuthKey) => void
  activeKeyId: string | null
  bulkRevoking: boolean
  resetSelectionKey: number
  toolbarAction?: ReactNode
}) {
  const { locale, timezone } = useConsole()
  const accessCopy = CONSOLE_COPY[locale].access
  const copy = CONSOLE_COPY[locale].access.table
  const common = CONSOLE_COPY[locale].common
  const [sorting, setSorting] = useUrlSortingState("access-sort", DEFAULT_SORTING)
  const [query, setQuery] = useUrlQueryState("access-q")
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({})
  const [storedPagination, setStoredPagination] = usePersistentUiState<PaginationState>(
    "access-pagination",
    DEFAULT_PAGINATION
  )
  const pagination = useMemo(
    () => normalizePagination(storedPagination),
    [storedPagination]
  )
  const [density, setDensity] = usePersistentUiState<"comfortable" | "compact">(
    "access-density",
    "comfortable"
  )
  const resolvedDensity = normalizeDensity(density)
  const [storedColumnVisibility, setStoredColumnVisibility] = usePersistentUiState<VisibilityState>(
    "access-columns",
    {}
  )
  const columnVisibility = useMemo(
    () => normalizeColumnVisibility(storedColumnVisibility),
    [storedColumnVisibility]
  )
  const [showColumns, setShowColumns] = useState(false)
  const columnsMenuRef = useRef<HTMLDivElement | null>(null)
  const deferredQuery = useDeferredValue(query)
  const hasActiveFilters =
    query.trim().length > 0 || hasSortingOverride(sorting, DEFAULT_SORTING)

  const filteredAuthKeys = useMemo(
    () => authKeys.filter((authKey) => matchesAuthKey(authKey, deferredQuery)),
    [authKeys, deferredQuery]
  )

  const clearFilters = useCallback(() => {
    setQuery("")
    setSorting(DEFAULT_SORTING)
  }, [setQuery, setSorting])
  const clearQuery = useCallback(() => {
    setQuery("")
  }, [setQuery])

  useEffect(() => {
    setRowSelection({})
  }, [resetSelectionKey])

  useEffect(() => {
    if (
      pagination.pageIndex !== storedPagination.pageIndex ||
      pagination.pageSize !== storedPagination.pageSize
    ) {
      setStoredPagination(pagination)
    }
  }, [pagination, setStoredPagination, storedPagination.pageIndex, storedPagination.pageSize])

  useEffect(() => {
    if (resolvedDensity !== density) {
      setDensity(resolvedDensity)
    }
  }, [density, resolvedDensity, setDensity])

  useEffect(() => {
    const storedKeys = Object.keys(storedColumnVisibility)
    const normalizedKeys = Object.keys(columnVisibility)
    const isSame =
      storedKeys.length === normalizedKeys.length &&
      normalizedKeys.every((key) => storedColumnVisibility[key] === columnVisibility[key])

    if (!isSame) {
      setStoredColumnVisibility(columnVisibility)
    }
  }, [columnVisibility, setStoredColumnVisibility, storedColumnVisibility])

  useEffect(() => {
    setStoredPagination((current) => {
      if (current.pageIndex === 0) {
        return current
      }

      return { ...current, pageIndex: 0 }
    })
  }, [deferredQuery, setStoredPagination, sorting])

  useEffect(() => {
    if (!showColumns || typeof window === "undefined") {
      return
    }

    const onPointerDown = (event: PointerEvent) => {
      if (!columnsMenuRef.current?.contains(event.target as globalThis.Node)) {
        setShowColumns(false)
      }
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setShowColumns(false)
      }
    }

    window.addEventListener("pointerdown", onPointerDown)
    window.addEventListener("keydown", onKeyDown)
    return () => {
      window.removeEventListener("pointerdown", onPointerDown)
      window.removeEventListener("keydown", onKeyDown)
    }
  }, [showColumns])

  const columns = useMemo(
    () => [
      columnHelper.display({
        id: "select",
        header: ({ table }) => (
          <div className="flex items-center">
            <input
              type="checkbox"
              aria-label={accessCopy.selectedCount(table.getSelectedRowModel().rows.length)}
              checked={table.getIsAllRowsSelected()}
              ref={(element) => {
                if (element) {
                  element.indeterminate =
                    table.getIsSomeRowsSelected() && !table.getIsAllRowsSelected()
                }
              }}
              onChange={table.getToggleAllRowsSelectedHandler()}
              className="size-4 accent-[var(--primary)]"
            />
          </div>
        ),
        cell: ({ row }) => (
          <div className="flex items-center" onClick={(event) => event.stopPropagation()}>
            <input
              type="checkbox"
              aria-label={row.original.description || row.original.id}
              checked={row.getIsSelected()}
              onChange={row.getToggleSelectedHandler()}
              className="size-4 accent-[var(--primary)]"
            />
          </div>
        ),
        enableSorting: false,
      }),
      columnHelper.accessor("description", {
        header: ({ column }) => (
          <Button
            variant="ghost"
            size="sm"
            className="-ml-2 h-8 px-2 text-[11px] font-[510] tracking-[0.18em] text-muted-foreground uppercase"
            onClick={() =>
              column.toggleSorting(column.getIsSorted() === "asc")
            }
          >
            {copy.columns.key}
            <ArrowUpDown className="size-3.5" />
          </Button>
        ),
        cell: ({ row }) => (
          <div className="space-y-1 whitespace-normal">
            <div className="font-medium">
              {row.original.description || copy.descriptionFallback}
            </div>
            <div className="font-mono text-xs text-muted-foreground">
              {truncateMiddle(row.original.id, 10, 8)}
            </div>
          </div>
        ),
      }),
      columnHelper.accessor("state", {
        header: copy.columns.status,
        cell: ({ row }) => <AuthKeyStateBadge state={row.original.state} />,
      }),
      columnHelper.accessor("tags", {
        header: copy.columns.tags,
        cell: ({ row }) => (
          <div className="max-w-48 whitespace-normal text-sm text-muted-foreground">
            {joinTags(row.original.tags, common.notSet)}
          </div>
        ),
      }),
      columnHelper.display({
        id: "shape",
        header: copy.columns.policy,
        cell: ({ row }) => (
          <div className="space-y-1 text-sm text-muted-foreground">
            <div>{row.original.reusable ? copy.reusable : copy.oneTime}</div>
            <div>{row.original.ephemeral ? copy.ephemeral : copy.persistent}</div>
          </div>
        ),
      }),
      columnHelper.accessor("usage_count", {
        header: ({ column }) => (
          <Button
            variant="ghost"
            size="sm"
            className="-ml-2 h-8 px-2 text-[11px] font-[510] tracking-[0.18em] text-muted-foreground uppercase"
            onClick={() =>
              column.toggleSorting(column.getIsSorted() === "asc")
            }
          >
            {copy.columns.usage}
            <ArrowUpDown className="size-3.5" />
          </Button>
        ),
        cell: ({ row }) => (
          <div className="space-y-1 text-sm text-muted-foreground">
            <div>{copy.usageCount(row.original.usage_count)}</div>
            <div>{formatDateTime(row.original.last_used_at_unix_secs, locale, timezone)}</div>
          </div>
        ),
      }),
      columnHelper.accessor("created_at_unix_secs", {
        header: ({ column }) => (
          <Button
            variant="ghost"
            size="sm"
            className="-ml-2 h-8 px-2 text-[11px] font-[510] tracking-[0.18em] text-muted-foreground uppercase"
            onClick={() =>
              column.toggleSorting(column.getIsSorted() === "asc")
            }
          >
            {copy.columns.lifecycle}
            <ArrowUpDown className="size-3.5" />
          </Button>
        ),
        cell: ({ row }) => (
          <div className="space-y-1 text-sm text-muted-foreground">
            <div>
              {copy.createdAt(formatDateTime(row.original.created_at_unix_secs, locale, timezone))}
            </div>
            <div>
              {copy.expiresAt(formatDateTime(row.original.expires_at_unix_secs, locale, timezone))}
            </div>
          </div>
        ),
      }),
      columnHelper.display({
        id: "actions",
        header: "",
        cell: ({ row }) => (
          <div className="flex justify-end">
            <Button
              variant="outline"
              size="sm"
              disabled={
                row.original.state !== "active" ||
                pendingKeyId === row.original.id
              }
              onClick={(event) => {
                event.stopPropagation()
                onRevoke(row.original)
              }}
            >
              <Ban className="size-3.5" />
              {pendingKeyId === row.original.id ? copy.revoking : copy.revoke}
            </Button>
          </div>
        ),
      }),
    ],
    [accessCopy, common.notSet, copy, locale, onRevoke, pendingKeyId, timezone]
  )

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: filteredAuthKeys,
    columns,
    state: {
      sorting,
      rowSelection,
      pagination,
      columnVisibility,
    },
    onSortingChange: setSorting,
    onRowSelectionChange: setRowSelection,
    onPaginationChange: setStoredPagination,
    onColumnVisibilityChange: setStoredColumnVisibility,
    enableRowSelection: true,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  })

  const selectedAuthKeys = table.getSelectedRowModel().rows.map((row) => row.original)
  const pagedRows = table.getRowModel().rows
  const pageCount = table.getPageCount()
  const pageIndex = table.getState().pagination.pageIndex
  const pageSize = table.getState().pagination.pageSize
  const rangeStart = filteredAuthKeys.length === 0 ? 0 : pageIndex * pageSize + 1
  const rangeEnd = filteredAuthKeys.length === 0 ? 0 : rangeStart + pagedRows.length - 1
  const densityCellClass =
    resolvedDensity === "compact"
      ? "align-top whitespace-normal py-2"
      : "align-top whitespace-normal"
  const densityHeadClass = resolvedDensity === "compact" ? "h-9" : ""
  const toggleableColumns = useMemo(
    () =>
      table
        .getAllLeafColumns()
        .filter((column) => !["select", "actions"].includes(column.id)),
    [table]
  )

  return (
    <div className="space-y-4">
      <div className="space-y-3 border-b border-border/70 pb-4">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <SearchField
            value={query}
            onChange={setQuery}
            onClear={clearQuery}
            placeholder={copy.filterPlaceholder}
            clearLabel={common.clearFilters}
            focusLabel={common.focusSearch}
            className="w-full xl:max-w-[420px]"
          />
          <div className="flex flex-wrap items-center gap-2 xl:justify-end">
            {toolbarAction}
            <div className="relative" ref={columnsMenuRef}>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowColumns((current) => !current)}
              >
                <Columns3 className="size-3.5" />
                {common.columns}
              </Button>
              {showColumns ? (
                <div className="console-surface-elevated absolute top-full right-0 z-20 mt-2 min-w-[220px] rounded-[12px] border border-border p-3 shadow-[0_18px_40px_rgba(0,0,0,0.18)]">
                  <div className="mb-2 text-[11px] font-[510] tracking-[0.16em] text-muted-foreground uppercase">
                    {common.columns}
                  </div>
                  <div className="space-y-2">
                    {toggleableColumns.map((column) => (
                      <label
                        key={column.id}
                        className="flex items-center gap-2 text-[13px] text-foreground"
                      >
                        <input
                          type="checkbox"
                          checked={column.getIsVisible()}
                          onChange={column.getToggleVisibilityHandler()}
                          className="size-4 accent-[var(--primary)]"
                        />
                        {column.id === "description"
                          ? copy.columns.key
                          : column.id === "state"
                            ? copy.columns.status
                            : column.id === "tags"
                              ? copy.columns.tags
                              : column.id === "shape"
                                ? copy.columns.policy
                                : column.id === "usage_count"
                                  ? copy.columns.usage
                                  : copy.columns.lifecycle}
                      </label>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
            <div className="inline-flex items-center gap-1 rounded-full border border-border/80 bg-background px-1 py-1">
              <Button
                variant={resolvedDensity === "comfortable" ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setDensity("comfortable")}
              >
                {common.comfortable}
              </Button>
              <Button
                variant={resolvedDensity === "compact" ? "secondary" : "ghost"}
                size="sm"
                onClick={() => setDensity("compact")}
              >
                {common.compact}
              </Button>
            </div>
            {hasActiveFilters ? (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                {common.clearFilters}
              </Button>
            ) : null}
          </div>
        </div>
        <div className="text-[12px] tracking-[-0.12px] text-muted-foreground">
          {copy.count(filteredAuthKeys.length, authKeys.length)}
        </div>
      </div>

      {selectedAuthKeys.length > 0 ? (
        <div className="console-surface-soft sticky top-[78px] z-10 flex flex-col gap-3 rounded-[12px] px-3 py-3 shadow-[0_12px_32px_rgba(0,0,0,0.08)] sm:flex-row sm:items-center sm:justify-between">
          <div className="text-[13px] font-[510] tracking-[-0.13px] text-foreground">
            {accessCopy.selectedCount(selectedAuthKeys.length)}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => setRowSelection({})}>
              {common.clearSelection}
            </Button>
            <Button
              size="sm"
              onClick={() => onBulkRevoke(selectedAuthKeys)}
              disabled={bulkRevoking}
            >
              <Ban className="size-3.5" />
              {bulkRevoking ? copy.revoking : accessCopy.bulkRevoke}
            </Button>
          </div>
        </div>
      ) : null}

      <Table className="console-scrollbar">
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <TableHead key={header.id} className={densityHeadClass}>
                  {header.isPlaceholder
                    ? null
                    : flexRender(
                        header.column.columnDef.header,
                        header.getContext()
                      )}
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {pagedRows.length === 0 ? (
            <TableRow>
              <TableCell
                colSpan={8}
                className="h-28 text-center text-muted-foreground"
              >
                {copy.empty}
              </TableCell>
            </TableRow>
          ) : (
            pagedRows.map((row) => (
              <TableRow
                key={row.id}
                data-console-row="access"
                className={`cursor-pointer transition hover:bg-[var(--surface-soft)] ${
                  activeKeyId === row.original.id ? "bg-[var(--surface-soft)]" : ""
                }`}
                onClick={() => onView(row.original)}
                onKeyDown={(event) => {
                  if (event.key === "ArrowDown") {
                    event.preventDefault()
                    focusCollectionItem(event.currentTarget, '[data-console-row="access"]', "next")
                    return
                  }

                  if (event.key === "ArrowUp") {
                    event.preventDefault()
                    focusCollectionItem(event.currentTarget, '[data-console-row="access"]', "previous")
                    return
                  }

                  if (event.key === "Home") {
                    event.preventDefault()
                    focusCollectionItem(event.currentTarget, '[data-console-row="access"]', "first")
                    return
                  }

                  if (event.key === "End") {
                    event.preventDefault()
                    focusCollectionItem(event.currentTarget, '[data-console-row="access"]', "last")
                    return
                  }

                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault()
                    onView(row.original)
                  }
                }}
                tabIndex={0}
                aria-label={`${common.viewDetails}: ${row.original.description || row.original.id}`}
                aria-selected={activeKeyId === row.original.id}
              >
                {row.getVisibleCells().map((cell) => (
                  <TableCell
                    key={cell.id}
                    className={densityCellClass}
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>

      <div className="flex flex-col gap-3 pt-1 sm:flex-row sm:items-center sm:justify-between">
        <div className="text-[13px] text-muted-foreground">
          {common.range(rangeStart, rangeEnd, filteredAuthKeys.length)}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="console-surface-soft flex items-center gap-2 rounded-[10px] px-3 py-2 text-[12px] text-secondary-foreground">
            <span>{common.rowsPerPage}</span>
            <select
              value={pageSize}
              onChange={(event) =>
                setStoredPagination({
                  pageIndex: 0,
                  pageSize: Number(event.target.value),
                })
              }
              className="bg-transparent text-foreground outline-none"
            >
              {PAGE_SIZE_OPTIONS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
          <div className="text-[12px] text-muted-foreground">
            {common.page(pageCount === 0 ? 0 : pageIndex + 1, Math.max(pageCount, 1))}
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            {common.previous}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            {common.next}
          </Button>
        </div>
      </div>
    </div>
  )
}
