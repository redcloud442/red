"use client";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { logError } from "@/services/Error/ErrorLogs";
import {
  getUserOptions,
  getUserOptionsMerchant,
} from "@/services/Options/Options";
import { getAdminTopUpRequest } from "@/services/TopUp/Admin";
import { escapeFormData } from "@/utils/function";
import { createClientSide } from "@/utils/supabase/client";
import { TopUpRequestData } from "@/utils/types";
import { alliance_member_table, user_table } from "@prisma/client";
import {
  ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  SortingState,
  useReactTable,
  VisibilityState,
} from "@tanstack/react-table";
import { format } from "date-fns";
import {
  CalendarIcon,
  ChevronLeft,
  ChevronRight,
  Loader2,
  RefreshCw,
  Search,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { Button } from "../ui/button";
import { Calendar } from "../ui/calendar";
import { Card } from "../ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";
import { ScrollArea, ScrollBar } from "../ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select";
import { Separator } from "../ui/separator";
import { Switch } from "../ui/switch";
import TableLoading from "../ui/tableLoading";
import { Textarea } from "../ui/textarea";
import { useAdminTopUpApprovalColumns } from "./AdminTopUpApprovalColumn";

type DataTableProps = {
  teamMemberProfile: alliance_member_table;
};

type FilterFormValues = {
  emailFilter: string;
  merchantFilter: string;
  userFilter: string;
  statusFilter: string;
  rejectNote: string;
  dateFilter: { start: string; end: string };
};

const AdminTopUpApprovalTable = ({ teamMemberProfile }: DataTableProps) => {
  const supabaseClient = createClientSide();
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});
  const [rowSelection, setRowSelection] = useState({});
  const [requestData, setRequestData] = useState<TopUpRequestData[]>([]);
  const [requestCount, setRequestCount] = useState(0);
  const [activePage, setActivePage] = useState(1);
  const [isFetchingList, setIsFetchingList] = useState(false);
  const [merchantOptions, setMerchantOptions] = useState<user_table[]>([]);
  const [userOptions, setUserOptions] = useState<user_table[]>([]);
  const [showFilters, setShowFilters] = useState(false);

  const columnAccessor = sorting?.[0]?.id || "alliance_top_up_request_date";
  const isAscendingSort =
    sorting?.[0]?.desc === undefined ? true : !sorting[0].desc;

  const fetchAdminRequest = async () => {
    try {
      if (!teamMemberProfile) return;
      setIsFetchingList(true);

      const sanitizedData = escapeFormData(getValues());

      const {
        emailFilter,
        merchantFilter,
        userFilter,
        statusFilter,
        dateFilter,
      } = sanitizedData;

      const startDate = dateFilter.start
        ? new Date(dateFilter.start)
        : undefined;
      const endDate = startDate ? new Date(startDate) : undefined;

      const { data, totalCount } = await getAdminTopUpRequest(supabaseClient, {
        teamId: teamMemberProfile.alliance_member_alliance_id,
        teamMemberId: teamMemberProfile.alliance_member_id,
        page: activePage,
        limit: 10,
        columnAccessor: columnAccessor,
        isAscendingSort: isAscendingSort,
        search: emailFilter,
        merchantFilter,
        userFilter,
        statusFilter,
        dateFilter: {
          start:
            startDate && !isNaN(startDate.getTime())
              ? startDate.toISOString()
              : undefined,
          end:
            endDate && !isNaN(endDate.getTime())
              ? new Date(endDate.setHours(23, 59, 59, 999)).toISOString()
              : undefined,
        },
      });

      setRequestData(data || []);
      setRequestCount(totalCount || 0);
    } catch (e) {
      if (e instanceof Error) {
        await logError(supabaseClient, {
          errorMessage: e.message,
          stackTrace: e.stack,
          stackPath:
            "components/AdminTopUpApprovalPage/AdminTopUpApprovalTable.tsx",
        });
      }
    } finally {
      setIsFetchingList(false);
    }
  };

  const {
    columns,
    isOpenModal,
    setIsOpenModal,
    handleUpdateStatus,
    isLoading,
  } = useAdminTopUpApprovalColumns(fetchAdminRequest);

  const table = useReactTable({
    data: requestData,
    columns,
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      rowSelection,
    },
  });
  const pageCount = Math.ceil(requestCount / 10);

  const { register, handleSubmit, getValues, control, reset, watch } =
    useForm<FilterFormValues>({
      defaultValues: {
        emailFilter: "",
        merchantFilter: "",
        userFilter: "",
        statusFilter: "",
        dateFilter: {
          start: undefined,
          end: undefined,
        },
        rejectNote: "",
      },
    });

  useEffect(() => {
    fetchAdminRequest();
  }, [supabaseClient, teamMemberProfile, activePage, sorting]);

  useEffect(() => {
    const fetchOptions = async () => {
      try {
        const pageLimit = 500;

        // Fetch Merchant Options
        let currentMerchantPage = 1;
        let allMerchantOptions: user_table[] = [];

        while (true) {
          const merchantData = await getUserOptionsMerchant(supabaseClient, {
            page: currentMerchantPage,
            limit: pageLimit,
            teamMemberId: teamMemberProfile.alliance_member_id,
          });

          if (!merchantData?.length) {
            break;
          }

          allMerchantOptions = [...allMerchantOptions, ...merchantData];

          if (merchantData.length < pageLimit) {
            break;
          }

          currentMerchantPage += 1;
        }

        setMerchantOptions(allMerchantOptions);

        // Fetch User Options
        let currentUserPage = 1;
        let allUserOptions: user_table[] = [];

        while (true) {
          const userData = await getUserOptions(supabaseClient, {
            page: currentUserPage,
            limit: pageLimit,
            teamMemberId: teamMemberProfile.alliance_member_id,
          });

          if (!userData?.length) {
            break;
          }

          allUserOptions = [...allUserOptions, ...userData];

          if (userData.length < pageLimit) {
            break;
          }

          currentUserPage += 1;
        }

        setUserOptions(allUserOptions);
      } catch (e) {}
    };

    fetchOptions();
  }, [supabaseClient, teamMemberProfile.alliance_member_id]);

  const handleSwitchChange = (checked: boolean) => {
    setShowFilters(checked);
    if (!checked) {
      reset();
      handleSubmit(handleFilter)();
    }
  };

  const handleFilter = async () => {
    await fetchAdminRequest();
  };

  const rejectNote = watch("rejectNote");

  return (
    <Card className="w-full rounded-sm p-4">
      <div className="flex flex-wrap gap-4 items-start py-4">
        <form
          className="flex flex-col gap-6 w-full max-w-4xl rounded-md"
          onSubmit={handleSubmit(handleFilter)}
        >
          {" "}
          {isOpenModal && (
            <Dialog
              open={isOpenModal.open}
              onOpenChange={(open) => setIsOpenModal({ ...isOpenModal, open })}
            >
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>{isOpenModal.status} Request</DialogTitle>
                </DialogHeader>
                {isOpenModal.status === "REJECTED" && (
                  <Controller
                    name="rejectNote"
                    control={control}
                    rules={{ required: "Rejection note is required" }}
                    render={({ field, fieldState }) => (
                      <div className="flex flex-col gap-2">
                        <Textarea
                          placeholder="Enter the reason for rejection..."
                          {...field}
                        />
                        {fieldState.error && (
                          <span className="text-red-500 text-sm">
                            {fieldState.error.message}
                          </span>
                        )}
                      </div>
                    )}
                  />
                )}
                <div className="flex justify-end gap-2 mt-4">
                  <DialogClose asChild>
                    <Button variant="secondary">Cancel</Button>
                  </DialogClose>
                  <Button
                    disabled={isLoading}
                    onClick={() =>
                      handleUpdateStatus(
                        isOpenModal.status,
                        isOpenModal.requestId,
                        rejectNote
                      )
                    }
                  >
                    {isLoading ? (
                      <Loader2 className="animate-spin" />
                    ) : isOpenModal.status === "REJECTED" ? (
                      "Confirm Rejection"
                    ) : (
                      "Confirm Approval"
                    )}
                  </Button>
                </div>
              </DialogContent>
            </Dialog>
          )}
          <div className="flex flex-wrap gap-2 items-center w-full">
            <Input
              {...register("emailFilter")}
              placeholder="Filter username..."
              className="w-full sm:max-w-sm p-2 border rounded"
            />
            <Button
              type="submit"
              disabled={isFetchingList}
              size="sm"
              variant="outline"
              className="w-full sm:w-auto"
            >
              <Search />
            </Button>
            <Button
              onClick={fetchAdminRequest}
              disabled={isFetchingList}
              size="sm"
              className="w-full sm:w-auto"
            >
              <RefreshCw className="mr-2" />
              Refresh
            </Button>
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Switch
                id="filter-switch"
                checked={showFilters}
                onCheckedChange={handleSwitchChange}
              />
              <Label htmlFor="filter-switch">Filter</Label>
            </div>
          </div>
          {showFilters && (
            <div className="flex flex-wrap gap-2 items-center rounded-md">
              <Controller
                name="merchantFilter"
                control={control}
                render={({ field }) => (
                  <Select
                    onValueChange={(value) =>
                      field.onChange(value === field.value ? "" : value)
                    }
                    value={field.value || ""}
                  >
                    <SelectTrigger className="w-full sm:w-auto">
                      <SelectValue placeholder="Merchant" />
                    </SelectTrigger>
                    <SelectContent>
                      {merchantOptions.map((opt) => (
                        <SelectItem key={opt.user_id} value={opt.user_id}>
                          {opt.user_username}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />

              <Controller
                name="userFilter"
                control={control}
                render={({ field }) => (
                  <Select
                    onValueChange={(value) =>
                      field.onChange(value === field.value ? "" : value)
                    }
                    value={field.value || ""}
                  >
                    <SelectTrigger className="w-full sm:w-auto">
                      <SelectValue placeholder="Requestor" />
                    </SelectTrigger>
                    <SelectContent>
                      {userOptions.map((opt) => (
                        <SelectItem key={opt.user_id} value={opt.user_id}>
                          {opt.user_username}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />

              <Controller
                name="statusFilter"
                control={control}
                render={({ field }) => (
                  <Select
                    onValueChange={(value) =>
                      field.onChange(value === field.value ? "" : value)
                    }
                    value={field.value || ""}
                  >
                    <SelectTrigger className="w-full sm:w-auto">
                      <SelectValue placeholder="Status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="PENDING">Pending</SelectItem>
                      <SelectItem value="APPROVED">Approved</SelectItem>
                      <SelectItem value="REJECTED">Rejected</SelectItem>
                    </SelectContent>
                  </Select>
                )}
              />

              <Controller
                name="dateFilter.start"
                control={control}
                render={({ field }) => (
                  <Popover>
                    <PopoverTrigger asChild>
                      <Button
                        variant="outline"
                        className="w-full sm:w-auto font-normal justify-start"
                      >
                        <CalendarIcon className="mr-2 h-4 w-4" />
                        {field.value
                          ? format(new Date(field.value), "PPP")
                          : "Select Start Date"}
                      </Button>
                    </PopoverTrigger>
                    <PopoverContent className="w-auto p-0">
                      <Calendar
                        mode="single"
                        selected={
                          field.value ? new Date(field.value) : undefined
                        }
                        onSelect={(date: Date | undefined) =>
                          field.onChange(date?.toISOString() || "")
                        }
                        initialFocus
                      />
                    </PopoverContent>
                  </Popover>
                )}
              />

              <Button onClick={fetchAdminRequest} className="w-full sm:w-auto">
                Submit
              </Button>
            </div>
          )}
        </form>
      </div>

      <ScrollArea className="w-full overflow-x-auto ">
        {isFetchingList && <TableLoading />}
        <Separator />
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
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
            {table.getRowModel().rows.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={row.getIsSelected() && "selected"}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center"
                >
                  No results.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
          <tfoot>
            <TableRow>
              <TableCell className="px-0" colSpan={columns.length}>
                <div className="flex justify-between items-center border-t px-2 pt-2">
                  <span className="text-sm text-gray-600 dark:text-white">
                    Showing {Math.min(activePage * 10, requestCount)} out of{" "}
                    {requestCount} entries
                  </span>
                </div>
              </TableCell>
            </TableRow>
          </tfoot>
        </Table>
        <ScrollBar orientation="horizontal" />
      </ScrollArea>

      <div className="flex items-center justify-end gap-x-4 py-4">
        {activePage > 1 && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setActivePage((prev) => Math.max(prev - 1, 1))}
            disabled={activePage <= 1}
          >
            <ChevronLeft />
          </Button>
        )}

        <div className="flex space-x-2">
          {(() => {
            const maxVisiblePages = 3;
            const pages = Array.from({ length: pageCount }, (_, i) => i + 1);
            let displayedPages = [];

            if (pageCount <= maxVisiblePages) {
              // Show all pages if there are 3 or fewer
              displayedPages = pages;
            } else {
              if (activePage <= 2) {
                // Show the first 3 pages and the last page
                displayedPages = [1, 2, 3, "...", pageCount];
              } else if (activePage >= pageCount - 1) {
                // Show the first page and the last 3 pages
                displayedPages = [
                  1,
                  "...",
                  pageCount - 2,
                  pageCount - 1,
                  pageCount,
                ];
              } else {
                displayedPages = [
                  activePage - 1,
                  activePage,
                  activePage + 1,
                  "...",
                  pageCount,
                ];
              }
            }

            return displayedPages.map((page, index) =>
              typeof page === "number" ? (
                <Button
                  key={page}
                  variant={activePage === page ? "default" : "outline"}
                  size="sm"
                  onClick={() => setActivePage(page)}
                >
                  {page}
                </Button>
              ) : (
                <span key={`ellipsis-${index}`} className="px-2 py-1">
                  {page}
                </span>
              )
            );
          })()}
        </div>
        {activePage < pageCount && (
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              setActivePage((prev) => Math.min(prev + 1, pageCount))
            }
            disabled={activePage >= pageCount}
          >
            <ChevronRight />
          </Button>
        )}
      </div>
    </Card>
  );
};

export default AdminTopUpApprovalTable;
