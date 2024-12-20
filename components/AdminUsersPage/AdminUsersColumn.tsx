import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { logError } from "@/services/Error/ErrorLogs";
import {
  handleUpdateRole,
  handleUpdateUserRestriction,
} from "@/services/User/Admin";
import { formatDateToYYYYMMDD } from "@/utils/function";
import { createClientSide } from "@/utils/supabase/client";
import { UserRequestdata } from "@/utils/types";
import { ColumnDef } from "@tanstack/react-table";
import { ArrowUpDown, Copy, MoreHorizontal } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import TableLoading from "../ui/tableLoading";

export const AdminUsersColumn = (
  handleFetch: () => void
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): ColumnDef<UserRequestdata, any>[] => {
  const supabaseClient = createClientSide();
  const router = useRouter();
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);

  const handlePromoteToMerchant = async (
    alliance_member_alliance_id: string,
    role: string
  ) => {
    try {
      setIsLoading(true);

      await handleUpdateRole({ userId: alliance_member_alliance_id, role });

      // if (role === "ADMIN") {
      //   const supabase = createServiceRoleClient();
      //   const { data, error } = await supabase.auth.admin.updateUserById(
      //     userId,
      //     {
      //       password: newPassword,
      //     }
      //   );
      // }
      handleFetch();
      toast({
        title: `Role Updated`,
        description: `Role Updated Sucessfully`,
        variant: "success",
      });
    } catch (e) {
      if (e instanceof Error) {
        await logError(supabaseClient, {
          errorMessage: e.message,
          stackTrace: e.stack,
          stackPath: "components/AdminUsersPage/AdminUsersColumn.tsx",
        });
      }
      toast({
        title: `Role Update Failed`,
        description: `Something went wrong`,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleBanUser = async (alliance_member_alliance_id: string) => {
    try {
      setIsLoading(true);
      await handleUpdateUserRestriction({
        userId: alliance_member_alliance_id,
      });
      handleFetch();
      toast({
        title: `User Banned`,
        description: `User Banned Sucessfully`,
        variant: "success",
      });
    } catch (e) {
      if (e instanceof Error) {
        await logError(supabaseClient, {
          errorMessage: e.message,
          stackTrace: e.stack,
          stackPath: "components/AdminUsersPage/AdminUsersColumn.tsx",
        });
      }
      toast({
        title: `User Ban Failed`,
        description: `Something went wrong`,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    <TableLoading />;
  }

  return [
    {
      accessorKey: "user_id",

      header: ({ column }) => (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          User ID <ArrowUpDown />
        </Button>
      ),
      cell: ({ row }) => {
        const id = row.getValue("user_id") as string;
        const maxLength = 15;

        const handleCopy = async () => {
          if (id) {
            await navigator.clipboard.writeText(id);
            toast({
              title: "Copied",
              description: "User ID copied to clipboard",
              variant: "success",
            });
          }
        };

        return (
          <div className="flex items-center space-x-2">
            <div
              className="truncate"
              title={id.length > maxLength ? id : undefined}
            >
              {id.length > maxLength ? `${id.slice(0, maxLength)}...` : id}
            </div>
            {id && (
              <Button variant="ghost" size="sm" onClick={handleCopy}>
                <Copy className="w-4 h-4" />
              </Button>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: "user_username",

      header: ({ column }) => (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Username <ArrowUpDown />
        </Button>
      ),
      cell: ({ row }) => (
        <div className="text-wrap">{row.getValue("user_username")}</div>
      ),
    },
    {
      accessorKey: "user_first_name",

      header: ({ column }) => (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          First Name <ArrowUpDown />
        </Button>
      ),
      cell: ({ row }) => (
        <div className="text-wrap">{row.getValue("user_first_name")}</div>
      ),
    },
    {
      accessorKey: "user_last_name",

      header: ({ column }) => (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Last Name <ArrowUpDown />
        </Button>
      ),
      cell: ({ row }) => (
        <div className="text-wrap">{row.getValue("user_last_name")}</div>
      ),
    },
    {
      accessorKey: "user_date_created",
      header: ({ column }) => (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Date Created <ArrowUpDown />
        </Button>
      ),
      cell: ({ row }) => (
        <div className="text-wrap">
          {formatDateToYYYYMMDD(row.getValue("user_date_created"))}
        </div>
      ),
    },
    {
      accessorKey: "alliance_member_restricted",

      header: ({ column }) => (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Restricted <ArrowUpDown />
        </Button>
      ),
      cell: ({ row }) => (
        <div className="text-wrap">
          {row.getValue("alliance_member_restricted") ? "YES" : "NO"}
        </div>
      ),
    },

    {
      accessorKey: "alliance_member_is_active",

      header: ({ column }) => (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Active <ArrowUpDown />
        </Button>
      ),
      cell: ({ row }) => {
        const isActive = row.getValue("alliance_member_is_active");
        return (
          <div
            className={`${isActive ? "text-green-500" : "text-red-500"} text-wrap`}
          >
            {isActive ? "YES" : "NO"}
          </div>
        );
      },
    },
    {
      header: "Actions",
      cell: ({ row }) => {
        const data = row.original;

        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="h-8 w-8 p-0">
                <MoreHorizontal />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Actions</DropdownMenuLabel>
              <DropdownMenuItem
                onClick={() =>
                  router.push(`/admin/users/${data.alliance_member_user_id}`)
                }
              >
                View Profile
              </DropdownMenuItem>
              {data.alliance_member_role !== "MERCHANT" && (
                <DropdownMenuItem
                  onClick={() =>
                    handlePromoteToMerchant(data.alliance_member_id, "MERCHANT")
                  }
                >
                  Promote as Merchant
                </DropdownMenuItem>
              )}
              {data.alliance_member_role !== "ADMIN" && (
                <DropdownMenuItem
                  onClick={() =>
                    handlePromoteToMerchant(data.alliance_member_id, "ADMIN")
                  }
                >
                  Promote as Admin
                </DropdownMenuItem>
              )}
              {data.alliance_member_role !== "ACCOUNTING" && (
                <DropdownMenuItem
                  onClick={() =>
                    handlePromoteToMerchant(
                      data.alliance_member_id,
                      "ACCOUNTING"
                    )
                  }
                >
                  Promote as Accountant
                </DropdownMenuItem>
              )}
              <DropdownMenuItem
                onClick={() => handleBanUser(data.alliance_member_id)}
              >
                Ban User
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        );
      },
    },
  ];
};
