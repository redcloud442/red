import { Button } from "@/components/ui/button";
import { LegionRequestData } from "@/utils/types";
import { Prisma } from "@prisma/client";
import { ColumnDef } from "@tanstack/react-table";
import { ArrowUpDown } from "lucide-react";

export const LegionBountyColumn = (): ColumnDef<LegionRequestData>[] => {
  return [
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
      cell: ({ row }) => {
        return <div>{row.getValue("user_username")}</div>;
      },
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
      cell: ({ row }) => <div>{row.getValue("user_first_name")}</div>,
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
      cell: ({ row }) => <div>{row.getValue("user_last_name")}</div>,
    },
    {
      accessorKey: "total_bounty_earnings",

      header: ({ column }) => (
        <Button
          variant="ghost"
          onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
        >
          Total Referral Earnings <ArrowUpDown />
        </Button>
      ),
      cell: ({ row }) => (
        <div>
          ₱{" "}
          {new Prisma.Decimal(
            row.getValue("total_bounty_earnings")
          ).toLocaleString()}
        </div>
      ),
    },
  ];
};
