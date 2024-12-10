"use client";
import { alliance_member_table } from "@prisma/client";
import AdminTopUpApprovalTable from "./AdminTopUpApprovalTable";

type Props = {
  teamMemberProfile: alliance_member_table;
};

const AdminTopUpApprovalPage = ({ teamMemberProfile }: Props) => {
  return (
    <div className="mx-auto p-10">
      <div>
        <header className="mb-4">
          <h1 className="Title">Top Up History List Page</h1>
          <p className="text-gray-600">
            View all your transactions that are currently in the system.
          </p>
        </header>

        {/* Table Section */}
        <section className=" rounded-lg p-6">
          <AdminTopUpApprovalTable teamMemberProfile={teamMemberProfile} />
        </section>
      </div>
    </div>
  );
};

export default AdminTopUpApprovalPage;
