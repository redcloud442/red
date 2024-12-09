import { applyRateLimit } from "@/utils/function";
import prisma from "@/utils/prisma";
import { protectionAccountingUser } from "@/utils/serversideProtection";
import { NextRequest, NextResponse } from "next/server";

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ requestId: string }> }
) {
  try {
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("cf-connecting-ip") ||
      "unknown";

    const { requestId } = await context.params;

    if (!requestId) {
      return NextResponse.json(
        { error: "Request ID is required." },
        { status: 400 }
      );
    }

    const body = await request.json();
    const { status, note }: { status: string; note?: string | null } = body;

    if (!status || !["APPROVED", "PENDING", "REJECTED"].includes(status)) {
      return NextResponse.json(
        { error: "Invalid or missing status." },
        { status: 400 }
      );
    }

    const { teamMemberProfile } = await protectionAccountingUser();
    if (!teamMemberProfile) {
      return NextResponse.json(
        { error: "User authentication failed." },
        { status: 401 }
      );
    }

    await applyRateLimit(teamMemberProfile?.alliance_member_id, ip);

    const existingRequest =
      await prisma.alliance_withdrawal_request_table.findUnique({
        where: { alliance_withdrawal_request_id: requestId },
      });

    if (
      existingRequest &&
      existingRequest.alliance_withdrawal_request_status !== "PENDING"
    ) {
      return NextResponse.json(
        { error: "Request has already been processed." },
        { status: 400 }
      );
    }

    const allianceData = await prisma.alliance_withdrawal_request_table.update({
      where: { alliance_withdrawal_request_id: requestId },
      data: {
        alliance_withdrawal_request_status: status,
        alliance_withdrawal_request_approved_by:
          teamMemberProfile.alliance_member_id,
        alliance_withdrawal_request_reject_note: note ?? null,
      },
    });

    if (status === "REJECTED") {
      const earningsType =
        allianceData.alliance_withdrawal_request_withdraw_type;

      await prisma.alliance_earnings_table.update({
        where: {
          alliance_earnings_member_id: teamMemberProfile.alliance_member_id,
        },
        data: {
          [earningsType === "TOTAL"
            ? "alliance_olympus_earnings"
            : earningsType === "DIRECT REFERRAL"
              ? "alliance_ally_bounty"
              : "alliance_legion_bounty"]: {
            increment: allianceData.alliance_withdrawal_request_amount,
          },
        },
      });
    }

    if (!allianceData) {
      return NextResponse.json(
        { error: "Failed to update top-up request." },
        { status: 500 }
      );
    }

    // Return success response
    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json(
      {
        error:
          error instanceof Error ? error.message : "Unexpected error occurred.",
        stack: error instanceof Error ? error.stack : undefined,
      },
      { status: 500 }
    );
  }
}
