import { applyRateLimit } from "@/utils/function";
import prisma from "@/utils/prisma";
import { protectionAdminUser } from "@/utils/serversideProtection";
import { NextRequest, NextResponse } from "next/server";

const errorResponse = (message: string, status: number) =>
  NextResponse.json({ error: message }, { status });

const successResponse = (data: object = {}) =>
  NextResponse.json({ success: true, ...data });

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ packageId: string }> }
) {
  try {
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("cf-connecting-ip") ||
      "unknown";

    const { packageId } = await context.params;
    if (!packageId) return errorResponse("Package ID is required.", 400);

    const { packageData, teamMemberId } = await request.json();
    const { packageName, packageDescription, packagePercentage, packageDays } =
      packageData;

    if (
      !packageName ||
      !packageDescription ||
      !packagePercentage ||
      !packageDays
    ) {
      return errorResponse("All package fields are required.", 400);
    }

    const { teamMemberProfile } = await protectionAdminUser();
    if (!teamMemberProfile)
      return errorResponse("User authentication failed.", 401);

    if (
      teamMemberProfile.alliance_member_id !== teamMemberId &&
      teamMemberProfile.alliance_member_role !== "ADMIN"
    ) {
      return errorResponse(
        "You are not authorized to update this package.",
        403
      );
    }

    await applyRateLimit(teamMemberProfile.alliance_member_id, ip);

    const updatedPackage = await prisma.package_table.update({
      where: { package_id: packageId },
      data: {
        package_name: packageName,
        package_description: packageDescription,
        package_percentage: parseFloat(packagePercentage),
        packages_days: parseInt(packageDays),
      },
    });

    return successResponse({ data: updatedPackage });
  } catch (error) {
    return errorResponse(
      error instanceof Error ? error.message : "Unexpected error occurred.",
      500
    );
  }
}
