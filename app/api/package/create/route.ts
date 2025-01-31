import { applyRateLimit } from "@/utils/function";
import prisma from "@/utils/prisma";
import { protectionAdminUser } from "@/utils/serversideProtection";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const ip =
      request.headers.get("x-forwarded-for") ||
      request.headers.get("cf-connecting-ip") ||
      "unknown";

    const body = await request.json();

    if (!body) {
      return NextResponse.json(
        { error: "Request body is empty or invalid" },
        { status: 400 }
      );
    }

    const { packageName, packageDescription, packagePercentage, packageDays } =
      body;

    if (
      !packageName ||
      !packageDescription ||
      !packagePercentage ||
      !packageDays
    ) {
      return NextResponse.json({ error: "Invalid input" }, { status: 400 });
    }

    const { teamMemberProfile } = await protectionAdminUser(ip);

    if (!teamMemberProfile) {
      return NextResponse.json(
        { error: "Team member not found." },
        { status: 404 }
      );
    }

    await applyRateLimit(teamMemberProfile.alliance_member_id, ip);

    const checkIfPackageExists = await prisma.package_table.findFirst({
      where: { package_name: packageName },
    });

    if (checkIfPackageExists) {
      return NextResponse.json(
        { error: "Package already exists." },
        { status: 400 }
      );
    }

    const parsedPackagePercentage = parseFloat(packagePercentage);
    const parsedPackageDays = parseInt(packageDays, 10);

    if (isNaN(parsedPackagePercentage) || isNaN(parsedPackageDays)) {
      throw new Error(
        "Invalid number format for packagePercentage or packageDays."
      );
    }

    await prisma.$transaction([
      prisma.package_table.create({
        data: {
          package_name: packageName,
          package_description: packageDescription,
          package_percentage: parsedPackagePercentage,
          packages_days: parsedPackageDays,
        },
      }),
    ]);

    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Unknown error." },
      { status: 500 }
    );
  }
}
