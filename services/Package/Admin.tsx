import { PackagesFormValues } from "@/components/AdminPackagesPage/EditPackagesModal";
import { package_table } from "@prisma/client";
import { SupabaseClient } from "@supabase/supabase-js";

export const getAdminPackages = async (
  supabaseClient: SupabaseClient,
  params: {
    teamMemberId: string;
  }
) => {
  const { data, error } = await supabaseClient.rpc("get_packages_admin", {
    input_data: params,
  });

  if (error) throw error;

  return data as package_table[];
};

export const updatePackagesData = async (params: {
  packageData: PackagesFormValues;
  packageId: string;
  teamMemberId: string;
}) => {
  const { packageId } = params;

  const response = await fetch(
    `${process.env.NEXT_PUBLIC_BASE_URL}/api/package/` + packageId,
    {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(params),
    }
  );

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      result.error || "An error occurred while creating the top-up request."
    );
  }

  return response;
};

export const createPackage = async (params: {
  packageName: string;
  packageDescription: string;
  packagePercentage: string;
  packageDays: string;
}) => {
  const response = await fetch(
    `${process.env.NEXT_PUBLIC_BASE_URL}/api/package/create`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(params),
    }
  );

  const result = await response.json();

  if (!response.ok) {
    throw new Error(
      result.error || "An error occurred while creating the top-up request."
    );
  }

  return response;
};
