import LayoutButton from "@/components/ui/LayoutButton";
import AppSidebar from "@/components/ui/side-bar";
import { SidebarProvider } from "@/components/ui/sidebar";
import { protectionMemberUser } from "@/utils/serversideProtection";
import type { Metadata } from "next";
import { redirect } from "next/navigation";
import "../globals.css";

export const metadata: Metadata = {
  title: "Create Next App",
  description: "Generated by create next app",
};

export default async function AppLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const {
    profile,
    redirect: redirectTo,
    teamMemberProfile,
  } = await protectionMemberUser();

  if (redirectTo) {
    redirect(redirectTo);
  }
  if (!profile) redirect("/500");

  return (
    <SidebarProvider>
      <AppSidebar userData={profile} teamMemberProfile={teamMemberProfile} />
      <main className="min-h-screen w-full bg-gray-100 flex flex-col">
        {teamMemberProfile.alliance_member_role === "MEMBER" && (
          <LayoutButton />
        )}

        {/* Children Content */}
        <div className="flex-grow">{children}</div>
      </main>
    </SidebarProvider>
  );
}