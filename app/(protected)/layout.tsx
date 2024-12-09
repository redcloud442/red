import MobileNavBar from "@/components/ui/MobileNavBar";
import NavBar from "@/components/ui/navBar";
import AppSidebar from "@/components/ui/side-bar";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { ModeToggle } from "@/components/ui/toggleDarkmode";
import { protectionMemberUser } from "@/utils/serversideProtection";

import { ThemeProvider } from "@/components/theme-provider/theme-provider";
import { redirect } from "next/navigation";
import "../globals.css";

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
    <ThemeProvider
      attribute="class"
      defaultTheme="light"
      enableSystem
      disableTransitionOnChange
    >
      <SidebarProvider>
        <div className="flex min-h-screen h-full w-full overflow-auto">
          {["ADMIN"].includes(teamMemberProfile.alliance_member_role) && (
            <div>
              <AppSidebar
                userData={profile}
                teamMemberProfile={teamMemberProfile}
              />
            </div>
          )}

          <div className="flex-1 flex flex-col overflow-x-auto">
            {["ADMIN"].includes(teamMemberProfile.alliance_member_role) && (
              <div className="p-4 md:hidden">
                <SidebarTrigger />
              </div>
            )}
            {!["ADMIN"].includes(teamMemberProfile.alliance_member_role) && (
              <div className=" hidden md:block">
                <NavBar
                  teamMemberProfile={teamMemberProfile}
                  userData={profile}
                />
              </div>
            )}

            <div className="p-4 pb-10 md:pb-0">{children}</div>
            <ModeToggle />
            {!["ADMIN"].includes(teamMemberProfile.alliance_member_role) && (
              <MobileNavBar teamMemberProfile={teamMemberProfile} />
            )}
          </div>
        </div>
      </SidebarProvider>
    </ThemeProvider>
  );
}
