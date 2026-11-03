# Installer acceptance checklist

Run this checklist on a clean Windows 10/11 x64 machine before publishing:

1. Install the setup executable as a standard user account (installer elevation
   is expected for the Program Files destination).
2. Launch Watchful Eye from the Start Menu shortcut.
3. Confirm the inventory and log directories are created under
   `%LOCALAPPDATA%\WatchfulEye`, not under Program Files.
4. Confirm the bundled OUI database loads and manufacturer observations work.
5. Without Npcap, confirm the UI opens and gracefully reports unavailable packet
   operations rather than crashing.
6. Install Npcap separately, restart the application, and verify ARP discovery,
   then verify TTL fingerprinting where permitted.
7. Run two scans and verify the same UUID inventory and observation history are
   retained.
8. Open a device's details and verify its classification rationale and
   historical evidence are shown in local time.
9. Uninstall Watchful Eye and confirm `%LOCALAPPDATA%\WatchfulEye` remains.
10. Reinstall and confirm the existing inventory is still available.
