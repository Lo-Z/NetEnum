----------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ ---------------------------

------------------------- VERSION 2.0 FOR LINUX----------------------------

If you are installing NetEnum Via GIT, use the following instructions.
Note: chmod may not be needed as git preserves the executable bits, but is added just inscase its needed.

1. git clone https://github.com/Lo-Z/NetEnum.git
2. sudo ./NetEnum_Installer.sh
(if step 2 fails run - chmod +x NetEnum_Installer.sh - then try step 2 again.

----------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ ---------------------------

If you are downloaling the zip:

1. unzip NetEnum_2.0_Linux.zip
2. cd NetEnum_2.0_Linux
3. chmod +x NetEnum_Installer.sh
4. sudo ./NetEnum_Installer.sh

----------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ ---------------------------

If you need to uninstall NetEnum, remove the installed files:

sudo rm -r /usr/local/bin/NetEnum_2.0
sudo rm /usr/share/applications/NetEnum_2.0_CLI.desktop
sudo rm /usr/share/icons/hicolor/256x256/apps/NetEnum_Logo.png

----------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ ---------------------------

Icon Trouble shooting: if the Desktop icon doesnt show, reboot the system.
If it still doesnt show apply the following commands

#Allow file permisions
sudo chmod 644 /usr/share/icons/hicolor/256x256/apps/NetEnum_Logo.png
sudo chmod 644 /usr/share/applications/NetEnum_2.0_CLI.desktop

#Update the icon cache
sudo gtk-update-icon-cache /usr/share/icons/hicolor

Reboot the system 


----------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ ---------------------------
