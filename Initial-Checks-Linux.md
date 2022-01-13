# Initial Checks 


# Resources
https://www.cyberciti.biz/tips/linux-security.html



## General
1.  Check Bash history for ALL users.
    a. Find the spicy stuff.

2. Ensuring FTP isn't installed
3. Ensure Telnet is disabled

4. Check sudo group
5. Check sudoers file
6. Check SSH config files
    a. Disable Root Login
    b. Disable password-authentication if keys are in place.
7. Ensure that SELinux is enabled (if applicable) 
8. Lock empty password accounts
9. Make sure no non-root accounts have UID Set to 0
10. Ensure UFW has a deny all incoming (Add the SSH rule first!)
11. Ensure audit.d is up and running. 
12. Disable services that aren't needed
13. Change the default passwords (especially weak ones)

