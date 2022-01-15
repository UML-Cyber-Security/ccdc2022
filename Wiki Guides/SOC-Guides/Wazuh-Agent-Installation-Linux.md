# Wazuh Agent Installation Guide - LINUX (Debian/Ubuntu)

Installing a Wazuh Agent on an Ubuntu machine is pretty simple.


## ELK Stack Side (SOC)
 
You can find the correctly formatted command from the UI of the ELK stack Wazuh-Plugin

1. Choose "Debian/Ubuntu" as the OS (Or appropriate linux flavor)

2. Choose "x86_64" as the architecture (Find which is the applicable OS with the command ```uname -m```)

3. Type in the Wazuh server address replacing <IP Address>

4. Assign the agent to a predefined group in the dropdown menu

5. Now, the command to install and enroll the agent will pop up with the specified information. 
   All the user has to do is input this command and the installation will be complete.


   _Note: Make sure to give a name to your agent to make it easier to see who we're monitoring :)_
   
   _You can do this by adding this before the -i flag, after the various WAZUH specifications. "      WAZUH_AGENT_NAME='INSERT_NAME_HERE'    " (Include the single quotes, not double)_

6. Finally, the agent must be started on the machine. 

```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```
