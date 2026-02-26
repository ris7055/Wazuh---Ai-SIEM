# Getting Started with Wazuh using Microsoft Azure
## Step 1:

Create a VM in Microsoft Azure Platform: <br>
`
Azure services → Create a Resource → Create → Virtual Machine
`
</br> <br>
Fill up with necessary details as example given below:
<img width="765" height="537" alt="image" src="https://github.com/user-attachments/assets/9c541f59-4c84-4491-aedf-c0a665d15723" />
<img width="529" height="570" alt="image" src="https://github.com/user-attachments/assets/af4b58ba-1c82-4513-82a8-b5f34060ce2a" />\
Finally select all the SSH ports and click Review + Create:
<img width="761" height="322" alt="image" src="https://github.com/user-attachments/assets/dac06d6a-6dd9-43c5-8398-6eec5af45a55" />
</br> 

## Step 2:

a) SSH into your Azure VM from your PC terminal: 

`ssh <your-username>@<your-vm-public-ip>`

b) Update the VM & install prerequisites 

`
sudo apt update && sudo apt -y upgrade
sudo apt -y install curl tar
`
(Optional but good)

`sudo hostnamectl set-hostname wazuh-server`

c) Run the official Wazuh all-in-one installer
This installs Wazuh Server + Indexer + Dashboard on the same host using the assistant:

`
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
`

## Step 3:
Open the dashboard in your browser
In the browser, go to:
`
https://<your-vm-public-ip>
`

Log in with:\
Username: admin\
Password: the one printed after the Wazuh got installed in Azure terminal

Note: Must be using Admin PC only

<img width="774" height="515" alt="image" src="https://github.com/user-attachments/assets/b0d7236e-ae87-41b5-9e18-878a119cb2aa" />

So, the dashboard for Wazuh will be displayed:
<img width="1917" height="858" alt="image" src="https://github.com/user-attachments/assets/22a9dd3b-8f01-473d-a899-40767772ff55" />

