#1) Task1:
ip addr show
sudo apt install snort
snort --version
sudo snort -v -i wlo1
sudo nano /etc/snort/snort.conf
sudo nano /etc/snort/rules/local.rules
sudo snort -T -c /etc/snort/snort.conf -i wlo1

#From your another terminal try ping google.com according to the rules set in your
#local.rules file 
sudo nano /etc/snort/rules/local.rules
#1# alert icmp any any -> any any (msg:"ICMP Echo Request detected"; itype:8; sid:1000001; rev:1;)
#2# alert tcp any any -> any 80 (msg:"ICMP HTTP traffic detected"; sid:1000002; rev:1;)
#3# alert tcp any any -> any 22 (msg:"SSH traffic detected"; sid:1000003; rev:1;)
#From your another terminal try ping google.com according to the rules set in your
sudo snort -A console -q -c /etc/snort/snort.conf -i wlo1

#2) Task2:
#if everthing works fine, that means the snort is working as expected.Now we can train the model
#We will be using a historical dataset. Dataset is attached and publicly available.
# I used model_training.ipynb file to pre-process the dataset & train the model and
#to save the model as well. 

#3) Task3: 
#Integrating snort with the model, we will be reading the snort log alerts from snort
#and we have 2 options from there, we can run the model in our local terminal
#or in kaggle notebook, I used kaggle notebook for this.
#but  in anyway you have to run the snort_parser.py file in local terminal to get the
#input features to test. 
#for that you need to create a virtual environment
pip3 install virtualenv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements2.txt
#once everything is set you can good to go with snort_parser.py
python3 snort_parser.py
#this will give you the output for the snort_parser.py
#i then took these inputs and used them in kaggle notebook as specified in 
#model_testing.ipynb 
#as the model didnot resulted in intrusion,  i din not moved further, if the model 
#detected intrusion, we would have added the rule and take further actions.
