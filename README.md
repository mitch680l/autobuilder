```
*Requirements  
-Nordic SDK (incuding nrfutil)  
-Git Bash or Linux  
-Python  

*Config file  
-Line 1: Customer  
-Line 2: filename for security tags(aws) located in /server_auth   
-Line 3: mqtt host config  
-Line 4: http host config  
-Line 5: user  
-Line 6: pass  
-Line 7+: will get added to file but unused by app  

*Usage 
python combined.py (device number)       -- Generates device firmware and files will be located in autobuilder/(customer)/nrid(device_number)  
launch_env.sh                          --Launches git bash w/ necessary python enviroment (may require attunment if installed git bash in non default directory)  
update.sh                              --Will clean and recursivly update the submodules that this project depends on.  
verify (blob path) (aes key path)      --Will check encrypted blob with parser & aes key

*Workflow  
Use combined.py to generate merged.hex (partition application)
Automatic kestrel application isn't supported currently
```
