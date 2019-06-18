<img src="https://user-images.githubusercontent.com/25884689/58698021-04963d00-83cd-11e9-8962-54a3b36a12b2.png" width="50%" >

## VoIPShark: Open Source VoIP Analysis Platform

VoIPshark is an open source platform for VoIP analysis. It is created as a collection of Wireshark plugins. After installation, it will be available within Wireshark. This platform was created while working on "VoIP Traffic Analysis" course. Those interested can check the course here: https://www.pentesteracademy.com/course?id=43

VoIPShark will enable the user to do the following:

1. Perform macro analysis on VoIP traffic
2. Decrypt live or stored VoIP traffic while preserving packet structure and time information
3. Export VoIP audio streams to popular media formats
4. Detect the following threats/attacks

   * Message flood
   * Invite flood
   * SIP MiTM attack
   * Teardown
   * Enumeration
   * Attack tool detection


## Installation

### Step 1: Install library

#### For Linux and MacOS:

1. Create directory "/usr/local/lib/lua/5.2/" if it does not exist

       mkdir -p /usr/local/lib/lua/5.2/

2. Download VoIPShark and copy lockbox folder to "/usr/local/lib/lua/5.2/" directory

       git clone https://github.com/pentesteracademy/voipshark.git
       mv voipshark/lockbox /usr/local/lib/lua/5.2/
   
#### For Windows:

Download VoIPShark and copy lockbox folder to wireshark program directory.

To find out the location of wireshark program directory, check `Help > About Wireshark > Folders` (highlighted in green)
<p align="center">
<img src="https://user-images.githubusercontent.com/25884689/58771844-ee64c880-85e8-11e9-95be-2af3e7d60504.png" width="60%" >
</p>



### Step 2: Installing VoIPShark

1. Copy the "plugins" directory to Wireshark personal plugins directory.
2. Start wireshark. :)

One can get the location of wireshark plugins directory by checking `Help > About Wireshark > Folders` (highlighted in yellow)

![](https://user-images.githubusercontent.com/743886/43845711-72426d36-9ae1-11e8-9945-0bbe8e078e2a.png)


## Tool featured at

- DEF CON China 1.0 Main stage <https://www.defcon.org/html/dc-china-1/dc-cn-1-speakers.html>
- Blackhat Asia 2019 Arsenal <https://www.blackhat.com/asia-19/arsenal/schedule/index.html#voip-wireshark-attack-defense-toolkit-14349>


## Sister Project

PA-Toolkit (https://github.com/pentesteracademy/patoolkit)


## Author

- Nishant Sharma, R & D Manager, Pentester Academy <nishant@binarysecuritysolutions.com>
- Ashish Bhangale, Sr. Security Researcher, Pentester Academy <ashish@binarysecuritysolutions.com> 
- Jeswin Mathai, Security Researcher, Pentester Academy <jeswin@binarysecuritysolutions.com> 

Under the guidance of Mr. Vivek Ramachandran, CEO, Pentester Academy


## Screenshots

Decrypting SRTP: SRTP Packets

![Wireshark_2019-04-30_13-19-16](https://user-images.githubusercontent.com/25884689/58720935-1b0cba80-8406-11e9-9473-2142f93377de.png)
Decrypting SRTP: Enabling Auto Decryption


<img width="400" alt="Wireshark_2019-04-30_13-19-55" src="https://user-images.githubusercontent.com/25884689/58720923-15af7000-8406-11e9-9af5-835e1a52303e.png">


Decrypting SRTP: Decrypted SRTP (RTP)

![Wireshark_2019-04-30_13-20-14](https://user-images.githubusercontent.com/25884689/58721022-5b6c3880-8406-11e9-94fa-7a03d6558f0f.png)



Exporting Call Audio: Exported Streams 

<img width="621" alt="2019-04-30_12-59-42" src="https://user-images.githubusercontent.com/25884689/58720944-252eb900-8406-11e9-80df-1e19fd1ebdd0.png">




SIP Information Gathering : SIP Auth Export

<img width="621" alt="Wireshark_2019-04-30_13-09-11" src="https://user-images.githubusercontent.com/25884689/58720623-4e027e80-8405-11e9-85a7-6a39c030af4e.png">

SIP Information Gathering : DTMF

<img width="634" alt="Wireshark_2019-04-30_13-13-18" src="https://user-images.githubusercontent.com/25884689/58720647-55c22300-8405-11e9-9f6f-95ca7c206440.png">


 VoIP Attack Detection: Bruteforce

<img width="766" alt="Wireshark_2019-04-30_13-08-07" src="https://user-images.githubusercontent.com/25884689/58720310-63c37400-8404-11e9-8418-509f7eb0ff84.png">


 VoIP Attack Detection: Unauthenticated Users

<img width="381" alt="Wireshark_2019-04-30_13-17-16" src="https://user-images.githubusercontent.com/25884689/58720237-34ad0280-8404-11e9-8605-1b1bf41fa58d.png">


## License


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License v2 as published by
the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
