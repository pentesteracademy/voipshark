--[[
Plugin: SRTP Decrypt
Author: Pentester Academy
Date: 01/04/2018
Version: 1.0
--]]


------------- SRTP Decrypt C code converted to lua -- START------------

-- Note: I've  converted C code logic into lua, so few of the things that were done to mitigate drawbacks of C, have also been implemented as it is was given in the C code. 
-- Extensive use of string is done which required implementation of few more functions

-- necessary libraries for encryption/decryption function
local String = require("string");
local Array = require("lockbox.util.array");
local Stream = require("lockbox.util.stream");
local CTRMode = require("lockbox.cipher.mode.ctr");
local PKCS7Padding = require("lockbox.padding.pkcs7");
local ZeroPadding = require("lockbox.padding.zero");
local AES128Cipher = require("lockbox.cipher.aes128");


-- And or XOR substitution
local AND=bit32.band
local OR=bit32.bor
local XOR=bit32.bxor
local LSHIFT=bit32.lshift
local RSHIFT=bit32.rshift

-- global variable to maintain roll over counter
local rtp_sequence=0
local rtp_window=0
local rtp_rollcounter=0


-- function to perform AES CM encryption decryption, input: key, IV and data to encrypt or decrypt, output: plain/cipher text
function getCrypt(key,iv,data)
	local decipher = CTRMode.Decipher()
			.setKey(Array.fromHex(key))
			.setBlockCipher(AES128Cipher)
			.setPadding(ZeroPadding);

	local plainOutput = decipher
						.init()
						.update(Stream.fromArray(Array.fromHex(iv)))
						.update(Stream.fromArray(Array.fromHex(data)))
						.finish()
						.asHex();
	return plainOutput
end


-- string to obtain  position of character
local base64char="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

-- (My Code) function to adjust length of variable, for example, after conversion a 4 byte string might result in 0, which will be represented as a single byte, "0" are appended for further processing 
function maintainLen(str,len)
	for i=str:len(),len-1,1
		do
		str="0"..str
	end
	return str;
end

-- (My Code) function to convert in little endian form of the passed string, if the number is negative then the string will have ffffffff in the first 8 bytes.
function conv(str)
	i=0
	if(str:len()==4)
		then
		return str:sub(3,4)..str:sub(1,2)
	end
	if(str:sub(1,8)=="ffffffff")then i=8 end
	return str:sub(i+7,i+8)..str:sub(i+5,i+6)..str:sub(i+3,i+4)..str:sub(i+1,i+2)
end

-- (My Code) function for conversion to 8 bytes and then conversion to little endian and vice versa
function htonl(strr)
	str=string.format("%x",strr)
	for i= str:len(), 7,1 do
		str="0"..str
	end
	return tonumber(str:sub(7,8)..str:sub(5,6)..str:sub(3,4)..str:sub(1,2),16)
end

-- (My Code) function to increment The initalization vector by one for every block.
function inc_iv(str,i)
	local a=str:sub(29,32)
	a=string.format("%x",tonumber(a,16)+i)
	for i=a:len(),3,1
		do
		a="0"..a
	end
	return str:sub(1,28)..a
end



-- decode block called by decode_sdes (called 10 times, and at a time 4 bytes are processed)
function decode_block(input,output)
  local shifts={}
  for i = 1,4,1
  	do
  	local pos=base64char:find(input:sub(i,i))

    shifts[i] =pos-1
  end

  output= output  
  ..maintainLen(string.format("%x",(OR(LSHIFT(shifts[1],2),RSHIFT(shifts[2],4)))%256),2)
  ..maintainLen( string.format("%x",(OR(LSHIFT(shifts[2],4),RSHIFT(shifts[3],2)))%256),2)
  ..maintainLen(string.format("%x",(OR(LSHIFT(shifts[3],6),shifts[4]))%256),2)
  return output
end

-- Function to decode the encoding, the 40 byte encoded text is broken down to master key and master salt
function decode_sdes(input)
	local output="";
	for i =0,9,1
		do
		output=decode_block(input:sub(4*i+1,4*i+4),output);
	end
	return output:sub(1,32), output:sub(33)
end

-- Function to obtain the rtp sequence number from the buffer, utlizes first 5th to 8th bytes of the buffer 
function rtp_seq(buf)
	return OR(LSHIFT(tonumber(buf:sub(5,6),16), 8 ),tonumber(buf:sub(7,8),16))
end

-- Do derive function called to derive the session key and session salt and for decoding the entire packet as well. This function is called directly.
function do_derive(key,salt,label,len)
	local str=salt.."0000";
	local iv={}
	for i =0,15,1
		do
		iv[i+1]=tonumber(str:sub(2*i+1,2*i+2),16);
	end
	iv[8]=XOR(iv[8],label)
	for i=1,6,1
		do
		iv[10+i]=XOR(iv[10+i],0)
	end
	str=""
	for i=1,16,1
		do
		str=str..maintainLen(string.format("%x",iv[i]),2)
		end
	
	return do_ctr_crypt(key,str,"00000000000000000000000000000000",len,"key")
end

-- function called to obtain the counter for every packet, this function called rtp_crypt, input is the salt and the buffer, buffer is used to obtain ssrc, roc and sequence number
function srtp_crypt(salt,buf,len)


	local seq=rtp_seq(buf)
	local roc=0
    local diff = seq - rtp_sequence;
    if (diff > 0)
    then
        rtp_window = LSHIFT(rtp_window, diff);
        rtp_window = OR(rtp_window ,1);
        rtp_sequence = seq;
        rtp_rollcounter= roc;
    
    else
        diff = -diff;
  	     rtp_window = OR(rtp_window,LSHIFT(1, diff));
    end
    -- get ssrc from the buffer, its the first 16-24 bytes 
	local ssrc=tonumber(buf:sub(23,24)..buf:sub(21,22)..buf:sub(19,20)..buf:sub(17,18),16);
	-- adjusted the max 32 bit integer range crossing () 
	if(ssrc / 2147483647 >1) then  if ((ssrc / 2147483647)%2==0)then ssrc=ssrc%2147483647; else ssrc=(ssrc%4294967295)-4294967296; end end -- ERRoneous, need to modify <--------------------- ATTENTION

	return rtp_crypt(ssrc, roc, seq, salt)
end

-- function to compute roc
function srtp_compute_roc(rtp_roc,seq)
	
	local roc =rtp_roc;
    if ((AND((seq -rtp_sequence), 0xffff)) < 0x8000)
    then
     if (seq < rtp_sequence)
            then
            roc=roc+1
        end
    else
        if (seq > rtp_sequence)
        	then
            roc=roc-1
        end
   end
    return roc;
end

-- function to compute the counter, this function is called by srtp_crypt
function rtp_crypt(ssrc, roc, seq, salt)
	local counter=""
	counter=salt:sub(1,8)
			..conv(maintainLen(string.format("%x",XOR(tonumber(conv(salt:sub(9,16)),16),ssrc)),8))
			..conv(maintainLen(string.format("%x",XOR(tonumber(conv(salt:sub(17,24)),16),roc)),8))
			..conv(maintainLen(string.format("%x",XOR(tonumber(conv(salt:sub(25,28)),16),htonl(LSHIFT(seq,16)))),4))


	return counter:sub(1,28).."0000"

end

-- function to perform encryption/ decryption, the entire buffer is broken down, and encrypted/decrypted block by block by getcrypt function
function do_ctr_crypt(key,iv,data,len,type)
	local ctrlen=16

	local enc=""
	quot=math.floor(len/ctrlen)
	rem=len%ctrlen

	-- for full length blocks
	for i=0,quot-1,1
		do
		enc=enc..getCrypt(key,inc_iv(iv,i),data:sub(32*i+1,32*i+32))
	end

	-- if the block is not complete append with zero and compure again
	if(rem~=0)
		then

			local dataProc=data:sub(quot*ctrlen*2+1)
			for i=1,2*(ctrlen-rem),1 do dataProc=dataProc.."0" end
			
			if(type=="rtp")
				then
				enc=enc..getCrypt(key,inc_iv(iv,quot),dataProc):sub(1,2*(ctrlen-rem))
			else
				enc=enc..getCrypt(key,inc_iv(iv,quot),dataProc)
			end
	end
	return enc

end


--------------------------- SRTP Decryption C Code Converted to lua--End---------------------- 

---------------------------------------- Plguin Part------------------------------------------

-- NOTE: There are two dissectors one for sdp and another for rtp, upon encountering a sdp packet
-- the sdp dissector registers the media port for rtp dissector
-- TODO: sdp is only binded on port 5060
-- TODO: ROC set to 0 


-- Function that Decodes the buffer
function decode_buf(s_key,s_salt,buf,len)
	-- calling srtp_crypt to obtain the counter for every packet
	local counter=srtp_crypt(s_salt,buf,len)

	-- decrypting the packet, the session key, counter and buffer is passed,
	-- the first 12 bytes are header and the payload starts from 25th character
	-- to 160 bytes (320th character), the remaining 10 bytes are authentication tag
	-- TODO: Values hard coded
	return do_ctr_crypt(s_key,counter,buf:sub(25):sub(1,2*len),len,"rtp")										-- Erroneous, value hard coded 	<---------------------------------- ATTENTION
end

-- this function is used for conversion of userdata to string
local function getString(str)
	if str()~=nil then return tostring(str()) else return "" end
end

-- defining proto object
local myrtp = Proto("artp","MyRTP Protocol")

-- Defining object to get source, destination, port and ip
frame_number=Field.new("frame.number")
local ip_src=Field.new("ip.src")
local ip_dst=Field.new("ip.dst")
local src_port=Field.new("udp.srcport")
local dst_port=Field.new("udp.dstport")

-- table to hold invite_updates
local invite_update={}


-- table to hold encoded_pairs from which master key and master salt are derived
local encoded_pair={}




-- variable to store payloads
local payload={}


--function to be called whenever a new file is opened
function myrtp.init()

payload={}

end


function myrtp.dissector(tvbuf,pktinfo,root)
if(not pktinfo.visited )
	then

	local key=""

	-- The key of the table is in the format of source_ip:port-destination_ip:port

	key=getString(ip_src)..":"..getString(src_port).."-"..getString(ip_dst)..":"..getString(dst_port) 


	-- checking if the key exists for the given ip,port pair, this will prevent the dissector being called for unassociated ip and ports
	if(encoded_pair[key]~=nil)
		then

		-- fetching the session key and session salt
		local session_key=encoded_pair[key]["session_key"]
		local session_salt=encoded_pair[key]["session_salt"]


		 -- Converting data to string
		 -- converting tvbuf to string, I've broken this down because tvbuf:range supports maximum of 48 byte character, if more data is asked for, then "..." will be appened after 48 bytes and the rest of data wont show.
		 -- maybe some other mothod exists for what I've done.  
		 -- TODO: Assuming all RTP packets of same size
		local buffer=tostring(tvbuf:bytes())

		-- total length including ssrc and authentication tag
		local len=buffer:len()	

		-- total length of tvbuf in bytes = total length - 12 byte header - 10 byte auth tag
		local buffLen=math.floor((len-44)/2)


	    -- The Header remains the same after encryption/decryption, so the header is appended to the decrypted payload, to genrate the final rtp packet
	    decrypt=tvbuf:range(0,12)..decode_buf(session_key,session_salt,buffer,buffLen)

	    -- converting the string to byte array for later conversion
		b=ByteArray.new(decrypt)

		-- Storing the byte array in payload table
		payload[tostring(frame_number())]=b

		-- Genrating the TV Buffer from the byte array
		-- no nned for conversion since its not required anymore
		tvbuf=ByteArray.tvb(b, "Decrypted SRTP")		

		--Replaces the data of real packet
		-- calling the RTP dissector so that the we can use the RTP stream functionality.
		-- Disable this beacuse it was not required, when running on tshark
		Dissector.get("rtp"):call(tvbuf, pktinfo, root)
		
	end
else
	-- converting the stored payload into tvbuff
	tvbuf=ByteArray.tvb(payload[tostring(frame_number())], "Decrypted SRTP")

	-- calling the dissector with the 
	Dissector.get("rtp"):call(tvbuf, pktinfo, root)

end
   
end

-- defining sdp protocol
local mysdp=Proto("VoIPShark","VoIPShark")

-- init function to flush tables when new file is opened
function mysdp.init()
	invite_update={}
	encoded_pair={}
	enable_srtp_decrypt=false
end

-- creating preferences that can be set from Edit-> preferences-> protocol
local prefs = mysdp.prefs  
prefs.srtp = Pref.bool("Decrypt SRTP Automatically", false, "Check the box to automatically decrypt SRTP traffic when key is available in SDP packets") 


function mysdp.dissector(tvb,pktinfo,root)
	-- run only if the plugin is enabled
	if(prefs.srtp)
		then

		-- Find a=crypto field starting index
		local a_crypto_start=tvb:range(0):string():find("\na=crypto")

		-- Proceed only if it exists
		if(a_crypto_start~=nil)
		then

			-- runs only once, to set the encoded pair table
			if(not pktinfo.visited)
				then


				-- TODO: change String match to proper offset calculation
				-- Find the location where call-Id is
				local call_id_pos_start=tvb:range(0):string():find("Call[-]ID: ")

				-- once we have location of call-Id look for line termination 
				local call_id_pos_end=tvb:range(call_id_pos_start):string():find("\n")
				
				-- positioning to obtain only the call-ID value, "Call-ID: " has 8 characters thats why offset is 8
				local call_id=tvb:range(call_id_pos_start+8,call_id_pos_end-8):string()


				-- find media field
				local media_start=tvb:range(0):string():find("\nm=")

				--find media field line termination
				local media_end=tvb:range(media_start):string():find("\n")

				-- to fetching media field
				local media=tvb:range(media_start,media_end):string()

				-- finding starting of media port, which is after the first space
				local media_port_start=media:find(" ")

				-- finding the terminating space to know that the value has ended
				local media_port_end=media:sub(media_port_start+1):find(" ")

				-- fetching the media_port value as a substring
				local media_port=media:sub(media_port_start+1,media_port_end+media_port_start-1)

				-- Check where crypto line terminats, its also the terminating point for the encoded value
				local a_crypto_end=tvb:range(a_crypto_start):string():find("\n")

				-- get the a=crypto string
				local a_crypto=tvb:range(a_crypto_start,a_crypto_end):string()

				-- extract the index from where the encoded values starts
				local a_crypto_value_start=a_crypto:find("inline:")

				-- get the encoded value, 7 is because "inline:" has 7 characters, we don't want inline appended in the value
				local a_crypto_value=a_crypto:sub(a_crypto_value_start+7)


				-- Type here refers to UPDATE, INVITE or STATUS, fetch the first 11 character then perform string match
				local type=tvb:range(0,11):string()

				if(type:sub(1,6)=="UPDATE" or type:sub(1,6)=="INVITE")
					then

						-- upon recieving a invite request append it to invite update table.
						invite_update[call_id]={}
						
						-- store who sent the request
						invite_update[call_id]["sender"]=getString(ip_src)

						-- storing the media port of the sender
						invite_update[call_id]["media_port"]=media_port		

						-- storing the encoded pair of the sneder
						invite_update[call_id]["encoded_pair"]=	a_crypto_value


				-- check STATUS is 200 OK
				elseif(type:sub(9,11)=="200")
					then

					-- TODO: will only work when invite is present otherwise this won't work
					-- Check if a invite or update has been recieved 
					if(invite_update[call_id]~=nil)
						then

						--check which one is the server
						local reciver=getString(ip_dst)
						local sender=getString(ip_src)
						
						-- Encoded pair is the table that holds the master key and master salt for all client, server based on ip as well as on port
						-- The key in the table will be of the format: SenderIP:PORT-recieverIP:port, e.g: 192.168.20.130:17786-192.168.20.132:4000
						-- The value in the table will be master key and master salt, 2 key will exist for a single client and server

						-- sender-reciever key
						local key=sender..":"..media_port.."-"..reciver..":"..invite_update[call_id]["media_port"]

				
						-- derive the master key and master salt from the encoded pair for sender reciever
						local master_key,master_salt=decode_sdes(a_crypto_value)

						-- Create key value pair in encoded pair table
						encoded_pair[key]={}

						-- setting the master key for the sender 
						encoded_pair[key]["session_key"]=do_derive(master_key,master_salt,0,16)

						-- setting the master salt
						encoded_pair[key]["session_salt"]=do_derive(master_key,master_salt,2,14)

						-- creating the key for reciever-sender
						key=reciver..":"..invite_update[call_id]["media_port"].."-"..sender..":"..media_port

						-- derive the master key and master salt from the encoded pair
						local master_key,master_salt=decode_sdes(invite_update[call_id]["encoded_pair"])

						-- Create key value pair in encoded pair table
						encoded_pair[key]={}

						-- setting the master key
						encoded_pair[key]["session_key"]=do_derive(master_key,master_salt,0,16)

						-- setting the master salt
						encoded_pair[key]["session_salt"]=do_derive(master_key,master_salt,2,14)


						--TODO check if a port is already associated in the dissector table before adding
						-- adding ports of both server and client to dissectortable
						DissectorTable.get("udp.port"):add(media_port, myrtp)
						DissectorTable.get("udp.port"):add(invite_update[call_id]["media_port"], myrtp)
					end
				end
			else
				new_tvb=tvb:range(0,a_crypto_start-1):string()

					    -- converting the string to byte array for later conversion
						b=ByteArray.new(new_tvb)

						-- Genrating the TV Buffer from the byte array
						-- no nned for conversion since its not required anymore
						tvb=ByteArray.tvb(b, "Decrypted SDP")
						print(new_tvb)
						Dissector.get("sip"):call(tvb,pktinfo,root)	
				--Dissector.get("sip"):call(tvb,pktinfo,root)
			end
		else
			Dissector.get("sip"):call(tvb,pktinfo,root)
		end

	else
		Dissector.get("sip"):call(tvb,pktinfo,root)
	end
end

-- TODO: only 5060 is added
DissectorTable.get("udp.port"):add("5060",mysdp)

-- Registering for SIP over TLS 
DissectorTable.get("ssl.port"):add("5061",mysdp)



