--[[

Author: Pentester Academy
Website: www.pentesteracademy.com
Version: 1.0

--]]

do
  -- If GUI is not enabled exit. Keeps plugin from running for tshark
  if not gui_enabled() then return end

  local util=require('util')

  -- Object to get source IP Address
  local ip_src=Field.new("ip.src")

  -- Object to get Destination IP Address
  local ip_dst=Field.new("ip.dst")

  -- Object to get status code
  local status_code=Field.new("sip.Status-Code")

  -- Object to get method
  local method=Field.new("sip.Method")

  -- Object to get to_user
  local to_user=Field.new("sip.to.user")

  -- Object to get from_user
  local from_user=Field.new("sip.from.user")

  local data_text_line=Field.new("data-text-lines")

  -- Object to get call-ID
  local call_id=Field.new("sip.Call-ID")

  -- Table to store previous invites
  local message_store={}

  -- Table to store messages
  local messages={}
  local messages_store={}

  -- Tap to listen on frames with filter sip.Request-Line
  local tap = Listener.new("frame", "sip")

  -- function to convert userdata to string
  local function getString(str)
    if(str()~=nil) then return tostring(str()) else return "NA" end
  end

  -- Function to reset users table when new pcap is opened
  function tap.reset()
    message_store={}
    messages_store={}
    messages={}
  end

  -- This function will be called for every packet
  function tap.packet(pinfo,tvb)


     -- Variables to store the source, destination ip, from user, to user and call ID
     local src=getString(ip_src)
     local dst=getString(ip_dst)
     local from_user=getString(from_user)
     local to_user=getString(to_user)
     local callId=getString(call_id)
     
     
    if(getString(method)=="MESSAGE" and data_text_line()~=nil)
    then
        local message=data_text_line().offset

        -- create an entry in message table
        if(message_store[callId]==nil)
          then


            -- store the message and other details in message_store
            message_store[callId]={}
            message_store[callId]["from_user"]=from_user
            message_store[callId]["source"]=src
            message_store[callId]["destination"]=dst
            message_store[callId]["to_user"]=to_user

            -- data line is in hex seperated by ":", replace that colon with "" and convert to string
            message_store[callId]["message"]=tostring(data_text_line()):gsub(":",""):fromhex()
        end

    -- if the status code is 200 OK, that means the message was delivered properly
    elseif((getString(status_code)=="200" or getString(status_code)=="202") and message_store[callId]~=nil)
      then

          -- key used to store unique messages, the key is of format sender@sender_ip-reciever@reciver_ip-Message
          local key=message_store[callId]["from_user"].."@"..message_store[callId]["source"].."-"..message_store[callId]["to_user"].."@"..message_store[callId]["destination"].."-"..message_store[callId]["message"]


          if(messages[key]==nil)
            then
            
            -- map the unique messages in messages table
            messages[key]=callId
            table.insert(messages_store,key)
          end

    end

  end

  -- Function to be called on selecting the option from Tools menu  
  local function unique_messages(win,stringToFind)

      local header=  " __________________________________________________________________________________________________________________________________\n"
                   .."|   S.no   | Sender Username | Message Sender IP |Reciever Username| Message Reciever IP |              Message                    |\n"

      win:set(header)
      local count=0
      for k,v in ipairs(messages_store)do          
        
        local value=messages[v]
        local data=message_store[value]
        if(util.searchTable(data,stringToFind))
          then

            count=count+1


            local acf_settings={
              { 
                ["value"]=count,           
                ["length"]=10,  
                ["delimiter"]="",                 
                ["next"]=true,
                ["branch"]=false                     
              },
              { 
                ["value"]=data["from_user"],
                ["length"]=17,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["source"],
                ["length"]=19,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["to_user"],
                ["length"]=17,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["destination"],
                ["length"]=21,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              },
              { 
                ["value"]=data["message"],
                ["length"]=41,
                ["delimiter"]="",
                ["next"]=true,
                ["branch"]=false
              }                          
            }
            win:append("|----------------------------------------------------------------------------------------------------------------------------------|\n")        
            win:append(acf(acf_settings,"|"))  
          end

      end
      win:append("|__________________________________________________________________________________________________________________________________|\n")     
  end

 
 function menu1()
  util.dialog_menu(unique_messages,"Unique Messages")
 end

  -- Register the function to Tools menu
  register_menu("VOIP/SIP Information Gathering/Unique Messages",menu1, MENU_TOOLS_UNSORTED)
end


-- Function to convert hex to string

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end


-- Functions to prettify output.

function acf(settings,column_seperator)
  local final=""
  while(isNext(settings))do
      for k,v in ipairs(settings)do
          if(v["next"]==false) then v["value"]="" else v["next"]=false end
          final=final..column_seperator..format_str(v)
          if(k==#settings) then final=final..column_seperator.."\n" end
      end
   end
  return final
end

function isNext(settings)
  for k,v in ipairs(settings)do 
    if(v["next"]) then return true end
  end
  return false
end

function format_str(global,substr)
    local m=0
    local n=0
    local str=""
    local len=global["length"]
    local delimiter=global["delimiter"]
    if(substr==nil) then str=global["value"] else str=substr end
    if(str==nil) then str="" else str=tostring(str) end
    if (len==nil) then len=0 end
    if(delimiter==nil) then delimiter="" end
    local s=str
    if(str:len()<len)
        then
        if((len-str:len())%2==0)
            then 
                m=(len-str:len())/2
                n=m
        else
                m=math.floor(((len-str:len()) /2))+1
                n=m-1
        end     
        for i=1, m
            do
            s=" "..s
        end
        for i=1, n
            do
            s=s.." "
        end
    elseif(str:len()>len)
        then
        local str2=""
        local a=len
        if(global["branch"]) then str2=""..delimiter.."[^"..delimiter.."]" else str2=""..delimiter.."[^"..delimiter.."]*$" end
        if(delimiter~="")
            then
             a=string.find(str:sub(0,len), str2)
         end
        local c=0
        if( a==nil or a>len) then a=len end
        if(delimiter~="" and global["branch"] ) then c=1 end
        global["value"]=str:sub(a+c)
        global["next"]=true
        return format_str(global,str:sub(1,a-1))
    end
    return s
end
